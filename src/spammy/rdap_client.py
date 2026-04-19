from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence

import requests

from .models import AbuseContact, DomainRecord, NetworkOwner, RDAPRecord

try:
    from ipwhois import IPWhois
    from ipwhois.exceptions import HTTPLookupError, IPDefinedError
except ImportError:  # pragma: no cover - optional dependency
    IPWhois = None  # type: ignore
    IPDefinedError = Exception  # type: ignore
    HTTPLookupError = Exception  # type: ignore


EMAIL_RE = re.compile(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", re.IGNORECASE)


def _normalize_email(value: str) -> Optional[str]:
    value = value.strip()
    if "<" in value and ">" in value:
        value = value.split("<", 1)[-1].split(">", 1)[0]
    if EMAIL_RE.fullmatch(value):
        return value.lower()
    return None


def _confidence_for_email(address: str) -> float:
    lowered = address.lower()
    if "abuse" in lowered:
        return 0.95
    if "cert" in lowered or "security" in lowered:
        return 0.8
    if "postmaster" in lowered:
        return 0.7
    return 0.5


def _dedupe_contacts(contacts: Sequence[AbuseContact]) -> List[AbuseContact]:
    seen = {}
    for contact in contacts:
        key = contact.address.lower()
        if key not in seen or contact.confidence > seen[key].confidence:
            seen[key] = contact
    return list(seen.values())


def _emails_from_vcard(vcard_array: Any) -> List[str]:
    emails: List[str] = []
    if not isinstance(vcard_array, list) or len(vcard_array) < 2:
        return emails
    entries = vcard_array[1]
    for entry in entries:
        if not isinstance(entry, list) or len(entry) < 4:
            continue
        field, _, _, value = entry
        if field.lower() == "email" and isinstance(value, str):
            normalized = _normalize_email(value)
            if normalized:
                emails.append(normalized)
    return emails


def _match_emails(payload: Any) -> List[str]:
    try:
        blob = json.dumps(payload, default=str)
    except TypeError:
        blob = str(payload)
    matches = EMAIL_RE.findall(blob)
    # Normalize
    normalized = []
    for entry in matches:
        mail = _normalize_email(entry)
        if mail:
            normalized.append(mail)
    return normalized


def _split_emails(raw: str) -> List[str]:
    """Split a comma- or newline-separated email string into individual addresses."""
    if not raw:
        return []
    return [part.strip() for part in re.split(r"[,\n\r]+", raw) if part.strip()]


def rfc2142_contacts(hostname: str) -> List[AbuseContact]:
    """Return RFC 2142 best-effort abuse/postmaster contacts for *hostname*.

    These are guesses based on convention, not looked up, so confidence is low.
    Only used as a last-resort fallback when all structured lookups fail.
    """
    if not hostname:
        return []
    domain = hostname.lstrip("*").lstrip(".").lower()
    return [
        AbuseContact(address=f"abuse@{domain}", source="rfc2142:guess", confidence=0.30),
        AbuseContact(address=f"postmaster@{domain}", source="rfc2142:guess", confidence=0.20),
    ]


@dataclass
class RDAPClient:
    timeout: int = 8
    user_agent: str = "SpamReporter/0.1 (+https://example.local)"
    rdap_base: str = "https://rdap.org"

    def __post_init__(self) -> None:
        from urllib.parse import urlparse
        parsed = urlparse(self.rdap_base)
        if parsed.scheme not in ("https", "http"):
            raise ValueError(f"Invalid RDAP base URL scheme: {parsed.scheme!r}. Only http/https are allowed.")
        if not parsed.netloc:
            raise ValueError("RDAP base URL must include a hostname.")

    def _http_get(self, path: str) -> Optional[Dict[str, Any]]:
        url = f"{self.rdap_base.rstrip('/')}/{path.lstrip('/')}"
        try:
            response = requests.get(
                url,
                headers={"User-Agent": self.user_agent},
                timeout=self.timeout,
            )
            if response.status_code >= 400:
                return None
            return response.json()
        except requests.RequestException:
            return None

    def lookup_ip(self, ip: Optional[str]) -> Optional[RDAPRecord]:
        if not ip:
            return None

        rdap_payload: Optional[Dict[str, Any]] = None
        whois_payload: Optional[Dict[str, Any]] = None

        # --- Step 1: RDAP (most authoritative / freshest) ---
        if IPWhois is not None:
            try:
                rdap_payload = IPWhois(ip).lookup_rdap(depth=1)
            except (IPDefinedError, HTTPLookupError, OSError, ValueError):
                rdap_payload = None

        if rdap_payload is None:
            rdap_payload = self._http_get(f"ip/{ip}")

        # --- Step 2: WHOIS fallback (lower confidence, older data) ---
        # Used when RDAP produced no contacts or the lookup failed entirely.
        if IPWhois is not None and (
            rdap_payload is None
            or not self._extract_contacts(rdap_payload) if rdap_payload else True
        ):
            try:
                whois_payload = IPWhois(ip).lookup_whois()
            except (IPDefinedError, OSError, ValueError):
                whois_payload = None

        # Use RDAP as primary payload for owner info; supplement contacts from WHOIS
        payload = rdap_payload or whois_payload
        if not payload:
            return None

        network = payload.get("network") if isinstance(payload.get("network"), dict) else {}
        owner = NetworkOwner(
            name=network.get("name") if network else payload.get("name"),
            handle=network.get("handle") if network else payload.get("handle"),
            country=network.get("country") if network else payload.get("country"),
            rir=payload.get("asn_registry") or payload.get("port43"),
        )

        contacts: List[AbuseContact] = []
        if rdap_payload:
            contacts.extend(self._extract_contacts(rdap_payload, source_prefix="rdap"))
        if whois_payload:
            contacts.extend(self._extract_contacts_from_whois(whois_payload))

        return RDAPRecord(
            ip=ip,
            owner=owner,
            contacts=_dedupe_contacts(contacts),
            raw=payload,
        )

    def _extract_contacts_from_whois(self, payload: Dict[str, Any]) -> List[AbuseContact]:
        """Extract abuse contacts from an ipwhois.lookup_whois() result.

        WHOIS data is considered less authoritative than RDAP, so confidence
        values are capped at 0.75 (abuse_emails) and 0.50 (generic emails).
        """
        contacts: List[AbuseContact] = []
        nets = payload.get("nets") or []
        for net in nets:
            if not isinstance(net, dict):
                continue
            # abuse_emails is a comma-separated string or None
            for raw in _split_emails(net.get("abuse_emails") or ""):
                addr = _normalize_email(raw)
                if addr:
                    contacts.append(AbuseContact(address=addr, source="whois:abuse_emails", confidence=0.75))
            # generic emails (tech, admin, …)
            for raw in _split_emails(net.get("emails") or ""):
                addr = _normalize_email(raw)
                if addr:
                    conf = 0.75 if "abuse" in addr.lower() else 0.50
                    contacts.append(AbuseContact(address=addr, source="whois:emails", confidence=conf))
        return contacts

    def lookup_domain(self, domain: Optional[str]) -> Optional[DomainRecord]:
        if not domain:
            return None

        payload = self._http_get(f"domain/{domain}")
        if not payload:
            return None

        contacts = self._extract_contacts(payload, source_prefix="domain-rdap")
        registrar = None
        if isinstance(payload.get("entities"), list):
            for entity in payload["entities"]:
                roles = [role.lower() for role in entity.get("roles", [])]
                if "registrar" in roles:
                    vcard = entity.get("vcardArray")
                    if isinstance(vcard, list) and len(vcard) > 1:
                        for entry in vcard[1]:
                            if isinstance(entry, list) and len(entry) >= 4 and entry[0].lower() == "fn":
                                registrar = entry[3]
                                break
                if registrar:
                    break

        country = payload.get("country")
        remarks = payload.get("remarks") or []
        for remark in remarks:
            if isinstance(remark, dict):
                for desc in remark.get("description", []):
                    if len(desc) == 2 and desc[0].lower() == "country":
                        country = desc[1]

        return DomainRecord(
            domain=domain,
            registrar=registrar,
            contacts=_dedupe_contacts(contacts),
            country=country,
            raw=payload,
        )

    def _extract_contacts(self, payload: Dict[str, Any], source_prefix: str = "rdap") -> List[AbuseContact]:
        contacts: List[AbuseContact] = []

        objects = payload.get("objects")
        if isinstance(objects, dict):
            for handle, obj in objects.items():
                roles = [
                    role.lower() if isinstance(role, str) else str(role).lower()
                    for role in obj.get("roles", [])
                    if role is not None
                ]
                contact_blob = obj.get("contact", {})
                emails = []
                if isinstance(contact_blob, dict):
                    for key in ("email", "abuse_mailbox"):
                        value = contact_blob.get(key)
                        emails.extend(self._coerce_emails(value))
                if not emails:
                    emails.extend(self._coerce_emails(obj.get("emails")))
                if not emails:
                    emails.extend(_match_emails(obj))

                for email in emails:
                    confidence = 0.6
                    if any(role for role in roles if "abuse" in role):
                        confidence = 0.95
                    elif any(role for role in roles if "security" in role):
                        confidence = 0.8
                    elif "postmaster" in email:
                        confidence = 0.7
                    contacts.append(
                        AbuseContact(
                            address=email,
                            source=f"{source_prefix}:{handle}",
                            confidence=confidence,
                        )
                    )

        entities = payload.get("entities")
        if isinstance(entities, list):
            for entity in entities:
                if not isinstance(entity, dict):
                    continue
                roles = [
                    role.lower() if isinstance(role, str) else str(role).lower()
                    for role in entity.get("roles", [])
                    if role is not None
                ]
                emails = []
                vcard = entity.get("vcardArray")
                emails.extend(_emails_from_vcard(vcard))
                if not emails:
                    emails.extend(_match_emails(entity))
                for email in emails:
                    confidence = _confidence_for_email(email)
                    if any("abuse" in role for role in roles):
                        confidence = max(confidence, 0.95)
                    contacts.append(
                        AbuseContact(
                            address=email,
                            source=f"{source_prefix}:entity",
                            confidence=confidence,
                        )
                    )

        if not contacts:
            fallback_emails = _match_emails(payload)
            for email in fallback_emails:
                contacts.append(
                    AbuseContact(
                        address=email,
                        source=f"{source_prefix}:fallback",
                        confidence=_confidence_for_email(email),
                    )
                )

        return contacts

    def _coerce_emails(self, value: Any) -> List[str]:
        emails: List[str] = []
        if isinstance(value, str):
            normalized = _normalize_email(value)
            if normalized:
                emails.append(normalized)
        elif isinstance(value, list):
            for entry in value:
                if isinstance(entry, dict) and "value" in entry:
                    normalized = _normalize_email(entry["value"])
                    if normalized:
                        emails.append(normalized)
                elif isinstance(entry, str):
                    normalized = _normalize_email(entry)
                    if normalized:
                        emails.append(normalized)
        elif isinstance(value, dict):
            for sub_value in value.values():
                emails.extend(self._coerce_emails(sub_value))
        return emails
