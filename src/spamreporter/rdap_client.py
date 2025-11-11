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


@dataclass
class RDAPClient:
    timeout: int = 8
    user_agent: str = "SpamReporter/0.1 (+https://example.local)"
    rdap_base: str = "https://rdap.org"

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

        payload: Optional[Dict[str, Any]] = None
        if IPWhois is not None:
            try:
                payload = IPWhois(ip).lookup_rdap(depth=1)
            except (IPDefinedError, HTTPLookupError, OSError, ValueError):
                payload = None

        if payload is None:
            payload = self._http_get(f"ip/{ip}")

        if not payload:
            return None

        owner = NetworkOwner(
            name=payload.get("network", {}).get("name")
            if isinstance(payload.get("network"), dict)
            else payload.get("name"),
            handle=payload.get("network", {}).get("handle") if isinstance(payload.get("network"), dict) else payload.get("handle"),
            country=payload.get("network", {}).get("country")
            if isinstance(payload.get("network"), dict)
            else payload.get("country"),
            rir=payload.get("asn_registry") or payload.get("port43"),
        )

        contacts = self._extract_contacts(payload)

        return RDAPRecord(
            ip=ip,
            owner=owner,
            contacts=_dedupe_contacts(contacts),
            raw=payload,
        )

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
                roles = [role.lower() for role in obj.get("roles", [])]
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
                roles = [role.lower() for role in entity.get("roles", [])]
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
