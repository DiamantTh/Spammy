from __future__ import annotations

import ipaddress
import socket
from typing import List, Optional
from urllib.parse import urlparse

from .dns_checks import DNSCheckSummary, perform_dns_checks
from .models import (
    AbuseContact,
    AnalysisResult,
    AttachmentSummary,
    BodyLinkDetail,
    DomainRecord,
    RDAPRecord,
    SpamMetadata,
)
from .parsing import (
    collect_received_hops,
    extract_body_indicators,
    extract_body_text,
    extract_inner_message,
    guess_origin_ip,
    load_message,
    metadata_from_message,
    parse_authentication_summary,
    summarize_attachments,
)
from .rdap_client import RDAPClient, rfc2142_contacts
from .scoring import compute_spam_score


LANGUAGE_MAP = {
    "DE": "de",
    "AT": "de",
    "CH": "de",
    "LI": "de",
    "LU": "de",
    "US": "en",
    "GB": "en",
    "IE": "en",
    "AU": "en",
    "NZ": "en",
    "CA": "en",
    "FR": "fr",
    "BE": "fr",
    "MC": "fr",
    "LU_FR": "fr",
    "ES": "es",
    "MX": "es",
    "AR": "es",
    "CO": "es",
    "CL": "es",
    "PE": "es",
    "UY": "es",
    "PY": "es",
    "VE": "es",
}

DEFAULT_LANGUAGE = "en"


def determine_language(country_code: Optional[str]) -> str:
    if not country_code:
        return DEFAULT_LANGUAGE
    code = country_code.upper()
    return LANGUAGE_MAP.get(code, DEFAULT_LANGUAGE)


def _merge_contacts(*lists: Optional[List[AbuseContact]]) -> List[AbuseContact]:
    seen: dict[str, AbuseContact] = {}
    for contact_list in lists:
        if not contact_list:
            continue
        for contact in contact_list:
            key = contact.address.lower()
            if key not in seen or contact.confidence > seen[key].confidence:
                seen[key] = contact
    return list(seen.values())


def analyze_message(raw_data: bytes, rdap_client: Optional[RDAPClient] = None) -> AnalysisResult:
    client = rdap_client or RDAPClient()

    outer_message = load_message(raw_data)
    inner_message = extract_inner_message(outer_message) or outer_message

    # =========================================================================
    # PHASE 1 – HEADER ANALYSIS
    # Structural signals: routing path, authentication, DNS reputation.
    # =========================================================================
    metadata = metadata_from_message(inner_message)
    received_hops = collect_received_hops(inner_message)
    candidate_ip = guess_origin_ip(received_hops)
    attachments = summarize_attachments(inner_message)
    auth_summary = parse_authentication_summary(inner_message)
    sender_domain = metadata.sender.split("@")[-1].lower() if "@" in metadata.sender else None
    dns_checks = perform_dns_checks(candidate_ip, sender_domain)

    # RDAP (primary, authoritative) + WHOIS fallback (handled inside lookup_ip)
    rdap_record = client.lookup_ip(candidate_ip)
    domain_record = client.lookup_domain(sender_domain)

    # RFC 2142 last-resort: use PTR hostname if structured lookups yielded nothing
    rfc2142 = []
    has_structured_contacts = bool(
        (rdap_record and rdap_record.contacts) or (domain_record and domain_record.contacts)
    )
    if not has_structured_contacts and dns_checks.reverse_dns:
        rfc2142 = rfc2142_contacts(dns_checks.reverse_dns)

    abuse_contacts = _merge_contacts(
        rdap_record.contacts if rdap_record else None,
        domain_record.contacts if domain_record else None,
        rfc2142 or None,
    )

    country_code = None
    if rdap_record and rdap_record.owner and rdap_record.owner.country:
        country_code = rdap_record.owner.country
    elif domain_record and domain_record.country:
        country_code = domain_record.country

    preferred_language = determine_language(country_code)

    # =========================================================================
    # PHASE 2 – BODY ANALYSIS
    # Content signals: URLs, spam text patterns, link destinations.
    # =========================================================================
    body_indicators = extract_body_indicators(inner_message)
    body_text = extract_body_text(inner_message)
    body_link_details = _resolve_body_links(body_indicators.urls, rdap_client=client)

    # =========================================================================
    # SCORING – combine header + body signals into a weighted SpamScore
    # =========================================================================
    spam_score = compute_spam_score(
        metadata=metadata,
        received_hops=received_hops,
        auth_summary=auth_summary,
        body_indicators=body_indicators,
        body_link_details=body_link_details,
        dns_checks=dns_checks,
        body_text=body_text,
    )

    return AnalysisResult(
        metadata=metadata,
        received_hops=received_hops,
        candidate_ip=candidate_ip,
        rdap_record=rdap_record,
        domain_record=domain_record,
        abuse_contacts=abuse_contacts,
        preferred_language=preferred_language,
        attachments=attachments,
        original_message=outer_message,
        inner_message=inner_message if inner_message is not outer_message else None,
        auth_summary=auth_summary,
        body_indicators=body_indicators,
        body_link_details=body_link_details,
        dns_checks=dns_checks,
        spam_score=spam_score,
    )


def _resolve_body_links(urls: List[str], rdap_client: RDAPClient) -> List[BodyLinkDetail]:
    details: List[BodyLinkDetail] = []
    seen_domains: set[str] = set()
    for url in urls:
        parsed = urlparse(url)
        domain = parsed.hostname
        uses_https = parsed.scheme.lower() == "https"
        if not domain or domain in seen_domains:
            continue
        seen_domains.add(domain)
        is_ip_literal = False
        try:
            ipaddress.ip_address(domain)
            is_ip_literal = True
        except ValueError:
            pass
        ips = _resolve_ips(domain, limit=3)
        ip_records: List[RDAPRecord] = []
        for ip in ips:
            record = rdap_client.lookup_ip(ip)
            if record:
                ip_records.append(record)
        domain_record = None if is_ip_literal else rdap_client.lookup_domain(domain)
        owner_names = [
            record.owner.name
            for record in ip_records
            if record.owner and record.owner.name
        ]
        details.append(
            BodyLinkDetail(
                url=url,
                domain=domain,
                resolved_ips=ips,
                domain_record=domain_record,
                ip_records=ip_records,
                uses_https=uses_https,
                ip_owner_names=owner_names,
            )
        )
    return details


def _resolve_ips(domain: str, limit: int = 3) -> List[str]:
    import concurrent.futures
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(socket.getaddrinfo, domain, None)
            infos = future.result(timeout=3.0)
    except (socket.gaierror, concurrent.futures.TimeoutError, OSError):
        return []
    ips: List[str] = []
    for info in infos:
        ip = info[4][0]
        if ":" in ip:
            continue  # skip IPv6 for now
        if ip not in ips:
            ips.append(ip)
        if len(ips) >= limit:
            break
    return ips
