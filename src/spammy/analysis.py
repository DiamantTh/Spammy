from __future__ import annotations

from typing import List, Optional

from .models import AbuseContact, AnalysisResult, AttachmentSummary, DomainRecord, RDAPRecord, SpamMetadata
from .parsing import (
    collect_received_hops,
    extract_inner_message,
    guess_origin_ip,
    load_message,
    metadata_from_message,
    parse_authentication_summary,
    summarize_attachments,
)
from .rdap_client import RDAPClient


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
    merged: List[AbuseContact] = []
    seen = set()
    for contact_list in lists:
        if not contact_list:
            continue
        for contact in contact_list:
            key = contact.address.lower()
            existing = next((c for c in merged if c.address.lower() == key), None)
            if not existing:
                merged.append(contact)
            elif contact.confidence > existing.confidence:
                existing.confidence = contact.confidence
                existing.source = contact.source
    return merged


def analyze_message(raw_data: bytes, rdap_client: Optional[RDAPClient] = None) -> AnalysisResult:
    client = rdap_client or RDAPClient()

    outer_message = load_message(raw_data)
    inner_message = extract_inner_message(outer_message) or outer_message
    metadata = metadata_from_message(inner_message)
    received_hops = collect_received_hops(inner_message)
    candidate_ip = guess_origin_ip(received_hops)
    attachments = summarize_attachments(inner_message)
    auth_summary = parse_authentication_summary(inner_message)

    rdap_record = client.lookup_ip(candidate_ip)
    sender_domain = metadata.sender.split("@")[-1].lower() if "@" in metadata.sender else None
    domain_record = client.lookup_domain(sender_domain)

    abuse_contacts = _merge_contacts(
        rdap_record.contacts if rdap_record else None,
        domain_record.contacts if domain_record else None,
    )

    country_code = None
    if rdap_record and rdap_record.owner and rdap_record.owner.country:
        country_code = rdap_record.owner.country
    elif domain_record and domain_record.country:
        country_code = domain_record.country

    preferred_language = determine_language(country_code)

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
    )
