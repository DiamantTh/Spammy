from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from email.message import EmailMessage
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence


@dataclass
class ReceivedHop:
    """Represents a single Received header hop."""

    raw: str
    ip: Optional[str] = None
    hostname: Optional[str] = None
    timestamp: Optional[datetime] = None


@dataclass
class AbuseContact:
    """Discovered abuse or postmaster contact."""

    address: str
    source: str
    confidence: float = 0.5


@dataclass
class NetworkOwner:
    """Network ownership metadata returned by RDAP."""

    name: Optional[str] = None
    handle: Optional[str] = None
    country: Optional[str] = None
    rir: Optional[str] = None


@dataclass
class RDAPRecord:
    """Normalized RDAP/WHOIS information."""

    ip: str
    owner: Optional[NetworkOwner] = None
    contacts: List[AbuseContact] = field(default_factory=list)
    raw: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DomainRecord:
    """RDAP data for the envelope/domain sender."""

    domain: str
    registrar: Optional[str] = None
    contacts: List[AbuseContact] = field(default_factory=list)
    country: Optional[str] = None
    raw: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SpamMetadata:
    """High level message metadata used in the report."""

    subject: str
    sender: str
    recipient: str
    date: Optional[datetime]
    message_id: Optional[str]
    headers: Dict[str, str]
    raw_headers: Sequence[str]


@dataclass
class AttachmentSummary:
    filename: Optional[str]
    content_type: str
    size: int


@dataclass
class AuthStatus:
    result: Optional[str] = None
    detail: Optional[str] = None
    identity: Optional[str] = None


@dataclass
class AuthSummary:
    spf: AuthStatus = field(default_factory=AuthStatus)
    dkim: AuthStatus = field(default_factory=AuthStatus)
    dmarc: AuthStatus = field(default_factory=AuthStatus)


@dataclass
class BodyIndicators:
    urls: List[str] = field(default_factory=list)
    domains: List[str] = field(default_factory=list)
    ips: List[str] = field(default_factory=list)


@dataclass
class BodyLinkDetail:
    url: str
    domain: Optional[str]
    resolved_ips: List[str]
    domain_record: Optional[DomainRecord] = None
    ip_records: List[RDAPRecord] = field(default_factory=list)
    uses_https: bool = True
    ip_owner_names: List[str] = field(default_factory=list)


@dataclass
class DNSCheckSummary:
    reverse_dns: Optional[str] = None
    reverse_error: Optional[str] = None
    mx_records: List[str] = field(default_factory=list)
    mx_error: Optional[str] = None
    spf_present: Optional[bool] = None
    spf_error: Optional[str] = None
    blocklist_hits: List[str] = field(default_factory=list)
    blocklist_error: Optional[str] = None


@dataclass
class AnalysisResult:
    """Complete analysis payload consumed by reporters."""

    metadata: SpamMetadata
    received_hops: List[ReceivedHop]
    candidate_ip: Optional[str]
    rdap_record: Optional[RDAPRecord]
    domain_record: Optional[DomainRecord]
    abuse_contacts: List[AbuseContact]
    preferred_language: str
    attachments: List[AttachmentSummary]
    original_message: EmailMessage
    inner_message: Optional[EmailMessage] = None
    auth_summary: AuthSummary = field(default_factory=AuthSummary)
    body_indicators: BodyIndicators = field(default_factory=BodyIndicators)
    body_link_details: List[BodyLinkDetail] = field(default_factory=list)
    dns_checks: DNSCheckSummary = field(default_factory=DNSCheckSummary)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize the result for JSON output."""

        def serialize_contacts(contacts: List[AbuseContact]) -> List[Dict[str, Any]]:
            return [
                {
                    "address": c.address,
                    "source": c.source,
                    "confidence": c.confidence,
                }
                for c in contacts
            ]

        return {
            "metadata": {
                "subject": self.metadata.subject,
                "sender": self.metadata.sender,
                "recipient": self.metadata.recipient,
                "date": self.metadata.date.isoformat() if self.metadata.date else None,
                "message_id": self.metadata.message_id,
                "headers": self.metadata.headers,
                "raw_headers": list(self.metadata.raw_headers),
            },
            "received_hops": [
                {
                    "raw": hop.raw,
                    "ip": hop.ip,
                    "hostname": hop.hostname,
                    "timestamp": hop.timestamp.isoformat() if hop.timestamp else None,
                }
                for hop in self.received_hops
            ],
            "candidate_ip": self.candidate_ip,
            "rdap_record": {
                "ip": self.rdap_record.ip,
                "owner": self.rdap_record.owner.__dict__ if self.rdap_record and self.rdap_record.owner else None,
                "contacts": serialize_contacts(self.rdap_record.contacts) if self.rdap_record else [],
                "raw": self.rdap_record.raw if self.rdap_record else {},
            }
            if self.rdap_record
            else None,
            "domain_record": {
                "domain": self.domain_record.domain,
                "registrar": self.domain_record.registrar,
                "contacts": serialize_contacts(self.domain_record.contacts),
                "country": self.domain_record.country,
                "raw": self.domain_record.raw,
            }
            if self.domain_record
            else None,
            "abuse_contacts": serialize_contacts(self.abuse_contacts),
            "preferred_language": self.preferred_language,
            "attachments": [
                {
                    "filename": att.filename,
                    "content_type": att.content_type,
                    "size": att.size,
                }
                for att in self.attachments
            ],
            "auth_summary": {
                "spf": self._auth_status_dict(self.auth_summary.spf),
                "dkim": self._auth_status_dict(self.auth_summary.dkim),
                "dmarc": self._auth_status_dict(self.auth_summary.dmarc),
            },
            "body_indicators": {
                "urls": self.body_indicators.urls,
                "domains": self.body_indicators.domains,
                "ips": self.body_indicators.ips,
            },
            "body_link_details": [
                {
                    "url": detail.url,
                    "domain": detail.domain,
                    "resolved_ips": detail.resolved_ips,
                    "domain_record": self._domain_dict(detail.domain_record),
                    "ip_records": [self._rdap_dict(record) for record in detail.ip_records],
                    "uses_https": detail.uses_https,
                }
                for detail in self.body_link_details
            ],
            "dns_checks": {
                "reverse_dns": self.dns_checks.reverse_dns,
                "reverse_error": self.dns_checks.reverse_error,
                "mx_records": self.dns_checks.mx_records,
                "mx_error": self.dns_checks.mx_error,
                "spf_present": self.dns_checks.spf_present,
                "spf_error": self.dns_checks.spf_error,
                "blocklist_hits": self.dns_checks.blocklist_hits,
                "blocklist_error": self.dns_checks.blocklist_error,
            },
        }

    @staticmethod
    def _auth_status_dict(status: AuthStatus) -> Dict[str, Optional[str]]:
        return {
            "result": status.result,
            "detail": status.detail,
            "identity": status.identity,
        }

    @staticmethod
    def _rdap_dict(record: Optional[RDAPRecord]) -> Optional[Dict[str, Any]]:
        if not record:
            return None
        return {
            "ip": record.ip,
            "owner": record.owner.__dict__ if record.owner else None,
            "contacts": [
                {
                    "address": c.address,
                    "source": c.source,
                    "confidence": c.confidence,
                }
                for c in record.contacts
            ],
            "raw": record.raw,
        }

    @staticmethod
    def _domain_dict(record: Optional[DomainRecord]) -> Optional[Dict[str, Any]]:
        if not record:
            return None
        return {
            "domain": record.domain,
            "registrar": record.registrar,
            "contacts": [
                {
                    "address": c.address,
                    "source": c.source,
                    "confidence": c.confidence,
                }
                for c in record.contacts
            ],
            "country": record.country,
            "raw": record.raw,
        }


@dataclass
class ReportPaths:
    """Represents output files generated by CLI."""

    html: Optional[Path] = None
    json: Optional[Path] = None
    text: Optional[Path] = None
