from __future__ import annotations

import ipaddress
import re
from datetime import datetime
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import parsedate_to_datetime, parsedate_to_datetime as parse_email_date, parseaddr
from typing import List, Optional, Tuple

from .models import (
    AttachmentSummary,
    AuthStatus,
    AuthSummary,
    BodyIndicators,
    ReceivedHop,
    SpamMetadata,
)

IPV4_RE = re.compile(r"(?:\d{1,3}\.){3}\d{1,3}")
IPV6_RE = re.compile(r"\b([0-9a-f:]{3,})\b", re.IGNORECASE)
HOST_RE = re.compile(r"from\s+([^\s;]+)", re.IGNORECASE)


def load_message(data: bytes) -> EmailMessage:
    """Parse raw RFC822 bytes into EmailMessage with default policy."""

    parser = BytesParser(policy=policy.default)
    return parser.parsebytes(data)


def extract_inner_message(message: EmailMessage) -> Optional[EmailMessage]:
    """
    If the message contains a nested message/rfc822 part (common for
    forwarded spam attachments), return the first such part.
    """

    for part in message.walk():
        if part.get_content_type() == "message/rfc822":
            payload = part.get_payload(0)
            if isinstance(payload, EmailMessage):
                return payload
    return None


def metadata_from_message(message: EmailMessage) -> SpamMetadata:
    headers = {
        key: message.get(key, "")
        for key in ["Subject", "From", "To", "Date", "Message-ID", "Return-Path", "Received-SPF"]
        if message.get(key) is not None
    }
    raw_headers = [f"{k}: {v}" for (k, v) in message.items()]

    sender = parseaddr(message.get("From", ""))[1] or message.get("From", "")
    recipient = parseaddr(message.get("To", ""))[1] or message.get("To", "")
    date_header = message.get("Date")
    date = parsedate_to_datetime(date_header) if date_header else None

    return SpamMetadata(
        subject=message.get("Subject", "(no subject)"),
        sender=sender,
        recipient=recipient,
        date=date,
        message_id=message.get("Message-ID"),
        headers=headers,
        raw_headers=raw_headers,
    )


def _parse_received_timestamp(raw_header: str) -> Optional[datetime]:
    if ";" not in raw_header:
        return None
    ts = raw_header.split(";")[-1].strip()
    try:
        return parse_email_date(ts)
    except (ValueError, TypeError):
        return None


def _extract_ip(raw_header: str) -> Optional[str]:
    match = IPV4_RE.search(raw_header)
    if match:
        candidate = match.group(0)
        try:
            ipaddress.ip_address(candidate)
            return candidate
        except ValueError:
            pass

    match = IPV6_RE.search(raw_header)
    if match:
        value = match.group(1)
        # Remove enclosing brackets if present
        value = value.strip("[]")
        try:
            ipaddress.ip_address(value)
            return value
        except ValueError:
            return None
    return None


def _extract_hostname(raw_header: str) -> Optional[str]:
    match = HOST_RE.search(raw_header)
    if match:
        host = match.group(1)
        return host.strip("()")
    return None


def collect_received_hops(message: EmailMessage) -> List[ReceivedHop]:
    headers = message.get_all("Received", [])
    hops: List[ReceivedHop] = []
    for entry in headers:
        ip = _extract_ip(entry)
        hostname = _extract_hostname(entry)
        timestamp = _parse_received_timestamp(entry)
        hops.append(ReceivedHop(raw=entry, ip=ip, hostname=hostname, timestamp=timestamp))
    return hops


def _is_public_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return not (addr.is_private or addr.is_loopback or addr.is_reserved or addr.is_multicast)
    except ValueError:
        return False


def guess_origin_ip(hops: List[ReceivedHop]) -> Optional[str]:
    """
    Attempt to identify the first hop outside the local infrastructure by
    scanning Received headers from oldest to newest.
    """

    for hop in reversed(hops):
        if hop.ip and _is_public_ip(hop.ip):
            return hop.ip
    return None


def summarize_attachments(message: EmailMessage) -> List[AttachmentSummary]:
    attachments: List[AttachmentSummary] = []
    for part in message.iter_attachments():
        payload = part.get_payload(decode=True) or b""
        attachments.append(
            AttachmentSummary(
                filename=part.get_filename(),
                content_type=part.get_content_type(),
                size=len(payload),
            )
        )
    return attachments


URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
DOMAIN_RE = re.compile(r"\b([a-z0-9][a-z0-9-]{1,63}\.)+(?:[a-z]{2,})\b", re.IGNORECASE)
BODY_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def extract_body_indicators(message: EmailMessage) -> BodyIndicators:
    text_chunks: List[str] = []
    for part in message.walk():
        if part.get_content_maintype() == "multipart":
            continue
        content_type = part.get_content_type()
        if content_type in {"text/plain", "text/html"}:
            try:
                payload = part.get_payload(decode=True)
                if payload:
                    text_chunks.append(payload.decode(part.get_content_charset() or "utf-8", errors="replace"))
            except Exception:  # pragma: no cover - defensive
                continue
    blob = "\n".join(text_chunks)
    urls = sorted(set(URL_RE.findall(blob)))
    domains = sorted(set(_normalize_domain(match.group(0)) for match in DOMAIN_RE.finditer(blob)))
    ips = sorted(set(filter(_is_public_ip_text, BODY_IPV4_RE.findall(blob))))
    return BodyIndicators(urls=urls, domains=domains, ips=ips)


def extract_body_text(message: EmailMessage) -> str:
    """Return the body as a single plain-text string for content scoring.

    Preference order: text/plain first, then HTML with tags stripped.
    The returned string is suitable for passing to ``score_body_text()``.
    """
    plain_parts: List[str] = []
    html_parts: List[str] = []

    for part in message.walk():
        if part.get_content_maintype() == "multipart":
            continue
        content_type = part.get_content_type()
        try:
            raw = part.get_payload(decode=True)
            if not raw:
                continue
            text = raw.decode(part.get_content_charset() or "utf-8", errors="replace")
        except Exception:  # pragma: no cover
            continue
        if content_type == "text/plain":
            plain_parts.append(text)
        elif content_type == "text/html":
            html_parts.append(text)

    if plain_parts:
        return "\n".join(plain_parts)

    # Strip HTML tags from HTML-only messages
    combined = "\n".join(html_parts)
    combined = re.sub(r"<[^>]+>", " ", combined)
    combined = re.sub(r"&[a-zA-Z]{2,6};", " ", combined)
    combined = re.sub(r"\s{2,}", " ", combined)
    return combined.strip()


def _normalize_domain(domain: str) -> str:
    value = domain.lower().strip().strip(".")
    return value


def _is_public_ip_text(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return addr.version == 4 and not (addr.is_private or addr.is_loopback or addr.is_multicast)
    except ValueError:
        return False


def parse_authentication_summary(message: EmailMessage) -> AuthSummary:
    summary = AuthSummary()
    records = message.get_all("Authentication-Results", [])
    for record in records:
        _apply_auth_record(summary, record)

    received_spf = message.get("Received-SPF")
    if received_spf and not summary.spf.result:
        result_token = received_spf.split(";", 1)[0]
        parts = result_token.split()

        if parts:
            status = parts[0].split("=")
            verdict = status[1] if len(status) > 1 else status[0]
            summary.spf = AuthStatus(
                result=verdict.strip(),
                detail=received_spf.strip(),
            )
    return summary


AUTH_PATTERN = re.compile(r"(?P<method>spf|dkim|dmarc)=(?P<result>[a-zA-Z]+)(?P<rest>[^;]*)", re.IGNORECASE)


def _apply_auth_record(summary: AuthSummary, record: str) -> None:
    for match in AUTH_PATTERN.finditer(record):
        method = match.group("method").lower()
        result = match.group("result").lower()
        rest = match.group("rest").strip()
        identity = _extract_identity(rest)
        status = AuthStatus(
            result=result,
            detail=rest or None,
            identity=identity,
        )
        if method == "spf":
            summary.spf = status
        elif method == "dkim":
            summary.dkim = status
        elif method == "dmarc":
            summary.dmarc = status


IDENTITY_RE = re.compile(r"(smtp\.(mailfrom|helo)|header\.d|d)=([^;\s]+)")


def _extract_identity(rest: str) -> Optional[str]:
    match = IDENTITY_RE.search(rest)
    if match:
        return match.group(3)
    return None
