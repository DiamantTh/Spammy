from __future__ import annotations

import ipaddress
import socket
from typing import List, Optional

import dns.exception
import dns.reversename
import dns.resolver

from .models import DNSCheckSummary

BLOCKLIST_ZONES = [
    "zen.spamhaus.org",
    "bl.spamcop.net",
]


_resolver = dns.resolver.Resolver()
_resolver.timeout = 3.0
_resolver.lifetime = 3.0


def perform_dns_checks(ip: Optional[str], domain: Optional[str]) -> DNSCheckSummary:
    summary = DNSCheckSummary()
    if ip:
        summary.reverse_dns, summary.reverse_error = _reverse_dns(ip)
        summary.blocklist_hits, summary.blocklist_error = _check_blocklists(ip)
    if domain:
        summary.mx_records, summary.mx_error = _resolve_mx(domain)
        summary.spf_present, summary.spf_error = _check_spf(domain)
    return summary


def _reverse_dns(ip: str):
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname.rstrip("."), None
    except (socket.herror, socket.gaierror) as exc:
        return None, str(exc)


def _check_blocklists(ip: str):
    hits: List[str] = []
    reversed_ip = _reverse_ip(ip)
    if not reversed_ip:
        return hits, "invalid ip"
    for zone in BLOCKLIST_ZONES:
        query = f"{reversed_ip}.{zone}"
        try:
            _resolver.resolve(query, "A")
            hits.append(zone)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            continue
        except dns.exception.DNSException as exc:
            return hits, str(exc)
    return hits, None


def _resolve_mx(domain: str):
    records: List[str] = []
    try:
        answers = _resolver.resolve(domain, "MX")
        for answer in answers:
            host = str(answer.exchange).rstrip(".")
            if host:
                records.append(host)
        return records, None
    except dns.exception.DNSException as exc:
        return records, str(exc)


def _check_spf(domain: str):
    try:
        answers = _resolver.resolve(domain, "TXT")
        for answer in answers:
            text = "".join(part.decode() if isinstance(part, bytes) else part for part in answer.strings)
            if text.lower().startswith("v=spf1"):
                return True, None
        return False, None
    except dns.resolver.NXDOMAIN:
        return False, "NXDOMAIN"
    except dns.exception.DNSException as exc:
        return None, str(exc)


def _reverse_ip(ip: str) -> Optional[str]:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if addr.version != 4:
        return None
    octets = ip.split(".")
    return ".".join(reversed(octets))
