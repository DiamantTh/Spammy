from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from uuid import uuid4

from .analysis import analyze_message
from .config_loader import load_config
from .rdap_client import RDAPClient
from .reporting import ReportBuilder
from .storage import (
    AbuseContactRecord,
    AnalysisRecord,
    MessageRecord,
    StorageBackend,
    StorageError,
    build_storage,
)


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="spammy",
        description="Analyze spam EML files, run RDAP lookups, and generate multilingual abuse reports.",
    )
    general = parser.add_argument_group("General")
    general.add_argument(
        "--auto-stdout",
        action="store_true",
        help="Print stdout output without interactive confirmation prompts.",
    )
    general.add_argument(
        "--config",
        type=Path,
        help="Pfad zur Spammy-Konfiguration (Standard: ./config/spammy.toml oder /etc/spammy/spammy.toml).",
    )
    general.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose logging on stderr.",
    )
    general.add_argument(
        "-V",
        "--version",
        action="store_true",
        help="Print Spammy version and exit.",
    )

    io_group = parser.add_argument_group("Input / Output")
    io_group.add_argument(
        "--eml",
        type=Path,
        help="Path to an EML/RFC822 file. If omitted, stdin is read (useful for Dovecot/Postfix pipe).",
    )
    io_group.add_argument(
        "--output-html",
        type=Path,
        help="Write the rendered HTML report to this path.",
    )
    io_group.add_argument(
        "--output-json",
        type=Path,
        help="Write machine-readable JSON to this path.",
    )
    io_group.add_argument(
        "--output-text",
        type=Path,
        help="Write the localized plain-text template to this path.",
    )

    rendering = parser.add_argument_group("Rendering")
    rendering.add_argument(
        "--language",
        choices=["en", "de", "fr", "es"],
        help="Override the automatically detected template language.",
    )
    rendering.add_argument(
        "--stdout-format",
        choices=["summary", "html", "json", "text", "none"],
        default="summary",
        help="Select what to print to stdout (default: summary).",
    )
    rendering.add_argument(
        "--template-dir",
        type=Path,
        help="Optional template directory overriding the bundled ones.",
    )

    network = parser.add_argument_group("Network")
    network.add_argument(
        "--rdap-base",
        default=None,
        help="Override RDAP base URL (defaults to rdap.org).",
    )
    network.add_argument(
        "--timeout",
        type=int,
        default=None,
        help="Network timeout for RDAP lookups in seconds (default: 8).",
    )
    return parser.parse_args(argv)


MAX_EML_BYTES = 25 * 1024 * 1024  # 25 MB hard limit


def load_input(path: Optional[Path]) -> bytes:
    if path:
        size = path.stat().st_size
        if size > MAX_EML_BYTES:
            print(f"[spammy] EML file too large ({size} bytes > {MAX_EML_BYTES})", file=sys.stderr)
            sys.exit(1)
        return path.read_bytes()
    data = sys.stdin.buffer.read(MAX_EML_BYTES + 1)
    if len(data) > MAX_EML_BYTES:
        print(f"[spammy] stdin input too large (>{MAX_EML_BYTES} bytes)", file=sys.stderr)
        sys.exit(1)
    return data


def main(argv: Optional[list[str]] = None) -> int:
    _argv = list(sys.argv[1:] if argv is None else argv)
    if _argv and _argv[0] == "serve":
        return _serve_main(_argv[1:])
    args = parse_args(_argv)
    if args.version:
        from . import __version__

        print(f"Spammy {__version__}")
        return 0
    raw = load_input(args.eml)
    config = load_config(args.config)
    rdap_base = args.rdap_base or config.rdap.base_url
    timeout = args.timeout or config.rdap.timeout
    template_dir = args.template_dir or config.reporting.template_dir
    try:
        storage_backend = build_storage(config.storage)
    except StorageError as exc:  # pragma: no cover - requires env mismatch
        print(f"[spammy] Failed to initialise storage backend: {exc}", file=sys.stderr)
        storage_backend = None

    try:
        client = RDAPClient(timeout=timeout, rdap_base=rdap_base)
    except ValueError as exc:
        print(f"[spammy] Invalid RDAP base URL: {exc}", file=sys.stderr)
        return 1
    result = analyze_message(raw, rdap_client=client)
    _persist_result(storage_backend, result)

    builder = ReportBuilder(template_dir=template_dir)
    lang = args.language or result.preferred_language

    html_report = builder.render_html(result, lang=lang)
    text_report = builder.render_text(result, lang=lang)
    json_report = builder.json_dump(result)

    if args.output_html:
        args.output_html.write_text(html_report, encoding="utf-8")
    if args.output_text:
        args.output_text.write_text(text_report, encoding="utf-8")
    if args.output_json:
        args.output_json.write_text(json_report, encoding="utf-8")

    stdout_format = _maybe_confirm_stdout(args.stdout_format, args.auto_stdout)
    if stdout_format == "summary":
        _print_summary(result, rdap_base=rdap_base)
    elif stdout_format == "html":
        sys.stdout.write(html_report)
    elif stdout_format == "text":
        sys.stdout.write(text_report)
    elif stdout_format == "json":
        sys.stdout.write(json_report)

    return 0


def _persist_result(storage: Optional[StorageBackend], result) -> None:
    if not storage:
        return

    message_record, analysis_record, contact_records = _build_records(result)
    try:
        storage.store_message(message_record, analysis_record, contact_records)
    except StorageError as exc:  # pragma: no cover - requires backend fail
        print(f"[spammy] Failed to persist analysis: {exc}", file=sys.stderr)


def _build_records(result):
    message_uuid = result.metadata.message_id or str(uuid4())
    now = datetime.now(timezone.utc)
    message_record = MessageRecord(
        message_id=message_uuid,
        subject=result.metadata.subject,
        sender=result.metadata.sender,
        recipient=result.metadata.recipient,
        category=None,
        mailbox=result.metadata.recipient,
        created_at=now,
    )
    rdap_owner = result.rdap_record.owner.name if result.rdap_record and result.rdap_record.owner else None
    analysis_record = AnalysisRecord(
        message_id=message_uuid,
        origin_ip=result.candidate_ip,
        rdap_network=rdap_owner,
        severity=None,
        metadata_json=json.dumps(result.to_dict(), ensure_ascii=False),
        created_at=now,
    )
    contacts = [
        AbuseContactRecord(
            message_id=message_uuid,
            address=contact.address,
            role=contact.source,
            confidence=contact.confidence,
        )
        for contact in result.abuse_contacts
    ]
    return message_record, analysis_record, contacts


def _print_summary(result, rdap_base: str) -> None:
    header_lines = "\n".join(result.metadata.raw_headers)
    print("=== Full header ===")
    print(header_lines)
    print()

    rdap_owner = (
        result.rdap_record.owner.name
        if result.rdap_record and result.rdap_record.owner and result.rdap_record.owner.name
        else "unknown"
    )
    registrar = result.domain_record.registrar if result.domain_record else "n/a"
    domain = result.domain_record.domain if result.domain_record else "n/a"

    print("=== Header analysis ===")
    print(f"Subject          : {result.metadata.subject}")
    print(f"Sender           : {result.metadata.sender}")
    print(f"Recipient        : {result.metadata.recipient}")
    print(f"Candidate IP     : {result.candidate_ip or 'unknown'}")
    print(f"RDAP IP lookup   : {rdap_base} -> {rdap_owner}")
    print(f"RDAP domain      : {domain} (registrar {registrar})")
    if result.received_hops:
        print("Received hops    :")
        for hop in result.received_hops:
            print(f"  - {hop.raw}")
    else:
        print("Received hops    : none")
    print()

    dns = result.dns_checks
    print("=== DNS / MX checks ===")
    reverse = dns.reverse_dns or f"(error: {dns.reverse_error})" if dns.reverse_error else "n/a"
    print(f"Reverse DNS    : {reverse}")
    if dns.mx_records:
        print(f"MX records     : {', '.join(dns.mx_records)}")
    elif dns.mx_error:
        print(f"MX records     : error ({dns.mx_error})")
    else:
        print("MX records     : none")
    if dns.spf_present is True:
        print("SPF record     : present")
    elif dns.spf_present is False:
        print("SPF record     : not found")
    else:
        print(f"SPF record     : error ({dns.spf_error})" if dns.spf_error else "unknown")
    if dns.blocklist_hits:
        print(f"Blocklist hits : {', '.join(dns.blocklist_hits)}")
    elif dns.blocklist_error:
        print(f"Blocklist hits : error ({dns.blocklist_error})")
    else:
        print("Blocklist hits : none")
    print()

    indicators = result.body_indicators
    print("=== Body analysis ===")
    if indicators.urls:
        print("URLs:")
        for url in indicators.urls:
            print(f"  - {url}")
    else:
        print("URLs: none")
    if indicators.domains:
        print("Domains:")
        for dom in indicators.domains:
            print(f"  - {dom}")
    else:
        print("Domains: none")
    if indicators.ips:
        print("IPs:")
        for ip in indicators.ips:
            print(f"  - {ip}")
    else:
        print("IPs: none")
    print()

    auth = result.auth_summary
    print("=== Authentication ===")
    print(f"SPF  : {auth.spf.result or 'unknown'} ({auth.spf.identity or auth.spf.detail or 'n/a'})")
    print(f"DKIM : {auth.dkim.result or 'unknown'} ({auth.dkim.identity or auth.dkim.detail or 'n/a'})")
    print(f"DMARC: {auth.dmarc.result or 'unknown'} ({auth.dmarc.identity or auth.dmarc.detail or 'n/a'})")
    print()

    if result.body_link_details:
        print("=== Body link owners ===")
        for detail in result.body_link_details:
            print(f"- {detail.domain or detail.url}")
            if detail.resolved_ips:
                print(f"    Resolved IPs: {', '.join(detail.resolved_ips)}")
            if detail.domain_record and detail.domain_record.registrar:
                print(f"    Registrar   : {detail.domain_record.registrar}")
            if detail.ip_owner_names:
                print(f"    IP Owners   : {', '.join(detail.ip_owner_names)}")
            if not detail.uses_https:
                print("    WARNING     : HTTP link (no TLS)")
        print()

    if result.abuse_contacts:
        print("=== Abuse contacts ===")
        for contact in result.abuse_contacts:
            print(f"- {contact.address} ({int(contact.confidence * 100)}%)")
    else:
        print("=== Abuse contacts ===")
        print("No contacts discovered.")


def _maybe_confirm_stdout(format_choice: str, auto_stdout: bool) -> str:
    if format_choice in {"summary", "none"}:
        return format_choice
    if auto_stdout or not sys.stdout.isatty() or not sys.stdin.isatty():
        return format_choice
    prompt = f"Display rendered {format_choice.upper()} output on stdout? [y/N] "
    try:
        answer = input(prompt).strip().lower()
    except EOFError:  # pragma: no cover - interactive guard
        return "none"
    if answer in {"y", "yes"}:
        return format_choice
    print("[spammy] Skipping stdout template output.")
    return "none"


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())


def _serve_main(argv: list[str]) -> int:
    """Entry-point for ``spammy serve [OPTIONS]``."""
    import argparse as _ap

    p = _ap.ArgumentParser(prog="spammy serve", description="Start the Spammy web server.")
    p.add_argument("--host", default=None, help="Bind address for the web UI (overrides config).")
    p.add_argument("--port", type=int, default=None, help="Port for the web UI (overrides config).")
    p.add_argument("--with-api", action="store_true", help="Also start the external FastAPI service.")
    p.add_argument("--api-host", default=None, help="Bind address for the external API.")
    p.add_argument("--api-port", type=int, default=None, help="Port for the external API.")
    p.add_argument("--debug", action="store_true", help="Enable debug mode (auto-reload, verbose errors).")
    p.add_argument("--config", type=Path, default=None, help="Path to spammy.toml config file.")
    args = p.parse_args(argv)

    import logging
    logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO, format="%(levelname)s %(name)s: %(message)s")

    cfg = load_config(args.config)

    from .server import run as server_run
    server_run(
        config=cfg,
        host=args.host,
        port=args.port,
        api_host=args.api_host,
        api_port=args.api_port,
        with_api=args.with_api,
        debug=args.debug,
    )
    return 0
