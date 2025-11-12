from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
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
    parser.add_argument(
        "--config",
        type=Path,
        help="Pfad zur Spammy-Konfiguration (Standard: ./config/spammy.toml oder /etc/spammy/spammy.toml).",
    )
    parser.add_argument(
        "--eml",
        type=Path,
        help="Path to an EML/RFC822 file. If omitted, stdin is read (useful for Dovecot/Postfix pipe).",
    )
    parser.add_argument(
        "--output-html",
        type=Path,
        help="Write the rendered HTML report to this path.",
    )
    parser.add_argument(
        "--output-json",
        type=Path,
        help="Write machine-readable JSON to this path.",
    )
    parser.add_argument(
        "--output-text",
        type=Path,
        help="Write the localized plain-text template to this path.",
    )
    parser.add_argument(
        "--stdout-format",
        choices=["summary", "html", "json", "text", "none"],
        default="summary",
        help="Select what to print to stdout (default: summary).",
    )
    parser.add_argument(
        "--auto-stdout",
        action="store_true",
        help="Print stdout output without interactive confirmation prompts.",
    )
    parser.add_argument(
        "--language",
        choices=["en", "de", "fr", "es"],
        help="Override the automatically detected template language.",
    )
    parser.add_argument(
        "--template-dir",
        type=Path,
        help="Optional template directory overriding the bundled templates.",
    )
    parser.add_argument(
        "--rdap-base",
        default=None,
        help="Override RDAP base URL (defaults to rdap.org).",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=None,
        help="Network timeout for RDAP lookups in seconds (default: 8).",
    )
    return parser.parse_args(argv)


def load_input(path: Optional[Path]) -> bytes:
    if path:
        return path.read_bytes()
    return sys.stdin.buffer.read()


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(argv)
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

    client = RDAPClient(timeout=timeout, rdap_base=rdap_base)
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
    now = datetime.utcnow()
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
    rdap_owner = (
        result.rdap_record.owner.name
        if result.rdap_record and result.rdap_record.owner and result.rdap_record.owner.name
        else "unknown"
    )
    registrar = result.domain_record.registrar if result.domain_record else "n/a"
    domain = result.domain_record.domain if result.domain_record else "n/a"
    contacts = ", ".join(c.address for c in result.abuse_contacts) or "none"
    auth = result.auth_summary
    print(
        "=== Spammy Analysis Summary ===\n"
        f"Subject       : {result.metadata.subject}\n"
        f"Sender        : {result.metadata.sender}\n"
        f"Recipient     : {result.metadata.recipient}\n"
        f"Origin IP     : {result.candidate_ip or 'unknown'}\n"
        f"Attachments   : {len(result.attachments)}\n"
        f"RDAP IP check : {rdap_base} -> owner {rdap_owner}\n"
        f"RDAP domain   : {domain} (registrar {registrar})\n"
        f"SPF           : {auth.spf.result or 'unknown'} ({auth.spf.identity or auth.spf.detail or 'n/a'})\n"
        f"DKIM          : {auth.dkim.result or 'unknown'} ({auth.dkim.identity or auth.dkim.detail or 'n/a'})\n"
        f"DMARC         : {auth.dmarc.result or 'unknown'} ({auth.dmarc.identity or auth.dmarc.detail or 'n/a'})\n"
        f"Contacts      : {contacts}\n"
    )


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
