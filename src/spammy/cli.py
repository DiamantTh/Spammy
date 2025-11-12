from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Optional

from .analysis import analyze_message
from .config_loader import load_config
from .rdap_client import RDAPClient
from .reporting import ReportBuilder


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

    client = RDAPClient(timeout=timeout, rdap_base=rdap_base)
    result = analyze_message(raw, rdap_client=client)

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

    stdout_format = args.stdout_format
    if stdout_format == "summary":
        print(
            f"Subject: {result.metadata.subject}\n"
            f"Sender: {result.metadata.sender}\n"
            f"Origin IP: {result.candidate_ip or 'unknown'}\n"
            f"Contacts: {', '.join(c.address for c in result.abuse_contacts) or 'none'}"
        )
    elif stdout_format == "html":
        sys.stdout.write(html_report)
    elif stdout_format == "text":
        sys.stdout.write(text_report)
    elif stdout_format == "json":
        sys.stdout.write(json_report)

    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
