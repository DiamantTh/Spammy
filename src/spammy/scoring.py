"""Weighted spam scoring: Header → Body → URL → Auth → Network."""

from __future__ import annotations

import ipaddress
import re
from typing import List, Tuple

from .models import (
    AuthSummary,
    BodyIndicators,
    BodyLinkDetail,
    DNSCheckSummary,
    ReceivedHop,
    SpamMetadata,
    SpamScore,
    SpamSignal,
)

# ---------------------------------------------------------------------------
# Category weights (must sum to 1.0)
# URLs get the highest single weight per product requirement.
# ---------------------------------------------------------------------------
_CATEGORY_WEIGHTS = {
    "header": 0.20,
    "body": 0.25,
    "url": 0.30,
    "auth": 0.15,
    "network": 0.10,
}

# ---------------------------------------------------------------------------
# Spam text patterns: (regex, signal_name, description, base_weight)
# Patterns cover DE + EN since Spammy handles both locales.
# ---------------------------------------------------------------------------
_SPAM_PATTERNS: List[Tuple[str, str, str, float]] = [
    (
        r"\b(act now|limited time offer|expires soon|sofort handeln|jetzt handeln)\b",
        "urgency",
        "Dringlichkeitssprache",
        0.08,
    ),
    (
        r"\b(free|gratis|kostenlos|for free|free of charge|umsonst)\b",
        "free_offer",
        "Kostenlos-Versprechen",
        0.05,
    ),
    (
        r"\b(click here|click below|hier klicken|jetzt klicken|klicken sie hier)\b",
        "clickbait",
        "Click-Bait-Aufforderung",
        0.07,
    ),
    (
        r"\b(winner|you.?ve won|gewinner|sie haben gewonnen|congratulations|glückwunsch|herzlichen glückwunsch|lottery|lotterie)\b",
        "lottery",
        "Gewinn-/Lotteriebetrug",
        0.18,
    ),
    (
        r"\b(bank\s*account|wire\s*transfer|western\s*union|moneygram|swift\s*transfer|überweisung|bankverbindung)\b",
        "financial_fraud",
        "Finanzbetrug",
        0.22,
    ),
    (
        r"\b(nigerian|prince|inheritance|millions|beneficiary|erbe|erbschaft|prinz|million(en)?)\b",
        "advance_fee",
        "Vorschussbetrug (419)",
        0.28,
    ),
    (
        r"\b(enlarge|erectile|penis|viagra|cialis|pharmacy|apotheke|potenz|potenzmittel)\b",
        "pharma_spam",
        "Pharmaspam",
        0.22,
    ),
    (
        r"\b(lose weight|fat burn|diet pill|abnehmen|schlank|fettverbrenner|gewicht(s)?verlust)\b",
        "diet_spam",
        "Diätspam",
        0.15,
    ),
    (
        r"\b(casino|gambling|bet now|wetten|jackpot|spielcasino|glücksspiel)\b",
        "gambling",
        "Glücksspielwerbung",
        0.15,
    ),
    (
        r"\b(password|passwort|verify your account|konto bestätigen|login details|zugangsdaten|anmeldedaten)\b",
        "phishing",
        "Phishing-Signal",
        0.20,
    ),
    (
        r"\b(investment opportunity|investition|rendite|hohe rendite|high return|gewinnbringend)\b",
        "investment_fraud",
        "Investitionsbetrug",
        0.18,
    ),
    (
        r"\b(make money|geld verdienen|von zu hause|heimarbeit|work from home|nebenverdienst)\b",
        "money_making",
        "Geld-verdienen-Schema",
        0.12,
    ),
    (
        r"\$\s*\d[\d,\.]*\s*(million|billion|thousand|mio|mrd)?\b",
        "dollar_amount",
        "Auffälliger Geldbetrag",
        0.05,
    ),
    (
        r"[\!]{3,}",
        "excessive_exclamation",
        "Übermäßige Ausrufezeichen",
        0.04,
    ),
    (
        r"\b[A-ZÄÖÜ]{5,}\b",
        "all_caps_word",
        "GROSSSCHREIBUNG im Text",
        0.03,
    ),
]

# Known URL-shortener hostnames
_URL_SHORTENERS = frozenset(
    {
        "bit.ly",
        "t.co",
        "tinyurl.com",
        "goo.gl",
        "ow.ly",
        "short.to",
        "buff.ly",
        "adf.ly",
        "bc.vc",
        "is.gd",
        "rebrandly.com",
        "cutt.ly",
        "rb.gy",
        "shorturl.at",
    }
)

# TLDs commonly associated with throwaway/spam domains
_SUSPICIOUS_TLDS = frozenset(
    {".xyz", ".tk", ".top", ".gq", ".ml", ".ga", ".cf", ".pw", ".work", ".click", ".loan", ".win"}
)


def _clamp(value: float, lo: float = 0.0, hi: float = 1.0) -> float:
    return max(lo, min(hi, value))


# ---------------------------------------------------------------------------
# Phase 1 – Header scoring
# ---------------------------------------------------------------------------

def score_headers(
    metadata: SpamMetadata,
    received_hops: List[ReceivedHop],
) -> Tuple[float, List[SpamSignal]]:
    """Score structural header indicators.  Returns (score 0-1, signals)."""
    signals: List[SpamSignal] = []
    raw = 0.0

    # Excessive hop count (>6 is unusual)
    hop_count = len(received_hops)
    if hop_count > 6:
        w = min(0.04 * (hop_count - 6), 0.15)
        raw += w
        signals.append(SpamSignal("many_hops", f"{hop_count} Received-Hops (>6)", w, "header"))

    # From ≠ Return-Path domain mismatch
    from_domain = ""
    rp_domain = ""
    if "@" in (metadata.sender or ""):
        from_domain = metadata.sender.split("@", 1)[-1].lower().strip()
    rp = metadata.headers.get("Return-Path", "")
    if "@" in rp:
        rp_domain = rp.split("@", 1)[-1].strip().rstrip(">").lower()
    if from_domain and rp_domain and from_domain != rp_domain:
        raw += 0.20
        signals.append(
            SpamSignal(
                "from_rp_mismatch",
                f"From-Domain ({from_domain}) ≠ Return-Path-Domain ({rp_domain})",
                0.20,
                "header",
            )
        )

    # Missing Message-ID
    if not metadata.message_id:
        raw += 0.08
        signals.append(SpamSignal("no_message_id", "Fehlende Message-ID", 0.08, "header"))

    # Subject: CAPS or excessive punctuation
    subj = metadata.subject or ""
    if re.search(r"[A-ZÄÖÜ]{8,}", subj):
        raw += 0.06
        signals.append(SpamSignal("subject_caps", "Betreff in GROSSBUCHSTABEN", 0.06, "header"))
    if subj.count("!") >= 3:
        raw += 0.06
        signals.append(SpamSignal("subject_exclamation", "≥3 Ausrufezeichen im Betreff", 0.06, "header"))

    return _clamp(raw), signals


# ---------------------------------------------------------------------------
# Phase 1b – Auth scoring
# ---------------------------------------------------------------------------

def score_auth(auth: AuthSummary) -> Tuple[float, List[SpamSignal]]:
    """Score SPF/DKIM/DMARC results.  Returns (score 0-1, signals).
    0.5 = neutral, <0.5 = legitimacy signal, >0.5 = spam signal."""
    signals: List[SpamSignal] = []
    raw = 0.0  # deviation from neutral

    if auth.spf.result:
        r = auth.spf.result.lower()
        if r in ("fail", "hardfail"):
            raw += 0.35
            signals.append(SpamSignal("spf_fail", "SPF Hard Fail", 0.35, "auth"))
        elif r == "softfail":
            raw += 0.20
            signals.append(SpamSignal("spf_softfail", "SPF Soft Fail", 0.20, "auth"))
        elif r == "pass":
            raw -= 0.15
            signals.append(SpamSignal("spf_pass", "SPF bestanden (legitimitätsstärkend)", -0.15, "auth"))
        elif r in ("none", "neutral"):
            raw += 0.05
            signals.append(SpamSignal("spf_none", "Kein SPF-Eintrag vorhanden", 0.05, "auth"))

    if auth.dkim.result:
        r = auth.dkim.result.lower()
        if r == "pass":
            raw -= 0.20
            signals.append(SpamSignal("dkim_pass", "DKIM-Signatur gültig (legitimitätsstärkend)", -0.20, "auth"))
        elif r == "fail":
            raw += 0.30
            signals.append(SpamSignal("dkim_fail", "DKIM-Signatur ungültig", 0.30, "auth"))

    if auth.dmarc.result:
        r = auth.dmarc.result.lower()
        if r == "pass":
            raw -= 0.20
            signals.append(SpamSignal("dmarc_pass", "DMARC bestanden (legitimitätsstärkend)", -0.20, "auth"))
        elif r == "fail":
            raw += 0.30
            signals.append(SpamSignal("dmarc_fail", "DMARC fehlgeschlagen", 0.30, "auth"))

    # Map raw deviation to [0,1]: neutral → 0.5
    return _clamp(raw + 0.5), signals


# ---------------------------------------------------------------------------
# Phase 2 – Body text scoring (fuzzy keyword matching)
# ---------------------------------------------------------------------------

def score_body_text(text: str) -> Tuple[float, List[SpamSignal]]:
    """Score raw body text against spam patterns.  Returns (score 0-1, signals)."""
    if not text:
        return 0.0, []

    signals: List[SpamSignal] = []
    raw = 0.0
    lower = text.lower()

    for pattern, name, description, base_weight in _SPAM_PATTERNS:
        matches = re.findall(pattern, lower, re.IGNORECASE)
        if matches:
            count = len(matches)
            # Cap contribution at 3× the base weight per pattern
            contribution = min(base_weight * count, base_weight * 3.0)
            raw += contribution
            signals.append(
                SpamSignal(
                    name=name,
                    description=f"{description} ({count}×)",
                    weight=contribution,
                    category="body",
                )
            )

    return _clamp(raw), signals


# ---------------------------------------------------------------------------
# Phase 2b – URL scoring (highest-weight category)
# ---------------------------------------------------------------------------

def score_urls(
    body_indicators: BodyIndicators,
    body_link_details: List[BodyLinkDetail],
    sender_domain: str = "",
) -> Tuple[float, List[SpamSignal]]:
    """Score URLs found in the body.  Returns (score 0-1, signals)."""
    signals: List[SpamSignal] = []
    raw = 0.0
    urls = body_indicators.urls

    if not urls:
        return 0.0, signals

    url_count = len(urls)

    # Base contribution for URLs being present at all
    base_contrib = min(0.04 * url_count, 0.16)
    raw += base_contrib
    signals.append(
        SpamSignal("urls_present", f"{url_count} URL(s) im Body gefunden", base_contrib, "url")
    )

    # Insecure HTTP URLs
    http_count = sum(1 for u in urls if u.lower().startswith("http://"))
    if http_count:
        contrib = min(0.08 * http_count, 0.24)
        raw += contrib
        signals.append(SpamSignal("http_urls", f"{http_count} unsichere HTTP-URL(s)", contrib, "url"))

    # Analyse per-domain details
    ip_url_count = 0
    shortener_count = 0
    suspicious_tld_count = 0
    external_domain_count = 0

    for detail in body_link_details:
        domain = (detail.domain or "").lower()
        if not domain:
            continue

        # IP-literal URL (e.g. http://1.2.3.4/)
        try:
            ipaddress.ip_address(domain)
            ip_url_count += 1
        except ValueError:
            pass

        # URL shortener
        if domain in _URL_SHORTENERS:
            shortener_count += 1

        # Suspicious TLD
        for tld in _SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                suspicious_tld_count += 1
                break

        # Domain differs from sender domain
        if sender_domain and domain != sender_domain and not domain.endswith("." + sender_domain):
            external_domain_count += 1

    if ip_url_count:
        contrib = min(0.28 * ip_url_count, 0.55)
        raw += contrib
        signals.append(SpamSignal("ip_literal_urls", f"{ip_url_count} IP-Literal-URL(s) (hochverdächtig)", contrib, "url"))

    if shortener_count:
        contrib = min(0.12 * shortener_count, 0.30)
        raw += contrib
        signals.append(SpamSignal("url_shorteners", f"{shortener_count} URL-Verkürzer (Verschleierung)", contrib, "url"))

    if suspicious_tld_count:
        contrib = min(0.15 * suspicious_tld_count, 0.30)
        raw += contrib
        signals.append(SpamSignal("suspicious_tlds", f"{suspicious_tld_count} verdächtige TLD(s)", contrib, "url"))

    if external_domain_count:
        contrib = min(0.07 * external_domain_count, 0.21)
        raw += contrib
        signals.append(
            SpamSignal(
                "external_domains",
                f"{external_domain_count} externe Domain(s) (≠ Absender-Domain)",
                contrib,
                "url",
            )
        )

    return _clamp(raw), signals


# ---------------------------------------------------------------------------
# Phase 3 – Network / DNS scoring
# ---------------------------------------------------------------------------

def score_network(dns_checks: DNSCheckSummary) -> Tuple[float, List[SpamSignal]]:
    """Score DNS-based network signals.  Returns (score 0-1, signals)."""
    signals: List[SpamSignal] = []
    raw = 0.0

    if dns_checks.blocklist_hits:
        contrib = min(0.38 * len(dns_checks.blocklist_hits), 0.65)
        raw += contrib
        signals.append(
            SpamSignal(
                "blocklist_hit",
                f"IP in Blockliste(n): {', '.join(dns_checks.blocklist_hits)}",
                contrib,
                "network",
            )
        )

    if not dns_checks.reverse_dns and not dns_checks.reverse_error:
        # No PTR and no error means lookup simply returned nothing
        raw += 0.10
        signals.append(SpamSignal("no_ptr", "Kein rDNS/PTR-Eintrag für Sender-IP", 0.10, "network"))
    elif dns_checks.reverse_error and not dns_checks.reverse_dns:
        raw += 0.10
        signals.append(SpamSignal("no_ptr", "PTR-Auflösung fehlgeschlagen", 0.10, "network"))

    return _clamp(raw), signals


# ---------------------------------------------------------------------------
# Aggregation
# ---------------------------------------------------------------------------

def compute_spam_score(
    metadata: SpamMetadata,
    received_hops: List[ReceivedHop],
    auth_summary: AuthSummary,
    body_indicators: BodyIndicators,
    body_link_details: List[BodyLinkDetail],
    dns_checks: DNSCheckSummary,
    body_text: str = "",
) -> SpamScore:
    """Run all scoring phases and combine into a single SpamScore.

    Analysis order (mirrors the header-first, body-second pipeline):
      Phase 1 – Headers + Auth  (structural legitimacy)
      Phase 2 – Body text + URLs (content indicators)
      Phase 3 – Network / DNS    (external reputation)
    """
    sender_domain = (
        metadata.sender.split("@", 1)[-1].lower()
        if metadata.sender and "@" in metadata.sender
        else ""
    )

    # --- Phase 1 ---
    header_score, header_signals = score_headers(metadata, received_hops)
    auth_score, auth_signals = score_auth(auth_summary)

    # --- Phase 2 ---
    body_score, body_signals = score_body_text(body_text)
    url_score, url_signals = score_urls(body_indicators, body_link_details, sender_domain)

    # --- Phase 3 ---
    network_score, network_signals = score_network(dns_checks)

    # Auth: 0.5 = neutral; shift to contribution in [-0.5, +0.5] → scale to [0, 1] for weighting
    auth_contribution = _clamp((auth_score - 0.5) * 2.0)

    total = (
        _CATEGORY_WEIGHTS["header"] * header_score
        + _CATEGORY_WEIGHTS["body"] * body_score
        + _CATEGORY_WEIGHTS["url"] * url_score
        + _CATEGORY_WEIGHTS["auth"] * auth_contribution
        + _CATEGORY_WEIGHTS["network"] * network_score
    )

    all_signals = header_signals + auth_signals + body_signals + url_signals + network_signals

    return SpamScore(
        total=_clamp(total),
        header_score=header_score,
        body_score=body_score,
        url_score=url_score,
        auth_score=auth_score,
        network_score=network_score,
        signals=all_signals,
    )
