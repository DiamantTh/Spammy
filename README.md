## Spammy – Local Spam Analysis & Abuse Reporter

Spammy is a self-hosted Python tool inspired by SpamCop. It ingests full EML/RFC822 messages, analyses Received headers to guess the originating system, performs RDAP/WHOIS lookups, and generates multilingual abuse reports (HTML, text, JSON). You can invoke it from Dovecot/Sieve, Postfix, rspamd, or manually via CLI.

### Highlights

- ✅ **EML ingestion** – reads stdin or files, automatically unwraps `message/rfc822` attachments.
- 🌐 **Modern RDAP lookups** – uses `ipwhois`/`rdap.org` to fetch network owners, registrar info, and abuse contacts.
- ✉️ **Abuse contact discovery** – extracts abuse/postmaster/security addresses from RDAP entities and objects.
- 🗣️ **Multilingual templates** – bundled HTML & TXT templates for English, German, French, and Spanish with automatic language selection based on RDAP country (override via `--language`).
- 📤 **User-ready reports** – writes responsive HTML, JSON, or plaintext summaries and prints a concise CLI summary.
- 🔌 **Mailserver integration** – designed for Dovecot `sieve_extprograms`, Postfix pipes/content filters, or rspamd external services. Optional daemon/milter modes are documented for advanced setups.

---

## Installation

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install --upgrade pip
pip install -e .
```

The editable install exposes a `spamreporter` CLI (defined in `pyproject.toml`).

---

## Usage

Basic analysis from a file:

```bash
spamreporter --eml samples/spam.eml \
  --output-html /tmp/report.html \
  --output-json /tmp/report.json \
  --output-text /tmp/report.txt
```

Reading from stdin (ideal for Dovecot/Postfix):

```bash
cat spam.eml | spamreporter --stdout-format text
```

Important flags:

| Flag | Description |
| --- | --- |
| `--language {en,de,fr,es}` | Force a specific template language. |
| `--template-dir /path` | Use custom Jinja2 templates instead of the bundled ones. |
| `--output-html/--output-json/--output-text` | Persist rendered reports. |
| `--stdout-format {summary,html,text,json,none}` | Control CLI output. |
| `--rdap-base URL` | Point to an alternative RDAP endpoint or mirror. |
| `--timeout SEC` | Adjust RDAP lookup timeout (default 8 s). |

The JSON output matches `AnalysisResult.to_dict()` and can be fed into ticketing systems or SIEM pipelines.

---

## Template localization

Templates live under `src/spamreporter/templates`. Each language has:

- `report_<lang>.html.j2` – HTML email body with styling.
- `report_<lang>.txt.j2` – Plain text fallback.

Create your own files in `/etc/spammy/templates` (or similar) and reference them via `--template-dir`. The loader falls back to the bundled English templates if a localized version is missing.

---

## Integration examples

### Dovecot Sieve pipe (Pigeonhole `sieve_extprograms`)

1. Enable external programs in `90-sieve.conf`:

   ```conf
   plugin {
     sieve_plugins = sieve_extprograms
     sieve_pipe_bin_dir = /usr/local/libexec/sieve-pipes
   }
   ```

2. Place an executable wrapper, e.g. `/usr/local/libexec/sieve-pipes/spamreporter.sh`:

   ```bash
   #!/bin/sh
   /usr/local/bin/spamreporter --stdout-format none \
     --output-html /var/spamreports/${SIEVE_MAILBOX}.html \
     --output-json /var/spamreports/${SIEVE_MAILBOX}.json
   ```

3. In the user or global Sieve script:

   ```sieve
   if header :contains "X-Report-Spam" "yes" {
     pipe :copy "spamreporter.sh";
     stop;
   }
   ```

The full EML (including attachments) reaches the CLI via stdin. Dovecot exports `$SIEVE_SENDER`, `$SIEVE_RECIPIENT`, etc., should you need extra context inside the wrapper.

### Postfix pipe/content filter

- **Alias pipe** (`virtual_alias_maps`):

  ```
  spamreport@yourdomain.example  "|/usr/local/bin/spamreporter --stdout-format none --output-html /var/spamreports/latest.html"
  ```

- **Dedicated transport (`master.cf`)**:

  ```
  spamreport unix  -       n       n       -       -       pipe
    user=spam reporter
    argv=/usr/local/bin/spamreporter --stdout-format json --output-json /var/spamreports/${recipient}.json
  ```

Point suspicious messages (e.g. forwarded to `spamreport@`) at the transport.

---

## Optional daemon modes

While the CLI covers on-demand use, you can extend the toolchain into always-on services:

1. **Milter** – wrap `analyze_message` inside a Python `pymilter` or `aiosmtpd` service that listens on a Unix/TCP socket and is referenced by Postfix (`smtpd_milters = inet:localhost:12345`). The milter streams message data into memory/tempfiles, invokes the analysis, and can inject headers (`X-Local-Spamreport`) or enqueue HTML reports.

2. **rspamd external service** – configure `external_services.conf` or a Lua script to call a lightweight daemon whenever `X-Spam-Flag: YES`. The daemon exposes a simple HTTP/TCP endpoint (`POST /analyze` with the full EML), runs the same analysis module, and stores/dispatches the reports.

3. **Systemd worker** – run a background `spamreporter-worker` that consumes EML files dropped into a spool (e.g. by `pipe` or `rspamd`) and delivers HTML/JSON summaries via email or a webhook.

These modes require additional queueing, authentication, and error handling, but they reuse the same `spamreporter.analysis` and `ReportBuilder` components delivered here.

---

## Development

- Run unit tests (when added):

  ```bash
  python -m pytest
  ```

- Lint formatting/style via your preferred tools.

---

## Roadmap ideas

- SPF/DKIM/DMARC validation summary.
- Automatic email delivery of the HTML report to the reporter and the abuse contacts.
- Attachment of the original EML to outgoing reports (mimicking SpamCop).
- Optional REST API for UI dashboards.

Contributions and integrations are welcome.
