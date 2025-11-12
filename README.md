## Spammy – Local Spam Analysis & Abuse Reporter

Spammy is a self-hosted Python tool inspired by SpamCop. It ingests full EML/RFC822 messages, analyses Received headers to guess the originating system, performs RDAP/WHOIS lookups, and generates multilingual abuse reports (HTML, text, JSON). You can invoke it from Dovecot/Sieve, Postfix, rspamd, or manually via CLI.

### Highlights

- ✅ **EML ingestion** – reads stdin or files, automatically unwraps `message/rfc822` attachments.
- 🌐 **Modern RDAP lookups** – uses `ipwhois`/`rdap.org` to fetch network owners, registrar info, and abuse contacts.
- ✉️ **Abuse contact discovery** – extracts abuse/postmaster/security addresses from RDAP entities and objects.
- 🗣️ **Multilingual templates** – bundled HTML & TXT templates for English, German, French, and Spanish with automatic language selection based on RDAP country (override via `--language`).
- 📤 **User-ready reports** – writes responsive HTML, JSON, or plaintext summaries and prints a concise CLI summary.
- 🔐 **SPF/DKIM/DMARC summary** – parses Authentication-Results headers and highlights failing policies directly in the report.
- 🔌 **Mailserver integration** – designed for Dovecot `sieve_extprograms`, Postfix pipes/content filters, or rspamd external services. Optional daemon/milter modes are documented for advanced setups.

---

## Dokumentation

- [Installation](doc/installation.md) – Schritte für pipx, virtuelle Umgebungen
  und Benutzer-Installs.
- [Database Setup](doc/database_setup.md) – Beispiele für das Anlegen von
  Datenbanken und Benutzern (PostgreSQL, MariaDB/MySQL, SQL Server) inkl.
  UTF‑8-Hinweisen.
- [Schéma SQL](doc/database_schema.sql) – Referenz-Tabellen (messages, analyses,
  abuse_contacts) inklusive Indexvorschlägen für spätere Auswertungen.

## Konfiguration

Spammy lädt Einstellungen aus `config/spammy.toml` (im Repo oder Deployment),
aus `/etc/spammy/spammy.toml` oder aus dem Pfad, den du via
`SPAMMY_CONFIG=/path/datei.toml` bzw. `--config` an das CLI übergibst. Eine
Beispieldatei findest du unter `config/spammy.example.toml`:

```toml
[rdap]
base_url = "https://rdap.org"
timeout = 8

[reporting]
template_dir = "/etc/spammy/templates"

[storage]
backend = "sqlite"
# database = "var/data/spammy.sqlite3"
# driver = "postgresql"
# host = "localhost"
# port = 5432
# user = "spammy"
# password = "secret"
# database = "spammy"
# odbc_dsn = "Driver=ODBC Driver 18 for SQL Server;Server=tcp:sql.example,1433;UID=spammy;PWD=secret"

[cache]
url = "memcached://localhost:11211"
```

Kopiere die Datei an einen deiner gewünschten Orte und passe Werte wie
`reporting.template_dir`, das gewünschte Storage-Backend (`backend = "sqlite"`
für lokale Tests oder `"memory"`/`"none"`), sowie optionale DB-Credentials
(`driver`, `host`, `user`, `password`, `database`, `odbc_dsn`) an – das CLI
übernimmt sie automatisch, solange entsprechende Flags nicht überschrieben
werden.

---

## Usage

Basic analysis from a file:

```bash
spammy --eml samples/spam.eml \
  --output-html /tmp/report.html \
  --output-json /tmp/report.json \
  --output-text /tmp/report.txt
```

Reading from stdin (ideal for Dovecot/Postfix):

```bash
cat spam.eml | spammy --stdout-format text
```

Important flags:

| Flag | Description |
| --- | --- |
| `--language {en,de,fr,es}` | Force a specific template language. |
| `--template-dir /path` | Use custom Jinja2 templates instead of the bundled ones. |
| `--output-html/--output-json/--output-text` | Persist rendered reports. |
| `--stdout-format {summary,html,text,json,none}` | Control CLI output. |
| `--auto-stdout` | Skip the confirmation prompt before printing HTML/TXT/JSON templates to stdout. |
| `--rdap-base URL` | Point to an alternative RDAP endpoint or mirror. |
| `--timeout SEC` | Adjust RDAP lookup timeout (default 8 s). |

The JSON output matches `AnalysisResult.to_dict()` and can be fed into ticketing systems or SIEM pipelines.

---

## Template localization

Templates live under `src/spammy/templates`. Each language has:

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

2. Place an executable wrapper, e.g. `/home/spammy/bin/spammy-sieve.sh`
   (verweise dort direkt auf `~spammy/.local/bin/spammy` aus der pipx-Installation
   oder auf ein dediziertes venv):

  ```bash
  #!/bin/sh
  ~spammy/.local/bin/spammy --stdout-format none \
     --output-html /var/spamreports/${SIEVE_MAILBOX}.html \
     --output-json /var/spamreports/${SIEVE_MAILBOX}.json
  ```

3. In the user or global Sieve script:

```sieve
if header :contains "X-Report-Spam" "yes" {
  pipe :copy "spammy-sieve.sh";
  stop;
}
```

The full EML (including attachments) reaches the CLI via stdin. Dovecot exports `$SIEVE_SENDER`, `$SIEVE_RECIPIENT`, etc., should you need extra context inside the wrapper.

### Postfix pipe/content filter

- **Alias pipe** (`virtual_alias_maps`):

  ```
  spammy@yourdomain.example  "|~spammy/.local/bin/spammy --stdout-format none --output-html /home/spammy/reports/latest.html"
  ```

- **Dedicated transport (`master.cf`)**:

  ```
  spammy unix  -       n       n       -       -       pipe
    user=spammy
    argv=~spammy/.local/bin/spammy --stdout-format json --output-json /home/spammy/reports/${recipient}.json
  ```

Point suspicious messages (e.g. forwarded to `spammy@`) at the transport.

---

## Optional daemon modes

While the CLI covers on-demand use, you can extend the toolchain into always-on services:

1. **Milter** – wrap `analyze_message` inside a Python `pymilter` or `aiosmtpd` service that listens on a Unix/TCP socket and is referenced by Postfix (`smtpd_milters = inet:localhost:12345`). The milter streams message data into memory/tempfiles, invokes the analysis, and can inject headers (`X-Local-Spamreport`) or enqueue HTML reports.

2. **rspamd external service** – configure `external_services.conf` or a Lua script to call a lightweight daemon whenever `X-Spam-Flag: YES`. The daemon exposes a simple HTTP/TCP endpoint (`POST /analyze` with the full EML), runs the same analysis module, and stores/dispatches the reports.

3. **Systemd worker** – run a background `spammy-worker` that consumes EML files dropped into a spool (e.g. by `pipe` or `rspamd`) and delivers HTML/JSON summaries via email or a webhook.

These modes require additional queueing, authentication, and error handling, but they reuse the same `spammy.analysis` and `ReportBuilder` components delivered here.

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
