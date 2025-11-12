# Installation Guide

Die folgenden Schritte beschreiben, wie du Spammy auf einem Host installierst.

## 1. pipx (empfohlen)

[pipx](https://pipx.pypa.io/) installiert Spammy in ein isoliertes Virtualenv und
legt eine ausführbare Datei unter `~/.local/bin/spammy` ab – ideal für Systeme mit
[Externally Managed Environments](https://packaging.python.org/en/latest/specifications/externally-managed-environments/) (ehemals PEP 668).

```bash
# sicherstellen, dass ~/.local/bin im PATH liegt
pipx ensurepath

# Installation aus dem Git-Checkout
pipx install --python python3 --editable .

# spätere Updates
pipx upgrade spammy
```

## 2. Virtuelle Umgebung für Entwicklung

Für lokale Entwicklung oder Tests kannst du ein klassisches venv verwenden:

```bash
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install --upgrade pip
python3 -m pip install -e .
```

Das CLI wird nach Änderungen sofort aktualisiert, solange du dich im selben
Workspace befindest.

## 3. Benutzerinstallation ohne venv (optional)

Wenn du außerhalb eines venv installieren möchtest, deaktiviere deine virtuelle
Umgebung und führe

```bash
python3 -m pip install --user -e .
```

aus. Achte darauf, dass `~/.local/bin` in deinem `PATH` liegt. Auf
Externally-Managed-Systemen solltest du diese Variante nur nutzen, wenn keine
Distributionseigene Sperre (z.B. Debian/Ubuntu) greift; ansonsten bei pipx
bleiben.
