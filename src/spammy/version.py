from __future__ import annotations

import os
from pathlib import Path


def _load_version() -> str:
    override = os.environ.get("SPAMMY_BUILD_TS") or os.environ.get("SOURCE_DATE_EPOCH")
    if override:
        try:
            return str(int(override))
        except ValueError:
            pass
    version_file = Path(__file__).with_name("_version.txt")
    if version_file.is_file():
        data = version_file.read_text(encoding="utf-8").strip()
        if data:
            return data
    return "0.0.dev0"


__version__ = _load_version()
