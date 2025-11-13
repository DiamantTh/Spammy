from __future__ import annotations

import os
from importlib import resources


def _load_version() -> str:
    override = os.environ.get("SPAMMY_BUILD_TS") or os.environ.get("SOURCE_DATE_EPOCH")
    if override:
        try:
            return str(int(override))
        except ValueError:
            pass
    try:
        data = (
            resources.files("spammy")
            .joinpath("_version.txt")
            .read_text(encoding="utf-8")
            .strip()
        )
        if data:
            return data
    except FileNotFoundError:
        pass
    return "0.0.dev0"


__version__ = _load_version()
