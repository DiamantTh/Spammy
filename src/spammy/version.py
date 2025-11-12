from __future__ import annotations

import os
from datetime import datetime, timezone


def _timestamp() -> str:
    override = os.environ.get("SPAMMY_BUILD_TS") or os.environ.get("SOURCE_DATE_EPOCH")
    if override:
        try:
            return str(int(override))
        except ValueError:
            pass
    return str(int(datetime.now(timezone.utc).timestamp()))


__version__ = _timestamp()

