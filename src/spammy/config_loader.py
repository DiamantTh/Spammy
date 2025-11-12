from __future__ import annotations

import os
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Iterable, Optional

try:  # Python 3.11+
    import tomllib  # type: ignore[attr-defined]
except ModuleNotFoundError:  # pragma: no cover - fallback for 3.10
    import tomli as tomllib  # type: ignore[import-not-found]

CONFIG_ENV_VAR = "SPAMMY_CONFIG"
DEFAULT_FILE_NAME = "spammy.toml"


@dataclass(frozen=True)
class RDAPSettings:
    base_url: str = "https://rdap.org"
    timeout: int = 8


@dataclass(frozen=True)
class ReportingSettings:
    template_dir: Optional[Path] = None


@dataclass(frozen=True)
class StorageSettings:
    backend: str = "sqlite"
    driver: Optional[str] = None
    host: Optional[str] = None
    port: Optional[int] = None
    user: Optional[str] = None
    password: Optional[str] = None
    database: Optional[str] = None
    odbc_dsn: Optional[str] = None


@dataclass(frozen=True)
class CacheSettings:
    url: Optional[str] = None


@dataclass(frozen=True)
class SpammyConfig:
    rdap: RDAPSettings = field(default_factory=RDAPSettings)
    reporting: ReportingSettings = field(default_factory=ReportingSettings)
    storage: StorageSettings = field(default_factory=StorageSettings)
    cache: CacheSettings = field(default_factory=CacheSettings)
    source: Optional[Path] = None


def candidate_paths(explicit: Optional[Path] = None) -> Iterable[Path]:
    """Return config paths to probe in order of priority."""
    tried: list[Path] = []
    if explicit:
        tried.append(explicit.expanduser())
    env_path = os.environ.get(CONFIG_ENV_VAR)
    if env_path:
        tried.append(Path(env_path).expanduser())
    tried.append(Path.cwd() / "config" / DEFAULT_FILE_NAME)
    tried.append(Path("/etc/spammy") / DEFAULT_FILE_NAME)
    seen: set[Path] = set()
    for path in tried:
        if path not in seen:
            seen.add(path)
            yield path


def load_config(path: Optional[Path] = None) -> SpammyConfig:
    """Load config data from TOML file(s), falling back to defaults."""
    for candidate in candidate_paths(path):
        if candidate.is_file():
            data = _parse_toml(candidate)
            return SpammyConfig(
                rdap=_merge_dataclass(RDAPSettings(), data.get("rdap", {})),
                reporting=_merge_dataclass(
                    ReportingSettings(), data.get("reporting", {})
                ),
                storage=_merge_dataclass(StorageSettings(), data.get("storage", {})),
                cache=_merge_dataclass(CacheSettings(), data.get("cache", {})),
                source=candidate,
            )
    return SpammyConfig()


def _parse_toml(path: Path) -> dict[str, Any]:
    with path.open("rb") as handle:
        return tomllib.load(handle)


def _merge_dataclass(instance, values: dict[str, Any]):
    if not values:
        return instance
    processed = {}
    for key, value in values.items():
        if isinstance(getattr(instance, key, None), Path) and isinstance(value, str):
            processed[key] = Path(value).expanduser()
        else:
            processed[key] = value
    return replace(instance, **processed)
