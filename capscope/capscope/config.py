"""Runtime configuration (environment variables, defaults, limits)."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


@dataclass
class Settings:
    data_dir: Path = field(default_factory=lambda: Path(os.environ.get(
        "CAPSCOPE_DATA", Path.home() / ".capscope")).resolve())
    host: str = "127.0.0.1"
    port: int = field(default_factory=lambda: _env_int("CAPSCOPE_PORT", 8765))
    tshark: str | None = field(default_factory=lambda: os.environ.get("CAPSCOPE_TSHARK") or None)
    # Limits (all are surfaced in the UI when reached)
    index_batch: int = 5000
    filter_timeout_s: int = field(default_factory=lambda: _env_int("CAPSCOPE_FILTER_TIMEOUT", 600))
    filter_max_hits: int = field(default_factory=lambda: _env_int("CAPSCOPE_FILTER_MAX_HITS", 5_000_000))
    detail_timeout_s: int = field(default_factory=lambda: _env_int("CAPSCOPE_DETAIL_TIMEOUT", 120))
    follow_timeout_s: int = field(default_factory=lambda: _env_int("CAPSCOPE_FOLLOW_TIMEOUT", 300))
    follow_max_bytes: int = 2_000_000
    export_max_frames: int = field(default_factory=lambda: _env_int("CAPSCOPE_EXPORT_MAX", 2_000_000))
    max_flows_in_memory: int = 200_000
    # Transaction windows (seconds)
    dns_timeout_s: float = 5.0
    gtp_timeout_s: float = 30.0
    gtpu_grace_s: float = 2.0
    auth_token: str | None = None  # set at start-up
    allowed_ext: tuple = (".pcap", ".pcapng", ".cap", ".ntar", ".pcap.gz", ".pcapng.gz")

    @property
    def captures_dir(self) -> Path:
        return self.data_dir / "captures"

    @property
    def exports_dir(self) -> Path:
        return self.data_dir / "exports"

    @property
    def tmp_dir(self) -> Path:
        return self.data_dir / "tmp"

    @property
    def catalog_path(self) -> Path:
        return self.data_dir / "catalog.sqlite"

    def ensure_dirs(self) -> None:
        for p in (self.data_dir, self.captures_dir, self.exports_dir, self.tmp_dir):
            p.mkdir(parents=True, exist_ok=True)


settings = Settings()
