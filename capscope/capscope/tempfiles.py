"""Controlled temporary files: always under <data>/tmp, removed on exit of the
``with`` block (also on exceptions/cancellation), at interpreter exit, and
stale leftovers are swept at start-up."""
from __future__ import annotations

import atexit
import shutil
import tempfile
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from .config import settings

_live: set[str] = set()
_lock = threading.Lock()


@contextmanager
def temp_dir(prefix: str) -> Iterator[str]:
    settings.ensure_dirs()
    d = tempfile.mkdtemp(prefix=f"{prefix}-", dir=settings.tmp_dir)
    with _lock:
        _live.add(d)
    try:
        yield d
    finally:
        shutil.rmtree(d, ignore_errors=True)
        with _lock:
            _live.discard(d)


def live_dirs() -> list[str]:
    with _lock:
        return sorted(_live)


@atexit.register
def _cleanup() -> None:
    for d in list(_live):
        shutil.rmtree(d, ignore_errors=True)
    # partially written exports
    try:
        for p in Path(settings.exports_dir).glob("*.part"):
            p.unlink(missing_ok=True)
    except OSError:
        pass
