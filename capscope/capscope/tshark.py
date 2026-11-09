"""TShark discovery and safe invocation.

Every call uses an argument list (never a shell), ``-n`` (no name
resolution, so no DNS lookups leave the machine) and captures stderr in a
background thread so a chatty stderr can never dead-lock a pipe.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import threading
from functools import lru_cache
from pathlib import Path

from .config import settings

_NOISE = re.compile(r"^(Running as user|.*This could be dangerous)")
CREATE_NO_WINDOW = 0x08000000 if sys.platform == "win32" else 0


class TSharkNotFound(RuntimeError):
    pass


def _candidates() -> list[str]:
    out = []
    if settings.tshark:
        out.append(settings.tshark)
    w = shutil.which("tshark")
    if w:
        out.append(w)
    if sys.platform == "win32":
        for env in ("ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"):
            base = os.environ.get(env)
            if base:
                out.append(str(Path(base) / "Wireshark" / "tshark.exe"))
    else:
        out += ["/usr/bin/tshark", "/usr/local/bin/tshark", "/opt/homebrew/bin/tshark"]
    return out


@lru_cache(maxsize=1)
def tshark_path() -> str:
    for c in _candidates():
        if c and Path(c).is_file():
            return str(Path(c))
    raise TSharkNotFound(
        "A TShark nem található. Telepítsd a Wiresharkot (TShark komponenssel), vagy add meg az útvonalát a "
        "CAPSCOPE_TSHARK környezeti változóban (pl. C:\\Program Files\\Wireshark\\tshark.exe).")


def popen(args: list[str], **kw) -> subprocess.Popen:
    """Start tshark with an argument list. stdout is a text pipe."""
    cmd = [tshark_path(), *args]
    return subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            shell=False, creationflags=CREATE_NO_WINDOW, **kw)


class StderrCollector(threading.Thread):
    def __init__(self, stream, limit: int = 64_000):
        super().__init__(daemon=True)
        self.stream, self.limit, self.buf = stream, limit, []
        self.size = 0
        self.start()

    def run(self) -> None:
        for raw in iter(self.stream.readline, b""):
            line = raw.decode("utf-8", "replace").rstrip()
            if not line or _NOISE.match(line):
                continue
            if self.size < self.limit:
                self.buf.append(line)
                self.size += len(line)

    def text(self) -> str:
        self.join(timeout=2)
        return "\n".join(self.buf)


def run(args: list[str], timeout: float | None = None, binary: bool = False) -> tuple[int, str | bytes, str]:
    """Run tshark to completion. Returns (returncode, stdout, filtered stderr)."""
    p = popen(args)
    try:
        out, err = p.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        p.kill()
        p.communicate()
        raise
    err_txt = "\n".join(l for l in err.decode("utf-8", "replace").splitlines() if l.strip() and not _NOISE.match(l))
    return p.returncode, (out if binary else out.decode("utf-8", "replace")), err_txt


@lru_cache(maxsize=1)
def version() -> str:
    try:
        rc, out, _ = run(["--version"], timeout=30)
    except (TSharkNotFound, OSError, subprocess.TimeoutExpired):
        return ""
    first = out.splitlines()[0] if out else ""
    m = re.search(r"TShark \(Wireshark\) ([0-9][^\s]*)", first)
    return m.group(1) if m else first.strip()


@lru_cache(maxsize=1)
def known_fields() -> frozenset[str]:
    """All display-filter field names of the installed TShark (cached per version on disk)."""
    ver = version() or "unknown"
    cache = settings.data_dir / f"fields-{re.sub(r'[^0-9A-Za-z.]', '_', ver)}.txt"
    if cache.is_file():
        return frozenset(cache.read_text("utf-8").split())
    rc, out, _ = run(["-G", "fields"], timeout=180)
    names = set()
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) >= 3 and parts[0] in ("F", "P"):
            names.add(parts[2])
    try:
        settings.ensure_dirs()
        cache.write_text("\n".join(sorted(names)), "utf-8")
    except OSError:
        pass
    return frozenset(names)


def column_field(kind: str) -> str:
    """Column pseudo-field name differs between TShark versions (4.2+: lower case)."""
    fields = known_fields()
    lower = {"info": "_ws.col.info", "protocol": "_ws.col.protocol"}[kind]
    if lower in fields:
        return lower
    return {"info": "_ws.col.Info", "protocol": "_ws.col.Protocol"}[kind]


def empty_pcap() -> Path:
    settings.ensure_dirs()
    p = settings.data_dir / "empty.pcap"
    if not p.is_file():
        import struct
        p.write_bytes(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    return p


_FILTER_HINTS = [
    (re.compile(r"Constant expression is invalid", re.I),
     "Valószínűleg elírt vagy ismeretlen mezőnév: a TShark nem mezőként, hanem konstansként értelmezte. "
     "Ellenőrizd a mező nevét (pl. 'dns.qry.name')."),
    (re.compile(r"neither a field nor a protocol name", re.I),
     "Ismeretlen mező- vagy protokollnév. Ellenőrizd az írásmódot (pl. 'dns.qry.name', 'gtpv2.cause')."),
    (re.compile(r"Unexpected end of filter|syntax error|Unexpected", re.I),
     "Szintaktikai hiba. Ellenőrizd a zárójeleket, az operátorokat (==, !=, &&, ||, contains, matches) és az idézőjeleket."),
    (re.compile(r"not a valid|isn't a valid|invalid", re.I),
     "A megadott érték nem illik a mező típusához (pl. IP-cím, szám vagy szöveg)."),
]


def validate_filter(expr: str) -> tuple[bool, str, str]:
    """Compile a display filter against an empty capture.

    Returns (ok, hungarian_message, raw_tshark_message)."""
    expr = (expr or "").strip()
    if not expr:
        return True, "", ""
    if len(expr) > 8000 or "\x00" in expr:
        return False, "A szűrőkifejezés túl hosszú vagy érvénytelen karaktert tartalmaz.", ""
    try:
        rc, _, err = run(["-n", "-r", str(empty_pcap()), "-Y", expr], timeout=60)
    except subprocess.TimeoutExpired:
        return False, "A szűrő ellenőrzése időtúllépés miatt megszakadt.", ""
    if rc == 0:
        return True, "", ""
    raw = err.replace("tshark: ", "").strip()
    hint = next((h for rx, h in _FILTER_HINTS if rx.search(raw)), "A TShark nem tudta értelmezni a szűrőt.")
    return False, f"Érvénytelen display filter. {hint}", raw
