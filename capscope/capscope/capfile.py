"""Minimal pcap / pcapng block walker and lossless pcapng exporter.

TShark does the dissection. This module only walks record/block headers so
we know, for every frame number, where its block starts in the file, which
section and interface it belongs to and its raw timestamp. That gives:

* lossless provenance (section, interface, original frame number),
* interface metadata incl. ISB drop counters (or "no data"),
* detection of embedded Decryption Secrets Blocks (DSB),
* fast single-frame access (hex view) and lossless export that copies the
  original bytes and adds an ``opt_comment`` carrying the original reference.
"""
from __future__ import annotations

import gzip
import hashlib
import struct
from dataclasses import dataclass, field
from typing import BinaryIO, Iterator

PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", 6), b"\xa1\xb2\xc3\xd4": (">", 6),
    b"\x4d\x3c\xb2\xa1": ("<", 9), b"\xa1\xb2\x3c\x4d": (">", 9),
}
PCAPNG_SHB = 0x0A0D0D0A
BT_IDB, BT_PB, BT_SPB, BT_NRB, BT_ISB, BT_EPB, BT_DSB = 1, 2, 3, 4, 5, 6, 0x0A


class CaptureFormatError(ValueError):
    pass


@dataclass
class PacketRef:
    frame_no: int
    offset: int          # file offset of the record/block
    section: int | None  # 1-based pcapng section (None for classic pcap)
    iface: int
    ts_units: int | None
    tsresol: int         # decimal exponent (6 = us, 9 = ns); negative = binary 2^-n
    caplen: int
    origlen: int


@dataclass
class CaptureInfo:
    format: str = "unknown"
    compressed: bool = False
    sections: list[dict] = field(default_factory=list)
    interfaces: list[dict] = field(default_factory=list)  # each: section, iface, name, linktype, ...
    dsb: list[dict] = field(default_factory=list)
    truncated: bool = False
    truncation_note: str = ""
    packets: int = 0
    bytes_total: int = 0
    sha256: str = ""
    endian: str = "<"
    pcap_tsresol: int = 6

    @property
    def random_access(self) -> bool:
        return not self.compressed and self.format in ("pcap", "pcapng")


def sniff_format(path: str) -> str:
    with open(path, "rb") as f:
        head = f.read(4)
    if head[:2] == b"\x1f\x8b":
        with gzip.open(path, "rb") as g:
            head = g.read(4)
        return ("gz:" + _fmt_of(head)) if _fmt_of(head) else ""
    return _fmt_of(head)


def _fmt_of(head: bytes) -> str:
    if head in PCAP_MAGICS:
        return "pcap"
    if len(head) == 4 and struct.unpack("<I", head)[0] == PCAPNG_SHB:
        return "pcapng"
    return ""


def _parse_options(buf: bytes, e: str) -> list[tuple[int, bytes]]:
    out, i = [], 0
    while i + 4 <= len(buf):
        code, ln = struct.unpack_from(e + "HH", buf, i)
        i += 4
        if code == 0:
            break
        out.append((code, buf[i:i + ln]))
        i += ln + ((-ln) % 4)
    return out


def _tsresol(v: bytes) -> int:
    b = v[0] if v else 6
    return -(b & 0x7F) if b & 0x80 else b


def units_to_ns(units: int, tsresol: int) -> int:
    if tsresol >= 0:
        return units * 10 ** (9 - tsresol) if tsresol <= 9 else units // 10 ** (tsresol - 9)
    return (units * 1_000_000_000) >> (-tsresol)


class _Reader:
    def __init__(self, f: BinaryIO, hasher):
        self.f, self.h, self.pos = f, hasher, 0

    def read(self, n: int) -> bytes:
        b = self.f.read(n)
        if self.h is not None:
            self.h.update(b)
        self.pos += len(b)
        return b


class CaptureWalker:
    """Sequential walker. Iterate ``packets()``; ``info`` is complete afterwards."""

    def __init__(self, path: str, hash_file: bool = True):
        self.path = path
        fmt = sniff_format(path)
        if not fmt:
            raise CaptureFormatError("Nem pcap/pcapng fájl (ismeretlen magic).")
        self.info = CaptureInfo(format=fmt.replace("gz:", ""), compressed=fmt.startswith("gz:"))
        self._hash = hashlib.sha256() if hash_file else None
        self.bytes_read = 0

    def _open(self) -> BinaryIO:
        return gzip.open(self.path, "rb") if self.info.compressed else open(self.path, "rb", buffering=1 << 20)

    def packets(self) -> Iterator[PacketRef]:
        with self._open() as f:
            r = _Reader(f, self._hash)
            try:
                if self.info.format == "pcap":
                    yield from self._pcap(r)
                else:
                    yield from self._pcapng(r)
            finally:
                self.bytes_read = r.pos
                self.info.bytes_total = r.pos
                if self._hash is not None:
                    self.info.sha256 = self._hash.hexdigest()

    # -- classic pcap ---------------------------------------------------------
    def _pcap(self, r: _Reader) -> Iterator[PacketRef]:
        hdr = r.read(24)
        e, res = PCAP_MAGICS[hdr[:4]]
        _, _, _, _, snaplen, linktype = struct.unpack(e + "HHiIII", hdr[4:24])
        self.info.endian, self.info.pcap_tsresol = e, res
        self.info.interfaces.append({"section": None, "iface": 0, "name": None, "description": None,
                                     "linktype": linktype & 0xFFFF, "snaplen": snaplen, "tsresol": res,
                                     "ifdrop": None, "ifrecv": None, "osdrop": None})
        n = 0
        while True:
            off = r.pos
            rh = r.read(16)
            if not rh:
                break
            if len(rh) < 16:
                self._trunc("A fájl egy rekordfejléc közepén ér véget.")
                break
            sec, frac, incl, orig = struct.unpack(e + "IIII", rh)
            body = r.read(incl)
            if len(body) < incl:
                self._trunc("A fájl egy csomag közepén ér véget (az utolsó csomag csonka).")
                break
            n += 1
            self.info.packets = n
            yield PacketRef(n, off, None, 0, sec * 10 ** res + frac, res, incl, orig)

    # -- pcapng ------------------------------------------------------------------
    def _pcapng(self, r: _Reader) -> Iterator[PacketRef]:
        n, section, e = 0, 0, "<"
        ifaces: list[dict] = []
        while True:
            off = r.pos
            head = r.read(8)
            if not head:
                break
            if len(head) < 8:
                self._trunc("A fájl egy blokkfejléc közepén ér véget.")
                break
            btype_le = struct.unpack("<I", head[:4])[0]
            if btype_le == PCAPNG_SHB:
                bom = r.read(4)
                if len(bom) < 4:
                    self._trunc("Csonka Section Header Block.")
                    break
                e = "<" if bom == b"\x4d\x3c\x2b\x1a" else ">"
                blen = struct.unpack(e + "I", head[4:8])[0]
                rest = r.read(blen - 12)
                if len(rest) < blen - 12 or blen < 28:
                    self._trunc("Csonka Section Header Block.")
                    break
                section += 1
                ifaces = []
                opts = dict((c, v) for c, v in _parse_options(rest[12:-4], e))
                self.info.sections.append({
                    "section": section, "offset": off, "endian": e,
                    "comment": opts.get(1, b"").decode("utf-8", "replace") or None,
                    "hardware": opts.get(2, b"").decode("utf-8", "replace") or None,
                    "os": opts.get(3, b"").decode("utf-8", "replace") or None,
                    "userappl": opts.get(4, b"").decode("utf-8", "replace") or None,
                })
                if section == 1:
                    self.info.endian = e
                continue
            if section == 0:
                raise CaptureFormatError("Hiányzó Section Header Block.")
            btype, blen = struct.unpack(e + "II", head)
            if blen < 12 or blen % 4:
                self._trunc(f"Érvénytelen blokkhossz ({blen}) a {off}. bájtnál; a feldolgozás itt megáll.")
                break
            body = r.read(blen - 8)
            if len(body) < blen - 8:
                self._trunc("A fájl egy blokk közepén ér véget (az utolsó csomag csonka).")
                break
            body = body[:-4]
            if btype == BT_IDB:
                linktype, _, snaplen = struct.unpack_from(e + "HHI", body, 0)
                opts = _parse_options(body[8:], e)
                d = dict(opts)
                ifc = {"section": section, "iface": len(ifaces), "linktype": linktype, "snaplen": snaplen,
                       "name": d.get(2, b"").decode("utf-8", "replace") or None,
                       "description": d.get(3, b"").decode("utf-8", "replace") or None,
                       "tsresol": _tsresol(d[9]) if 9 in d else 6,
                       "tsoffset": struct.unpack(e + "q", d[14])[0] if 14 in d and len(d[14]) == 8 else 0,
                       "filter": d.get(11, b"")[1:].decode("utf-8", "replace") or None,
                       "os": d.get(12, b"").decode("utf-8", "replace") or None,
                       "ifdrop": None, "ifrecv": None, "osdrop": None, "offset": off}
                ifaces.append(ifc)
                self.info.interfaces.append(ifc)
            elif btype in (BT_EPB, BT_PB):
                if btype == BT_EPB:
                    iface, th, tl, caplen, orig = struct.unpack_from(e + "IIIII", body, 0)
                else:
                    iface, _drops, th, tl, caplen, orig = struct.unpack_from(e + "HHIIII", body, 0)
                res = ifaces[iface]["tsresol"] if iface < len(ifaces) else 6
                n += 1
                self.info.packets = n
                yield PacketRef(n, off, section, iface, (th << 32) | tl, res, caplen, orig)
            elif btype == BT_SPB:
                orig = struct.unpack_from(e + "I", body, 0)[0]
                snap = ifaces[0]["snaplen"] if ifaces else 0
                caplen = min(orig, snap) if snap else orig
                n += 1
                self.info.packets = n
                yield PacketRef(n, off, section, 0, None, 6, caplen, orig)
            elif btype == BT_ISB:
                iface = struct.unpack_from(e + "I", body, 0)[0]
                d = dict(_parse_options(body[12:], e))
                if iface < len(ifaces):
                    for code, key in ((4, "ifrecv"), (5, "ifdrop"), (7, "osdrop")):
                        if code in d and len(d[code]) == 8:
                            ifaces[iface][key] = struct.unpack(e + "Q", d[code])[0]
            elif btype == BT_DSB:
                stype, slen = struct.unpack_from(e + "II", body, 0)
                self.info.dsb.append({"section": section, "offset": off, "type": f"0x{stype:08x}", "length": slen,
                                      "kind": {0x544C534B: "TLS key log", 0x57474B4C: "WireGuard key log",
                                               0x5A4E574B: "ZigBee NWK key", 0x5A415053: "ZigBee APS key",
                                               0x534B4559: "SSH key log"}.get(stype, "ismeretlen")})

    def _trunc(self, note: str) -> None:
        self.info.truncated = True
        self.info.truncation_note = note


# ---------------------------------------------------------------------------
# Random access
# ---------------------------------------------------------------------------

def read_frame_bytes(path: str, offset: int, fmt: str, endian: str) -> bytes:
    """Return the captured packet bytes of the record/block at ``offset``."""
    with open(path, "rb") as f:
        f.seek(offset)
        if fmt == "pcap":
            sec, frac, incl, orig = struct.unpack(endian + "IIII", f.read(16))
            return f.read(incl)
        btype, blen = struct.unpack(endian + "II", f.read(8))
        body = f.read(blen - 12)
        if btype == BT_EPB:
            caplen = struct.unpack_from(endian + "I", body, 12)[0]
            return body[20:20 + caplen]
        if btype == BT_PB:
            caplen = struct.unpack_from(endian + "I", body, 12)[0]
            return body[20:20 + caplen]
        if btype == BT_SPB:
            orig = struct.unpack_from(endian + "I", body, 0)[0]
            return body[4:4 + orig]
        raise CaptureFormatError("A megadott offseten nincs csomagblokk.")


# ---------------------------------------------------------------------------
# Lossless pcapng export with provenance comments
# ---------------------------------------------------------------------------

def _opt(e: str, code: int, value: bytes) -> bytes:
    return struct.pack(e + "HH", code, len(value)) + value + b"\x00" * ((-len(value)) % 4)


def _blk(e: str, btype: int, body: bytes) -> bytes:
    total = 12 + len(body)
    return struct.pack(e + "II", btype, total) + body + struct.pack(e + "I", total)


def _shb(e: str, comment: str) -> bytes:
    opts = _opt(e, 1, comment.encode()) + _opt(e, 4, b"CapScope export") + _opt(e, 0, b"")
    return _blk(e, PCAPNG_SHB, struct.pack(e + "IHHq", 0x1A2B3C4D, 1, 0, -1) + opts)


def export_pcapng(src: str, info: dict, refs: list[dict], out_path: str, *, source_label: str,
                  include_secrets: bool = False, progress=None, cancelled=None) -> dict:
    """Write selected frames (sorted by frame number) to a new pcapng.

    ``info``: stored capture metadata (format, endian, sections, interfaces, dsb).
    ``refs``: dicts with frame_no, offset, section, iface.
    Each exported packet gets an ``opt_comment``: ``capscope-ref file=<label> sha256=<..> frame=<n> ...``.
    Existing packet options/comments are preserved."""
    fmt = info["format"]
    sha = (info.get("sha256") or "")[:16]
    sections = {s["section"]: s for s in info.get("sections", [])}
    ifaces_by_section: dict = {}
    for ifc in info.get("interfaces", []):
        ifaces_by_section.setdefault(ifc["section"], []).append(ifc)
    written, secrets_written = 0, 0
    with open(src, "rb") as fin, open(out_path, "wb") as out:
        cur_section = object()
        e = "<"
        for i, ref in enumerate(refs):
            if cancelled and cancelled():
                raise InterruptedError
            sec = ref.get("section")
            if sec != cur_section:
                cur_section = sec
                if fmt == "pcap":
                    e = "<"
                    out.write(_shb(e, f"CapScope export of {source_label} (sha256 {sha}). Packet comments carry "
                                      f"the original frame numbers."))
                    ifc = info["interfaces"][0]
                    opts = _opt(e, 9, bytes([info.get("pcap_tsresol", 6)])) + _opt(e, 0, b"")
                    out.write(_blk(e, BT_IDB, struct.pack(e + "HHI", ifc["linktype"], 0, ifc["snaplen"]) + opts))
                else:
                    e = sections[sec]["endian"]
                    out.write(_shb(e, f"CapScope export of {source_label} (sha256 {sha}), source section {sec}. "
                                      f"Interface ids are kept; packet comments carry the original frame numbers."))
                    for ifc in ifaces_by_section.get(sec, []):  # copy all IDBs: interface ids stay stable
                        fin.seek(ifc["offset"])
                        bt, bl = struct.unpack(e + "II", fin.read(8))
                        out.write(struct.pack(e + "II", bt, bl) + fin.read(bl - 8))
                    if include_secrets:
                        for d in info.get("dsb", []):
                            if d["section"] == sec:
                                fin.seek(d["offset"])
                                bt, bl = struct.unpack(e + "II", fin.read(8))
                                out.write(struct.pack(e + "II", bt, bl) + fin.read(bl - 8))
                                secrets_written += 1
            comment = (f"capscope-ref file={source_label} sha256={sha} frame={ref['frame_no']}"
                       + (f" section={sec}" if sec is not None else "") + f" iface={ref.get('iface', 0)}")
            fin.seek(ref["offset"])
            if fmt == "pcap":
                pe = info["endian"]
                sec_, frac, incl, orig = struct.unpack(pe + "IIII", fin.read(16))
                data = fin.read(incl)
                units = sec_ * 10 ** info.get("pcap_tsresol", 6) + frac
                body = struct.pack(e + "IIIII", 0, units >> 32, units & 0xFFFFFFFF, incl, orig)
                body += data + b"\x00" * ((-incl) % 4) + _opt(e, 1, comment.encode()) + _opt(e, 0, b"")
                out.write(_blk(e, BT_EPB, body))
            else:
                bt, bl = struct.unpack(e + "II", fin.read(8))
                body = fin.read(bl - 12)
                fin.read(4)
                if bt == BT_EPB or bt == BT_PB:
                    if bt == BT_EPB:
                        iface, th, tl, caplen, orig = struct.unpack_from(e + "IIIII", body, 0)
                    else:
                        iface, _d, th, tl, caplen, orig = struct.unpack_from(e + "HHIIII", body, 0)
                    data_end = 20 + caplen + ((-caplen) % 4)
                    old_opts = _parse_options(body[data_end:], e)
                    nb = struct.pack(e + "IIIII", iface, th, tl, caplen, orig) + body[20:data_end]
                    nb += _opt(e, 1, comment.encode())
                    for code, val in old_opts:
                        nb += _opt(e, code, val)
                    nb += _opt(e, 0, b"")
                    out.write(_blk(e, BT_EPB, nb))
                else:  # SPB: cannot carry options, copied verbatim
                    out.write(_blk(e, bt, body))
            written += 1
            if progress and i % 2000 == 0:
                progress(i, len(refs))
    return {"frames": written, "secrets_blocks": secrets_written}
