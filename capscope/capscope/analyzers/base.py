"""Analyzer plug-in framework.

An analyzer is an independent module that

* declares the TShark fields it needs (``fields``) and the protocol layers that
  trigger it (``triggers``; ``None`` = every packet),
* owns its tables (``schema``),
* receives packets in capture order (``on_packet``) and finalises at the end
  (``finish``), where it is told whether the index is complete or cut
  (cancelled, truncated file, user limit) so it can mark results that depend
  on the missing tail as *undetermined*.

Finding/transaction states: ``observed`` (directly visible in the capture),
``inferred`` (derived by a correlation rule), ``undetermined`` (the capture
does not allow a decision). Every result stores the rule id and the frames.
"""
from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable

AGG = "\x1f"  # TShark -E aggregator (multi-occurrence separator)

OBSERVED, INFERRED, UNDETERMINED = "observed", "inferred", "undetermined"
NO_RESPONSE_TEXT = "A válasz nem látszik a vizsgált capture-ben."

IP_LAYERS = ("ip", "ipv6")
L4_LAYERS = ("tcp", "udp", "sctp")
ICMP_LAYERS = ("icmp", "icmpv6")


@dataclass
class Cut:
    """Describes why the indexed range may end before the real end of traffic."""
    reason: str | None = None   # None | cancelled | truncated | limit | error
    last_ts_ns: int | None = None
    last_frame: int = 0
    note: str = ""

    @property
    def is_cut(self) -> bool:
        return self.reason is not None


class Packet:
    __slots__ = ("vals", "idx", "frame", "ts_ns", "length", "caplen", "layers", "_lpos")

    def __init__(self, vals: list[str], idx: dict[str, int], frame: int, ts_ns: int, length: int, caplen: int,
                 layers: list[str]):
        self.vals, self.idx, self.frame, self.ts_ns = vals, idx, frame, ts_ns
        self.length, self.caplen, self.layers = length, caplen, layers
        self._lpos = None

    def raw(self, name: str) -> str:
        i = self.idx.get(name)
        return self.vals[i] if i is not None else ""

    def get(self, name: str, n: int = 0) -> str | None:
        v = self.raw(name)
        if not v:
            return None
        if n == 0:
            j = v.find(AGG)
            return v if j < 0 else v[:j]
        parts = v.split(AGG)
        return parts[n] if n < len(parts) else None

    def all(self, name: str) -> list[str]:
        v = self.raw(name)
        return v.split(AGG) if v else []

    def has(self, name: str) -> bool:
        return bool(self.raw(name))

    def int(self, name: str, n: int = 0) -> int | None:
        v = self.get(name, n)
        if v is None or v == "":
            return None
        try:
            return int(v, 0)
        except ValueError:
            try:
                return int(float(v))
            except ValueError:
                return None

    # -- layer helpers ---------------------------------------------------------
    def _positions(self) -> list[tuple[str, int]]:
        """[(layer, occurrence index among layers of the same name)]"""
        if self._lpos is None:
            seen: dict[str, int] = {}
            out = []
            for l in self.layers:
                k = seen.get(l, 0)
                out.append((l, k))
                seen[l] = k + 1
            self._lpos = out
        return self._lpos

    def has_layer(self, name: str) -> bool:
        return name in self.layers

    def endpoints_before(self, pos: int) -> tuple[str | None, str | None, int | None, int | None, str | None]:
        """IP/L4 endpoints of the layer at index ``pos`` (the nearest preceding IP and L4)."""
        lp = self._positions()
        ip_i = l4_i = None
        for i in range(pos - 1, -1, -1):
            l = lp[i][0]
            if l4_i is None and ip_i is None and l in L4_LAYERS:
                l4_i = i
            if l in IP_LAYERS:
                ip_i = i
                break
        if ip_i is None:
            return None, None, None, None, None
        ipname, k = lp[ip_i]
        src = self.get(f"{ipname}.src", k)
        dst = self.get(f"{ipname}.dst", k)
        sport = dport = None
        l4 = None
        if l4_i is not None:
            l4, k4 = lp[l4_i]
            sport = self.int(f"{l4}.srcport", k4)
            dport = self.int(f"{l4}.dstport", k4)
        return src, dst, sport, dport, l4

    def endpoints_of(self, layer: str) -> tuple[str | None, str | None, int | None, int | None, str | None]:
        try:
            pos = self.layers.index(layer)
        except ValueError:
            return None, None, None, None, None
        return self.endpoints_before(pos)

    def ip_layers(self) -> list[tuple[int, str, int]]:
        """[(position, 'ip'|'ipv6', occurrence)] excluding ICMP-embedded headers."""
        out = []
        for pos, (l, k) in enumerate(self._positions()):
            if l in ICMP_LAYERS:
                break
            if l in IP_LAYERS:
                out.append((pos, l, k))
        return out

    def l4_layers(self) -> list[tuple[int, str, int]]:
        out = []
        for pos, (l, k) in enumerate(self._positions()):
            if l in ICMP_LAYERS:
                break
            if l in ("tcp", "udp"):
                out.append((pos, l, k))
        return out


class Context:
    """Shared services for analyzers during one indexing run."""

    def __init__(self, con: sqlite3.Connection, capture: dict, settings: Any):
        self.con, self.capture, self.settings = con, capture, settings
        self.shared: dict[str, Any] = {}
        self.warnings: list[str] = []
        self._findings = None

    def finding(self, analyzer: str, rule: str, state: str, severity: str, ts_ns: int | None, title: str,
                detail: str = "", frames: Iterable[int] = (), obj_type: str | None = None,
                obj_id: int | None = None, en: str | None = None) -> None:
        from ..db import BatchWriter
        if self._findings is None:
            self._findings = BatchWriter(self.con, "INSERT INTO findings(analyzer, rule, state, severity, ts_ns, "
                                                   "title, detail, frames, obj_type, obj_id, title_en) "
                                                   "VALUES (?,?,?,?,?,?,?,?,?,?,?)")
        self._findings.add((analyzer, rule, state, severity, ts_ns, title, detail,
                            json.dumps(sorted(set(f for f in frames if f))[:200]), obj_type, obj_id, en or title))

    def flush(self) -> None:
        if self._findings is not None:
            self._findings.flush()


class Analyzer:
    name = "base"
    title = "Base"
    order = 100
    fields: tuple[str, ...] = ()
    triggers: frozenset[str] | None = None
    schema = ""

    def __init__(self, ctx: Context):
        self.ctx = ctx

    def on_packet(self, pkt: Packet) -> None:  # pragma: no cover - interface
        pass

    def periodic(self, now_ns: int) -> None:
        """Called roughly once per captured second (expire state, bound memory)."""

    def finish(self, cut: Cut) -> None:
        pass


# ---------------------------------------------------------------------------
# Generic request/response matcher
# ---------------------------------------------------------------------------

@dataclass
class Pending:
    key: tuple
    req_frame: int
    req_ts: int
    data: dict
    retrans: list[int] = field(default_factory=list)
    rsp_frame: int | None = None
    rsp_ts: int | None = None
    rsp_data: dict | None = None
    dup_rsp: list[int] = field(default_factory=list)


class TxnMatcher:
    """Pairs requests and responses by (protocol transaction id, endpoints, direction) within a time window.

    * same key while unanswered          -> retransmission of the same request
    * same key after an answer, > window -> new transaction (id reuse)
    * response without pending request   -> orphan (``on_orphan``)
    * pending past the window            -> finalised as unanswered
    """

    def __init__(self, timeout_ns: int, on_final: Callable[[Pending, str], None],
                 on_orphan: Callable[[tuple, Packet, dict], None] | None = None):
        self.timeout_ns = timeout_ns
        self.pending: dict[tuple, Pending] = {}
        self.on_final, self.on_orphan = on_final, on_orphan

    def request(self, key: tuple, pkt: Packet, data: dict) -> tuple[Pending, bool]:
        """Returns (pending, is_retransmission)."""
        p = self.pending.get(key)
        if p is not None:
            if p.rsp_frame is None and pkt.ts_ns - p.req_ts <= self.timeout_ns:
                p.retrans.append(pkt.frame)
                return p, True
            self._final(self.pending.pop(key))
        p = Pending(key, pkt.frame, pkt.ts_ns, data)
        self.pending[key] = p
        return p, False

    def response(self, key: tuple, pkt: Packet, data: dict) -> Pending | None:
        p = self.pending.get(key)
        if p is None or pkt.ts_ns - p.req_ts > self.timeout_ns or pkt.ts_ns < p.req_ts:
            if self.on_orphan:
                self.on_orphan(key, pkt, data)
            return None
        if p.rsp_frame is not None:
            p.dup_rsp.append(pkt.frame)
            return p
        p.rsp_frame, p.rsp_ts, p.rsp_data = pkt.frame, pkt.ts_ns, data
        return p

    def expire(self, now_ns: int) -> None:
        while self.pending:
            k = next(iter(self.pending))
            p = self.pending[k]
            if now_ns - p.req_ts <= self.timeout_ns:
                break
            self._final(self.pending.pop(k))

    def flush(self, cut: Cut) -> None:
        for p in list(self.pending.values()):
            if p.rsp_frame is None and cut.is_cut and cut.last_ts_ns is not None and \
                    cut.last_ts_ns - p.req_ts <= self.timeout_ns:
                self.on_final(p, "cut")
            elif p.rsp_frame is None and cut.last_ts_ns is not None and cut.last_ts_ns - p.req_ts < self.timeout_ns:
                self.on_final(p, "capture_end")
            else:
                self.on_final(p, "normal")
        self.pending.clear()

    def _final(self, p: Pending) -> None:
        self.on_final(p, "normal")


def txn_state(p: Pending, how: str) -> tuple[str, str, str]:
    """(status, state, note) for a finalised transaction."""
    if p.rsp_frame is not None:
        note = ""
        if p.retrans:
            note = f"A kérés {len(p.retrans)}× ismételve a válasz előtt."
        if p.dup_rsp:
            note += f" Többszörös válasz: {', '.join(map(str, p.dup_rsp))}."
        return "answered", OBSERVED, note.strip()
    if how == "cut":
        return "unanswered", UNDETERMINED, (NO_RESPONSE_TEXT + " Az index a válaszablakon belül véget ér "
                                            "(megszakítás / csonka fájl / korlát), ezért nem eldönthető.")
    if how == "capture_end":
        return "unanswered", UNDETERMINED, (NO_RESPONSE_TEXT + " A capture vége a válaszablakon belül van, "
                                            "ezért nem eldönthető, hogy érkezett-e később válasz.")
    note = NO_RESPONSE_TEXT
    if p.retrans:
        note += f" A kérés {len(p.retrans)}× ismételve."
    return "unanswered", OBSERVED, note


def dumps(v: Any) -> str:
    return json.dumps(v, ensure_ascii=False)


TXN_SCHEMA = """
CREATE TABLE IF NOT EXISTS transactions(
  id INTEGER PRIMARY KEY, proto TEXT, kind TEXT, req_frame INTEGER, rsp_frame INTEGER, req_ts INTEGER,
  rsp_ts INTEGER, rtt_ns INTEGER, client TEXT, client_port INTEGER, server TEXT, server_port INTEGER,
  txn_id TEXT, summary TEXT, result TEXT, result_ok INTEGER, retrans INTEGER, retrans_frames TEXT,
  dup_rsp_frames TEXT, status TEXT, state TEXT, rule TEXT, note TEXT, session_id INTEGER, imsi TEXT);
CREATE INDEX IF NOT EXISTS ix_txn_req ON transactions(req_frame);
"""

TXN_INSERT = ("INSERT INTO transactions(proto, kind, req_frame, rsp_frame, req_ts, rsp_ts, rtt_ns, client, client_port, "
              "server, server_port, txn_id, summary, result, result_ok, retrans, retrans_frames, dup_rsp_frames, status, "
              "state, rule, note, session_id, imsi) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)")
