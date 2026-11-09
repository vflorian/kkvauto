"""Overview statistics: per-second timeline, protocol hierarchy, top talkers."""
from __future__ import annotations

from .base import Analyzer, Cut, Packet

SCHEMA = """
CREATE TABLE IF NOT EXISTS timeline(bucket INTEGER PRIMARY KEY, pkts INTEGER, bytes INTEGER, first_frame INTEGER);
CREATE TABLE IF NOT EXISTS proto_hier(path TEXT PRIMARY KEY, depth INTEGER, pkts INTEGER, bytes INTEGER);
CREATE TABLE IF NOT EXISTS talkers(ip TEXT, scope TEXT, pkts_tx INTEGER, pkts_rx INTEGER, bytes_tx INTEGER,
  bytes_rx INTEGER, PRIMARY KEY(ip, scope)) WITHOUT ROWID;
"""
SKIP = {"ethertype", "vlan:ethertype"}
MAX_TALKERS = 500_000


class StatsAnalyzer(Analyzer):
    name = "stats"
    title = "Áttekintő statisztika"
    order = 10
    triggers = None
    schema = SCHEMA

    def __init__(self, ctx):
        super().__init__(ctx)
        self.tl: dict[int, list[int]] = {}
        self.phs: dict[str, list[int]] = {}
        self.talk: dict[tuple[str, str], list[int]] = {}
        self.talk_overflow = False

    def on_packet(self, pkt: Packet) -> None:
        b = pkt.ts_ns // 1_000_000_000
        e = self.tl.get(b)
        if e is None:
            self.tl[b] = [1, pkt.length, pkt.frame]
        else:
            e[0] += 1
            e[1] += pkt.length
        path = []
        for l in pkt.layers:
            if l == "ethertype":
                continue
            path.append(l)
            k = ":".join(path)
            e = self.phs.get(k)
            if e is None:
                self.phs[k] = [1, pkt.length]
            else:
                e[0] += 1
                e[1] += pkt.length
        ips = pkt.ip_layers()
        if not ips:
            return
        scopes = [("outer", ips[0])]
        if len(ips) > 1:
            scopes.append(("inner", ips[-1]))
        for scope, (_, l, k) in scopes:
            s, d = pkt.get(f"{l}.src", k), pkt.get(f"{l}.dst", k)
            for ip, tx in ((s, True), (d, False)):
                if not ip:
                    continue
                key = (ip, scope)
                e = self.talk.get(key)
                if e is None:
                    if len(self.talk) >= MAX_TALKERS:
                        self.talk_overflow = True
                        continue
                    e = self.talk[key] = [0, 0, 0, 0]
                if tx:
                    e[0] += 1
                    e[2] += pkt.length
                else:
                    e[1] += 1
                    e[3] += pkt.length

    def finish(self, cut: Cut) -> None:
        con = self.ctx.con
        con.executemany("INSERT INTO timeline VALUES (?,?,?,?)", [(k, *v) for k, v in self.tl.items()])
        con.executemany("INSERT INTO proto_hier VALUES (?,?,?,?)",
                        [(k, k.count(":"), *v) for k, v in self.phs.items()])
        items = list(self.talk.items())
        for i in range(0, len(items), 10000):
            con.executemany("INSERT INTO talkers VALUES (?,?,?,?,?,?)", [(k[0], k[1], *v) for k, v in items[i:i + 10000]])
        if self.talk_overflow:
            self.ctx.warnings.append(f"Top talkers: a {MAX_TALKERS} címes korlát elérve, a további címek kimaradtak.")


ANALYZER = StatsAnalyzer
