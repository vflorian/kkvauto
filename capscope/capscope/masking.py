"""Identifier masking for text exports (report, CSV, JSON).

Scope is explicit and reported in every masked export. Raw capture exports are
never masked (packet bytes are copied losslessly) and are labelled as such.
Masked values keep the PLMN/country prefix and get a per-export alias
(IMSI#1, MSISDN#2 …) so correlation inside one report stays possible
without exposing the identifier.
"""
from __future__ import annotations

import ipaddress
import re
from typing import Any

DIGITS_RX = re.compile(r"(?<!\d)(\d{14,16})(?!\d)")


class Masker:
    def __init__(self, imsi: bool = True, msisdn: bool = True, imei: bool = True, ue_ip: bool = False,
                 all_ip: bool = False, known: dict[str, set[str]] | None = None):
        self.opts = {"imsi": imsi, "msisdn": msisdn, "imei": imei, "ue_ip": ue_ip, "all_ip": all_ip}
        self.alias: dict[tuple[str, str], str] = {}
        self.count: dict[str, int] = {}
        self.known = {k: set(v) for k, v in (known or {}).items()}
        self._rx: re.Pattern | None = None

    @property
    def active(self) -> bool:
        return any(self.opts.values())

    def scope(self) -> dict:
        classes = [n for n, on in (("IMSI", self.opts["imsi"]), ("MSISDN", self.opts["msisdn"]),
                                   ("IMEI/IMEISV", self.opts["imei"]),
                                   ("UE IP addresses (allocated PAA / End User Address)", self.opts["ue_ip"]),
                                   ("all IP addresses", self.opts["all_ip"])) if on]
        return {"masked_classes": classes,
                "applies_to": "this text export only (report/CSV/JSON fields and free text)",
                "not_applied_to": "raw capture exports (pcapng) – packet bytes are exported unmodified",
                "free_text": "known identifiers and any 14–16 digit sequence in free text are replaced",
                "aliases": "per-export aliases (e.g. IMSI#1) keep correlation inside this export"}

    def _a(self, kind: str, value: str, shown: str) -> str:
        k = (kind, value)
        if k not in self.alias:
            self.count[kind] = self.count.get(kind, 0) + 1
            self.alias[k] = f"{shown} [{kind}#{self.count[kind]}]"
        return self.alias[k]

    def imsi(self, v: str | None) -> str | None:
        if not v or not self.opts["imsi"]:
            return v
        return self._a("IMSI", v, v[:5] + "x" * max(0, len(v) - 5))

    def msisdn(self, v: str | None) -> str | None:
        if not v or not self.opts["msisdn"]:
            return v
        return self._a("MSISDN", v, v[:2] + "x" * max(0, len(v) - 2))

    def imei(self, v: str | None) -> str | None:
        if not v or not self.opts["imei"]:
            return v
        return self._a("IMEI", v, v[:8] + "x" * max(0, len(v) - 8))

    def ip(self, v: str | None, ue: bool = False) -> str | None:
        if not v:
            return v
        if not (self.opts["all_ip"] or (ue and self.opts["ue_ip"]) or
                (self.opts["ue_ip"] and v in self.known.get("ue_ip", set()))):
            return v
        try:
            a = ipaddress.ip_address(v)
        except ValueError:
            return v
        shown = ".".join(v.split(".")[:2]) + ".x.x" if a.version == 4 else v.split(":")[0] + ":…"
        return self._a("IP", v, shown)

    def text(self, s: Any) -> Any:
        if not isinstance(s, str) or not s or not self.active:
            return s
        if self._rx is None:
            vals = []
            for kind in ("imsi", "msisdn", "imei"):
                if self.opts[kind]:
                    vals += self.known.get(kind, ())
            if self.opts["ue_ip"] or self.opts["all_ip"]:
                vals += self.known.get("ue_ip", ())
            vals = sorted({v for v in vals if v and len(v) >= 4}, key=len, reverse=True)
            self._rx = re.compile("|".join(re.escape(v) for v in vals)) if vals else re.compile(r"(?!x)x")

        def rep(m: re.Match) -> str:
            v = m.group(0)
            if v in self.known.get("imsi", ()):
                return self.imsi(v)
            if v in self.known.get("msisdn", ()):
                return self.msisdn(v)
            if v in self.known.get("imei", ()):
                return self.imei(v)
            return self.ip(v, ue=True) or v

        s = self._rx.sub(rep, s)
        if self.opts["imsi"] or self.opts["imei"]:
            s = DIGITS_RX.sub(lambda m: self._a("ID", m.group(1), m.group(1)[:5] + "x" * (len(m.group(1)) - 5)), s)
        if self.opts["all_ip"]:
            s = re.sub(r"(?<![\d.])(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?![\d.])", lambda m: self.ip(m.group(1)), s)
        return s

    def row(self, d: dict) -> dict:
        out = {}
        for k, v in d.items():
            lk = k.lower()
            if lk == "imsi":
                out[k] = self.imsi(v)
            elif lk == "msisdn":
                out[k] = self.msisdn(v)
            elif lk in ("imei", "imeisv", "mei"):
                out[k] = self.imei(v)
            elif lk in ("ue_ipv4", "ue_ipv6", "ue_ip"):
                out[k] = self.ip(v, ue=True)
            elif isinstance(v, str) and (lk.endswith("ip") or lk in ("src", "dst", "osrc", "odst", "client", "server",
                                                                       "inner_src", "inner_dst", "outer_src",
                                                                       "outer_dst", "a_ip", "b_ip")):
                out[k] = self.ip(v)
            else:
                out[k] = self.text(v)
        return out


def known_identifiers(con) -> dict[str, set[str]]:
    """Collect identifiers seen by the GTP analyzers in one capture index."""
    out = {"imsi": set(), "msisdn": set(), "imei": set(), "ue_ip": set()}
    try:
        for r in con.execute("SELECT imsi, msisdn, imei, ue_ipv4, ue_ipv6 FROM gtp_sessions"):
            for k, v in (("imsi", r[0]), ("msisdn", r[1]), ("imei", r[2]), ("ue_ip", r[3]), ("ue_ip", r[4])):
                if v:
                    out[k].add(v)
    except Exception:
        pass
    return out
