"""Analyzer registry.

To add a protocol rule set, drop a module into this package that defines
``ANALYZER = <subclass of base.Analyzer>``. It is discovered automatically,
its fields are added to the single TShark pass and its schema is created in
every new capture index. Analyzers run in ascending ``order``.
"""
from __future__ import annotations

import importlib
import pkgutil

from .base import Analyzer


def discover() -> list[type[Analyzer]]:
    out = []
    for m in pkgutil.iter_modules(__path__):
        if m.name.startswith("_") or m.name == "base":
            continue
        mod = importlib.import_module(f"{__name__}.{m.name}")
        cls = getattr(mod, "ANALYZER", None)
        if cls is not None:
            out.append(cls)
    return sorted(out, key=lambda c: c.order)
