"""Start CapScope: python -m capscope [--port 8765] [--data DIR] [--no-browser] [--check]"""
from __future__ import annotations

import argparse
import sys
import threading
import time
import webbrowser
from pathlib import Path

from . import __version__


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="capscope", description="CapScope – helyi pcap/pcapng elemző")
    ap.add_argument("--port", type=int, default=None, help="loopback port (alapértelmezés: 8765)")
    ap.add_argument("--data", default=None, help="adatkönyvtár (index, export, ideiglenes fájlok)")
    ap.add_argument("--no-browser", action="store_true", help="ne nyissa meg automatikusan a böngészőt")
    ap.add_argument("--check", action="store_true", help="csak környezetellenőrzés (TShark, adatkönyvtár)")
    a = ap.parse_args(argv)

    from .config import settings
    if a.port:
        settings.port = a.port
    if a.data:
        settings.data_dir = Path(a.data).expanduser().resolve()
    settings.ensure_dirs()

    from . import tshark
    print(f"CapScope {__version__}  |  Python {sys.version.split()[0]}  |  adatkönyvtár: {settings.data_dir}")
    try:
        path = tshark.tshark_path()
        ver = tshark.version()
        print(f"TShark: {path}  (verzió {ver or 'ismeretlen'})")
        n = len(tshark.known_fields())
        print(f"TShark mezők: {n}")
        ok, msg, _ = tshark.validate_filter("dns && gtpv2")
        print("Display filter ellenőrzés: " + ("OK" if ok else f"HIBA – {msg}"))
    except tshark.TSharkNotFound as e:
        print(f"HIBA: {e}")
        return 2
    if a.check:
        return 0

    import uvicorn
    from .api import app, ensure_token
    from .jobs import jobs
    from .service import recover_after_restart, wipe_tmp

    recover_after_restart()
    wipe_tmp()
    token = ensure_token()
    url = f"http://127.0.0.1:{settings.port}/?token={token}"
    print("\nA felület (csak erről a gépről érhető el):\n  " + url + "\nLeállítás: Ctrl+C\n")
    if not a.no_browser:
        threading.Timer(1.0, lambda: webbrowser.open(url)).start()
    try:
        uvicorn.run(app, host="127.0.0.1", port=settings.port, log_level="warning", access_log=False)
    finally:
        jobs.cancel_all()
        deadline = time.time() + 10
        for j in list(jobs.jobs.values()):
            if j.thread is not None:
                j.thread.join(timeout=max(0.1, deadline - time.time()))
    return 0


if __name__ == "__main__":
    sys.exit(main())
