"""Background jobs (import, filter, export) with progress and cancellation."""
from __future__ import annotations

import itertools
import threading
import time
import traceback
from typing import Any, Callable


class Job:
    def __init__(self, jid: int, kind: str, capture_id: int | None, title: str):
        self.id, self.kind, self.capture_id, self.title = jid, kind, capture_id, title
        self.state = "queued"
        self.progress: float | None = None
        self.message = ""
        self.counters: dict[str, Any] = {}
        self.result: dict[str, Any] = {}
        self.error: str | None = None
        self.started = time.time()
        self.finished: float | None = None
        self._cancel = threading.Event()
        self._procs: list = []
        self.thread: threading.Thread | None = None

    def cancelled(self) -> bool:
        return self._cancel.is_set()

    def attach(self, proc) -> None:
        self._procs.append(proc)
        if self.cancelled():
            self._kill()

    def cancel(self) -> None:
        self._cancel.set()
        self._kill()

    def _kill(self) -> None:
        for p in self._procs:
            try:
                if p.poll() is None:
                    p.kill()
            except OSError:
                pass

    def to_dict(self) -> dict:
        return {"id": self.id, "kind": self.kind, "capture_id": self.capture_id, "title": self.title,
                "state": self.state, "progress": self.progress, "message": self.message, "counters": self.counters,
                "result": self.result, "error": self.error, "started": self.started, "finished": self.finished,
                "elapsed_s": round((self.finished or time.time()) - self.started, 2)}


class JobManager:
    def __init__(self):
        self.jobs: dict[int, Job] = {}
        self._ids = itertools.count(1)
        self._lock = threading.Lock()

    def start(self, kind: str, capture_id: int | None, title: str, fn: Callable[[Job], None]) -> Job:
        with self._lock:
            job = Job(next(self._ids), kind, capture_id, title)
            self.jobs[job.id] = job

        def runner() -> None:
            job.state = "running"
            try:
                fn(job)
                if job.state == "running":
                    job.state = "cancelled" if job.cancelled() else "done"
            except InterruptedError:
                job.state = "cancelled"
            except Exception as e:  # surfaced in the UI
                job.state = "failed"
                job.error = f"{type(e).__name__}: {e}"
                job.result["traceback"] = traceback.format_exc(limit=5)
            finally:
                job.finished = time.time()

        job.thread = threading.Thread(target=runner, name=f"job-{job.id}-{kind}", daemon=True)
        job.thread.start()
        return job

    def get(self, jid: int) -> Job | None:
        return self.jobs.get(jid)

    def active_for(self, capture_id: int, kind: str | None = None) -> list[Job]:
        return [j for j in self.jobs.values() if j.capture_id == capture_id and j.state in ("queued", "running")
                and (kind is None or j.kind == kind)]

    def cancel_all(self) -> None:
        for j in self.jobs.values():
            if j.state in ("queued", "running"):
                j.cancel()


jobs = JobManager()
