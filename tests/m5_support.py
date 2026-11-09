"""Synthetic M5 fixtures. Fake generator tests are not real k6 qualification."""

import concurrent.futures
import json
import os
from pathlib import Path
import re
import sqlite3
import tempfile
import threading
import time
from urllib.request import build_opener, ProxyHandler
from urllib.error import HTTPError

from m4_support import ROOT, RuntimeWorld, Server
from security_assessment.resilience import ResilienceReview
from security_assessment.resilience_data import cell
from security_runtime.common import canonical, digest, read_file
from security_runtime.controller import HEAD_RESOURCES, selected_tree


class M5World(RuntimeWorld):
    def __init__(self, server, **kwargs):
        super().__init__(server, **kwargs)
        # Replace only the freshly created synthetic case with the M5 engine.
        # Use a distinct assessment ID to avoid mutating signed M4 history.
        self.spec["id"] = "resilience"
        self.control = ResilienceReview(self.state, ROOT, clock=lambda: self.now[0], upstream=self.publisher)
        self.control.create(self.spec)

    def workload(self, name="load", count=6):
        web = self.authorization([self.route(body=b"safe")])
        web["limits"].update(requests=count, seconds=15, timeout_seconds=2, expires_at=time.time() + 600)
        return {"id": name, "web": web, "scenario": "load", "purpose": "Synthetic scoped read workload",
            "workload": "Complete safe body from an owned loopback fixture", "dataset": "Synthetic fixed response",
            "phases": [{"id": "steady", "requests": count, "concurrency": min(3, count), "rps": 20, "seconds": 5}],
            "abort": {"errors": 1, "latency_ms": 1500}, "acceptance": {"p95_ms": 1400, "error_rate": 0, "minimum_success_rps": .1}}


class FakeGenerator:
    """Deterministic k6 stand-in; exercises real HTTP broker/target effects."""
    def tickets(self, count): return range(count)

    def __init__(self, argv, **_kwargs):
        script = Path(argv[-1]).read_text()
        options = json.loads(script.split("export const options=", 1)[1].split(";\n", 1)[0])
        self.url = json.loads(re.search(r"http.get\((\"[^\"]+\")", script).group(1))
        phase = options["scenarios"]["bounded"]
        self.cancelled = threading.Event()
        self.done = threading.Event()
        self.returncode = None
        def request(index):
            if not self.cancelled.is_set():
                try:
                    with build_opener(ProxyHandler({})).open(self.url + str(index), timeout=8) as response: response.read()
                except HTTPError as exc: exc.close()
                except Exception: pass
        def run():
            with concurrent.futures.ThreadPoolExecutor(max_workers=phase["vus"]) as pool:
                list(pool.map(request, self.tickets(phase["iterations"])))
            self.returncode = 0
            self.done.set()
        self.thread = threading.Thread(target=run, daemon=True)
        self.thread.start()

    def poll(self): return self.returncode
    def kill(self): self.cancelled.set(); self.returncode = -9
    def wait(self, timeout):
        self.done.wait(timeout)
        return self.returncode


def make_database(path, rows, view=False):
    connection = sqlite3.connect(path)
    connection.execute("CREATE TABLE records (transaction_id TEXT, amount INTEGER)")
    connection.executemany("INSERT INTO records VALUES (?,?)", rows)
    if view: connection.execute("CREATE VIEW projected AS SELECT * FROM records")
    connection.commit(); connection.close()
    return path.read_bytes()


def oracle(rows):
    return [{"table": "records", "columns": ["transaction_id", "amount"], "row_count": len(rows),
        "rows_sha256": digest(sorted([list(map(cell, r)) for r in rows], key=canonical)), "unique": [["transaction_id"]]}]


def artifact_contract(rows, recovery=False):
    return {"schema_version": 1, "mode": "recovery" if recovery else "integrity", "database": "backup.sqlite3", "oracle": oracle(rows),
        "rollback": {"database": "rollback.sqlite3", "oracle": oracle(rows)} if recovery else None,
        "objectives": {"restore_seconds": 10, "declared_snapshot_at": 100, "declared_reference_at": 110, "allowed_loss_seconds": 10} if recovery else None}
