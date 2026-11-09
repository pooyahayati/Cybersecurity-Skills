#!/usr/bin/env python3
"""Actual current k6, real local requests and M1 SQLite recovery workflow.

Only checkout head/worker publishing is synthetic. k6 is freshly resolved from
official GitHub metadata; an optional archive must match that current digest.
"""

import argparse
from contextlib import closing
import copy
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from m5_support import ROOT, M5World, Server, artifact_contract, make_database
from runtime_support import acceptance, source
from security_runtime.common import Blocked, canonical, parse, read_file, require, sha256
from security_runtime.controller import selected_tree
from security_runtime.sandbox import Docker
from security_runtime.sources import GitHub, Http, unpack


def k6_source():
    suffix, binary = ("windows-amd64.zip", "k6.exe") if os.name == "nt" else ("linux-amd64.tar.gz", "k6")
    spec = source("k6")
    spec.update(repository="grafana/k6", repository_id=54400687, owner_id=7195757, include=[],
        asset={"name": "k6-v{version}-" + suffix, "format": "zip" if os.name == "nt" else "tar.gz",
               "members": ["k6-v{version}-" + suffix.split(".")[0] + "/" + binary]},
        max_download_bytes=64 * 1024 * 1024, max_unpacked_bytes=256 * 1024 * 1024)
    return spec


class Publisher:
    def __init__(self, fixture, archive=None):
        self.fixture, self.archive = fixture, archive
        self.official = GitHub(Http(os.environ.get("GITHUB_TOKEN")))

    def resolve(self, spec):
        return self.official.resolve(spec) if spec["id"] == "k6" else self.fixture.resolve(spec)

    def fetch(self, spec, resolved):
        if spec["id"] != "k6": return self.fixture.fetch(spec, resolved)
        if self.archive is None: return self.official.fetch(spec, resolved)
        raw = read_file(self.archive.parent, self.archive.name, spec["max_download_bytes"])
        identity = resolved["identity"]
        require(len(raw) == identity["asset"]["size"] and sha256(raw) == identity["asset"]["sha256"], "archive is not the current official release")
        return unpack(raw, spec["asset"], spec["max_unpacked_bytes"], identity["label"].removeprefix("v"))


def prepare(world, docker_path, archive):
    publisher = Publisher(world.publisher, archive)
    world.runtime.upstream = world.control.web.controller.upstream = world.control.load.controller.upstream = publisher
    world.runtime.clock = world.control.clock = world.control.web.clock = world.control.load.clock = time.time
    world.control.web.controller.clock = world.control.load.controller.clock = time.time
    world.runtime.docker = Docker(docker_path, world.state)
    world.publisher.contents["m5"] = {p: read_file(ROOT, p) for p in selected_tree(ROOT, ["scripts"])}
    world.runtime.enroll(source("m5", "tool", ["scripts"]))
    for component in ("runtime", "m5"):
        candidate = world.runtime.prepare(component)["candidate"]
        world.runtime.review(acceptance(candidate)); world.runtime.activate(candidate)
    return publisher


def offline(world, name="artifact"):
    world.runtime.authorize({"id": name, "root": str(world.target), "inputs": sorted(world.spec["source"]["files"]), "components": ["m5"], "network": "none",
        "operations": [{"id": "check", "component": "m5", "entrypoint": "scripts/m5_worker.py", "interpreter": "python", "arguments": ["sqlite"], "timeout_seconds": 30, "max_output_bytes": 1048576}],
        "limits": {"calls": 1, "seconds": 30, "expires_at": time.time() + 600, "memory_mb": 256, "cpus": 1, "pids": 32, "tmpfs_mb": 64}})
    run = world.runtime.begin(name)["run"]
    return world.runtime.execute(run, "check")["operation"]


def run_suite(docker_path, archive=None):
    completed, commands, operations, worlds = False, 0, [], []
    fixture = tempfile.TemporaryDirectory(prefix="cyber-m5-workflow-")
    root = Path(fixture.name)
    rows = [("one", 100), ("two", 200)]
    safe = make_database(root / "safe.sqlite3", rows)
    state = {"overload": False, "ack": b"pending", "duplicate": False, "active": 0, "peak": 0, "calls": 0}
    lock = threading.Lock()
    database = root / "transactions.sqlite3"
    make_database(database, [])

    def handler(path, _token):
        if path == "/ack": return 200, {}, state["ack"]
        with lock:
            state["active"] += 1; state["peak"] = max(state["peak"], state["active"]); state["calls"] += 1
        try:
            time.sleep(.15)
            if state["duplicate"]:
                with closing(sqlite3.connect(database)) as connection:
                    connection.execute("INSERT INTO records VALUES (?,?)", ("same-intent", 10))
                    connection.commit()
            return (503 if state["overload"] else 200), {}, b"safe"
        finally:
            with lock: state["active"] -= 1

    server = Server(handler)
    world = M5World(server, files={"backup.sqlite3": safe, "rollback.sqlite3": safe,
        "m5-contract.json": canonical(artifact_contract(rows, True)), "incident.txt": b"private synthetic incident evidence"})
    worlds.append(world)

    def cli(command, value=None, extra=(), ok=True, selected=None):
        nonlocal commands
        commands += 1; selected = selected or world
        argv = [sys.executable, "-I", "-B", str(ROOT / "scripts/m5_review.py"), "--state", str(selected.state.root), command, "resilience"]
        if value is not None:
            path = selected.root / ("cli-" + str(commands) + ".json")
            path.write_bytes(canonical(value)); argv.append(str(path))
        argv.extend(map(str, extra))
        result = subprocess.run(argv, capture_output=True, timeout=45, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        require((result.returncode == 0) == ok and not result.stderr, "unexpected M5 CLI outcome: " + command)
        require(b"private synthetic incident evidence" not in result.stdout, "incident bytes leaked")
        return parse(result.stdout)

    try:
        prepare(world, docker_path, archive)
        world.runtime.enroll(k6_source())
        candidate = world.runtime.prepare("k6")["candidate"]
        review = acceptance(candidate)
        for area in review["checks"]:
            review["checks"][area]["evidence"] = "Synthetic integration operator: exact official asset digest and AGPL-3.0 source reviewed; native trusted executable, fixed generated loopback script, clean environment, no target script or credential exposure."
        world.runtime.review(review); world.runtime.activate(candidate)
        version = world.state.get("candidate", candidate)["resolved"]["identity"]["label"]
        spec = world.workload("normal")
        world.control.load_authorize("resilience", spec)
        first = world.control.load_execute("resilience", "normal")
        require(first["workload_passed"] and state["calls"] == 6 and 1 < state["peak"] <= 3, "real current k6 workload did not match bounded concurrency")
        before = state["calls"]
        try: world.control.load_execute("resilience", "normal")
        except Blocked: pass
        else: raise AssertionError("consumed workload replayed")
        require(state["calls"] == before, "replay reached target")
        state["overload"] = True
        world.control.load_authorize("resilience", world.workload("overloaded"))
        overloaded = world.control.load_execute("resilience", "overloaded")
        require(not overloaded["workload_passed"] and state["calls"] < before + 6, "overload became success or failed to abort")
        state["overload"] = False
        print(json.dumps({"stage": "real-k6", "version": version, "result": "passed"}), flush=True)

        plan = cli("recovery-plan", {"id": "restore", "deployment": "local", "ack_url": server.url + "ack"})
        operation = offline(world); operations.append(operation)
        restored = cli("artifact", {"id": "restored", "operation": operation, "plan": "restore"})
        require(restored["artifact_check_passed"], "actual M1 restore/rollback failed")
        report = cli("plan")
        require(not report["artifacts"][0]["observed_alert_acknowledgment"], "missing alert considered delivered")
        load_report = next(r for r in report["loads"] if r["operation"] == first["operation"])
        require(load_report["context"]["acceptance"] == spec["acceptance"] and load_report["context"]["phases"] == spec["phases"]
                and load_report["producer"]["k6"]["candidate"] == candidate and load_report["finished_at"] >= load_report["started_at"],
                "load report lost frozen criteria, producer or observation time")
        recovery_report = report["artifacts"][0]
        require(recovery_report["producer"]["operation"] == operation and recovery_report["expected_contract"] == artifact_contract(rows, True)
                and recovery_report["recovery_plan"]["ack_body_sha256"] == plan["receiver_body_sha256"], "artifact report lost reviewed contract or provenance")
        state["ack"] = canonical(plan["receiver_body"])
        auth = world.authorization([world.route("ack", "ack", body=state["ack"])], name="ack-reader")
        world.control.web_authorize("resilience", auth)
        ack = world.control.web_execute("resilience", "ack-reader", "ack")["operation"]
        cli("acknowledge", {"recovery": "restored", "operation": ack})
        cli("acknowledge", {"recovery": "restored", "operation": ack}, ok=False)
        require(cli("plan")["artifacts"][0]["observed_alert_acknowledgment"], "fresh receiver acknowledgment not retained")
        cli("incident", {"id": "triage", "kind": "observation", "files": ["incident.txt"], "note": "private synthetic incident evidence", "claimed_at": time.time()})
        report = cli("plan")
        require(report["incidents"][0]["custody_intact"], "incident custody failed")
        exported = cli("report")
        markdown = (world.state.root / exported["markdown"]).read_text(encoding="utf-8")
        require(candidate in markdown and operation in markdown and str(spec["acceptance"]["p95_ms"]) in markdown,
                "human report lost producer or acceptance context")
        cli("invalidate-resilience", extra=("artifact", "restored"))
        report = cli("plan")
        require(not report["artifacts"][0]["accepted_artifact_check"] and not report["artifacts"][0]["observed_alert_acknowledgment"], "invalidated recovery or alert remained accepted")
        print(json.dumps({"stage": "restore-alert-incident", "result": "passed"}), flush=True)

        state["duplicate"] = True
        world.control.load_authorize("resilience", world.workload("duplicate-transactions"))
        duplicate_load = world.control.load_execute("resilience", "duplicate-transactions")
        require(duplicate_load["workload_passed"], "duplicate fixture did not respond successfully")
        with closing(sqlite3.connect(database)) as connection:
            count = connection.execute("SELECT count(*) FROM records").fetchone()[0]
        require(count == 6, "concurrent persisted fixture differs")
        duplicate = M5World(server, files={"backup.sqlite3": database.read_bytes(), "m5-contract.json": canonical(artifact_contract([("same-intent", 10)]))})
        worlds.append(duplicate); prepare(duplicate, docker_path, archive)
        operation = offline(duplicate); operations.append(operation)
        result = cli("artifact", {"id": "duplicates", "operation": operation, "plan": None}, selected=duplicate)
        require(not result["artifact_check_passed"], "actual duplicate persisted transactions accepted")
        row = cli("plan", selected=duplicate)["artifacts"][0]
        require(row["valid"] and row["result"]["restored"]["tables"][0]["duplicates_or_null_keys"], "duplicate detection lacks valid real producer")

        broken = M5World(server, files={"backup.sqlite3": b"existing but unrestorable", "rollback.sqlite3": safe,
            "m5-contract.json": canonical(artifact_contract(rows, True))})
        worlds.append(broken); prepare(broken, docker_path, archive)
        cli("recovery-plan", {"id": "broken", "deployment": "local", "ack_url": server.url + "ack"}, selected=broken)
        operation = offline(broken); operations.append(operation)
        result = cli("artifact", {"id": "broken", "operation": operation, "plan": "broken"}, selected=broken)
        require(not result["artifact_check_passed"], "existing corrupt backup passed restore")
        for item in worlds:
            require({p: sha256(read_file(item.target, p)) for p in item.spec["source"]["files"]} == item.state.get("assessment", "resilience")["source"]["manifest"], "original inputs changed")
        completed = True
        return {"result": "passed", "cli_outcomes": commands, "offline_operations": len(operations), "actual_target_requests": len(server.calls), "k6": version,
                "checks": ["bounded native k6 concurrency and no replay", "overload abort", "actual SQLite restore and rollback", "fresh alert acknowledgment and retraction",
                    "private incident custody", "real concurrent duplicate transactions rejected", "existing unrestorable backup rejected", "originals preserved"]}
    finally:
        server.close()
        if completed:
            for item in worlds: item.close()
            fixture.cleanup()
        else:
            # Failed evidence is retained outside the repository for diagnosis.
            fixture._finalizer.detach()
            print(json.dumps({"retained": [str(w.root) for w in worlds], "fixture": str(root)}), flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--docker", type=Path, required=True)
    parser.add_argument("--k6-archive", type=Path)
    args = parser.parse_args()
    print(json.dumps(run_suite(args.docker, args.k6_archive)), flush=True)
