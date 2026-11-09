#!/usr/bin/env python3
"""Required real Docker checks. Missing Docker fails; this suite never skips."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from workflow_package import ROOT
from security_runtime.common import Blocked, require, sha256
from security_runtime.common import timestamp
from security_runtime.controller import Controller
from security_runtime.sandbox import Docker
from security_runtime.store import Store
from runtime_support import Fixture


SCRIPT = b'''
import errno, json, os, pathlib, socket, subprocess, sys, time
mode = sys.argv[1]
if mode == "good":
    assert os.getuid() == 65532
    assert "CYBER_TEST_SECRET" not in os.environ
    assert not pathlib.Path("/var/run/docker.sock").exists()
    assert set(p.name for p in pathlib.Path("/sys/class/net").iterdir()) == {"lo"}
    try:
        socket.create_connection(("192.0.2.1", 443), timeout=0.2)
    except OSError:
        pass
    else:
        raise AssertionError("external network reachable")
    assert pathlib.Path("/inputs/customer.txt").read_bytes() == b"synthetic original\\n"
    for path in ("/inputs/customer.txt", "/component/check.py", "/resources/analyzer/check.py", "/host-write"):
        try:
            pathlib.Path(path).write_text("unauthorized mutation")
        except OSError as exc:
            assert exc.errno in (errno.EROFS, errno.EACCES)
        else:
            raise AssertionError("write escaped readonly boundary")
    status = pathlib.Path("/proc/self/status").read_text()
    assert "NoNewPrivs:\\t1" in status
    assert "CapEff:\\t0000000000000000" in status
    assert "Seccomp:\\t2" in status
    assert pathlib.Path("/sys/fs/cgroup/memory.max").read_text().strip() == "134217728"
    assert pathlib.Path("/sys/fs/cgroup/pids.max").read_text().strip() == "32"
    quota, period = pathlib.Path("/sys/fs/cgroup/cpu.max").read_text().split()
    assert int(quota) / int(period) == 0.5
    try:
        pathlib.Path("/tmp/fill").write_bytes(b"x" * (9 * 1024 * 1024))
    except OSError as exc:
        assert exc.errno == errno.ENOSPC
    else:
        raise AssertionError("scratch limit not enforced")
    assert sys.argv[2] == "; literal argument $(no-shell)"
    print(json.dumps({"isolation": "passed", "original_bytes": "preserved"}))
elif mode == "output":
    while True:
        print("x" * 4096, flush=True)
elif mode == "memory":
    data = bytearray(512 * 1024 * 1024)
    raise AssertionError("memory limit not enforced")
elif mode == "pids":
    children = []
    try:
        for index in range(64):
            children.append(subprocess.Popen(["/usr/bin/sleep", "10"]))
    except OSError as exc:
        assert exc.errno == errno.EAGAIN and len(children) < 32
    else:
        raise AssertionError("process limit not enforced")
    finally:
        for child in children:
            child.kill()
        for child in children:
            child.wait()
    print("process bound verified")
elif mode == "sleep":
    subprocess.Popen(["/usr/bin/sleep", "120"])
    time.sleep(120)
else:
    raise AssertionError("unknown mode")
'''


class MeasuredDocker(Docker):
    """Observe workload clocks separately from trusted preflight/cleanup I/O."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.states = {}
        self.attach_seconds = None

    def inspect(self, name):
        info = super().inspect(name)
        if info is not None:
            self.states[name] = info["State"]
        return info

    def command(self, args, *positional, **kwargs):
        started = time.monotonic()
        try:
            return super().command(args, *positional, **kwargs)
        finally:
            if args[:2] == ["container", "start"]:
                self.attach_seconds = time.monotonic() - started


def wait_running(fixture, authorization, deadline=15):
    end = time.monotonic() + deadline
    while time.monotonic() < end:
        operation = fixture.store.get("authorization", authorization)["operation"]
        if operation:
            info = fixture.docker.inspect(fixture.docker.name(operation))
            if info is not None and info.get("State", {}).get("Running") is True:
                return operation
        time.sleep(0.1)
    raise AssertionError("container did not enter running state")


def run_suite(executable):
    fixture = Fixture(SCRIPT)
    try:
        fixture.docker = MeasuredDocker(executable, fixture.store)
        fixture.controller.docker = fixture.docker
        fixture.ready()
        control = fixture.controller
        original = (fixture.target / "customer.txt").read_bytes()
        outcomes = []

        def start(name, mode, timeout=10, output=4096, calls=1):
            value = fixture.authorization(name)
            value["operations"][0].update(arguments=[mode] + (["; literal argument $(no-shell)"] if mode == "good" else []),
                                         timeout_seconds=timeout, max_output_bytes=output)
            value["limits"].update(calls=calls, seconds=timeout * calls)
            return fixture.begin(value)

        def preserved():
            require((fixture.target / "customer.txt").read_bytes() == original, "original target was modified")

        os.environ["CYBER_TEST_SECRET"] = "synthetic-ambient-value-never-forward"
        run = start("legitimate", "good")
        result = control.execute(run, "check")
        require(result["result"]["exit_code"] == 0, "legitimate isolated operation failed")
        preserved()
        output = (fixture.store.root / (result["operation"] + ".output")).read_bytes()
        require(b'"isolation": "passed"' in output and b"synthetic-ambient-value" not in output,
                "isolation assertions did not complete")
        outcomes.append("readonly targets, no egress/secrets, nonroot/caps/seccomp prerequisites, kernel and scratch limits")
        # M2 consumes a real successful M1 operation without interpreting a
        # completed process as a completed security review.
        from security_assessment.service import Assessment
        from m2_support import model
        assessment = Assessment(fixture.store, Path(__file__).resolve().parents[1])
        assessment.create({"schema_version": 1, "id": "real-producer", "source": {
            "root": str(fixture.target), "files": ["customer.txt"], "revision": None},
            "deployments": [], "model": model(), "redact_values": []})
        control_id = next(c["id"] for c in assessment.report("real-producer")["controls"]
                          if c["catalog_id"] == "application" and c["surface"] == "source")
        observed = fixture.store.get("operation", result["operation"])["finished_at"]
        observation = {"schema_version": 1, "id": "isolated-probe", "control": control_id,
                       "method": "controlled_reproduction", "actor": None, "files": ["customer.txt"], "context_refs": [],
                       "summary": "Synthetic isolation assertions; no target vulnerability assessment.",
                       "observed_at": observed, "expires_at": observed + 600, "operation": result["operation"]}
        try:
            assessment.record("real-producer", dict(observation, operation="op-" + "0" * 32), controller=True)
        except Blocked:
            pass
        else:
            raise AssertionError("invented execution provenance was accepted")
        assessment.record("real-producer", observation, controller=True)
        report = assessment.report("real-producer")
        require(report["evidence"][0]["valid"] and report["evidence"][0]["origin"] == "m1_controller"
                and report["coverage"]["reviewed"] == 0 and report["security_verdict"] == "not_established",
                "M2 bridge lost provenance or promoted a process exit into security success")
        preserved()
        outcomes.append("M2 real producer provenance, forged operation rejection and no automatic security success")
        try:
            control.execute(control.begin("legitimate")["run"], "check")
        except Blocked:
            pass
        else:
            raise AssertionError("resume reset the aggregate budget")
        outcomes.append("aggregate budget survives resume")

        run = start("process-limit", "pids")
        require(control.execute(run, "check")["result"]["exit_code"] == 0, "process bound fixture failed")
        outcomes.append("kernel process ceiling observed")

        for name, mode, timeout, output_limit in (("timeout", "sleep", 2, 4096),
                ("output", "output", 10, 512), ("memory", "memory", 10, 4096)):
            run = start(name, mode, timeout, output_limit)
            fixture.docker.states.clear()
            fixture.docker.attach_seconds = None
            try:
                control.execute(run, "check")
            except Blocked as exc:
                expected = {"timeout": "hard deadline", "output": "output limit", "memory": "memory limit"}
                require(expected[name] in str(exc), name + " blocked for an unrelated reason")
            else:
                raise AssertionError(name + " exceeded its boundary without blocking")
            require(fixture.docker.attach_seconds is not None
                    and fixture.docker.attach_seconds < timeout + 7, name + " attach exceeded its deadline/grace")
            require(len(fixture.docker.states) == 1, name + " workload identity was not observed")
            container_name, state = next(iter(fixture.docker.states.items()))
            if name != "output":
                require(state["Running"] is False and timestamp(state["FinishedAt"])
                        - timestamp(state["StartedAt"]) < timeout + 2,
                        name + " workload exceeded its actual container deadline")
                require(bool(state["OOMKilled"]) == (name == "memory"), "unexpected memory-limit result")
            else:
                operation = container_name.split(fixture.docker.instance + "-", 1)[1]
                require((fixture.store.root / (operation + ".output")).stat().st_size <= output_limit,
                        "output retained beyond its authorized bound")
            require(fixture.store.get("authorization", name)["operation"] is None, "cleanup not verified")
            require(fixture.docker.inspect(container_name) is None, name + " container remains after cleanup")
            preserved()
            outcomes.append(name + " limit enforced and cleanup verified")
            print(json.dumps({"case": name, "result": "passed",
                              "attach_seconds": fixture.docker.attach_seconds}), flush=True)

        for name, revocation in (("cancel", False), ("revoke", True)):
            run = start(name, "sleep", 30)
            errors = []

            def execute():
                try:
                    control.execute(run, "check")
                except BaseException as exc:
                    errors.append(exc)

            thread = threading.Thread(target=execute)
            thread.start()
            operation = wait_running(fixture, name)
            if revocation:
                control.revoke(authorization=name)
            else:
                control.cancel(run)
            thread.join(15)
            require(not thread.is_alive() and len(errors) == 1 and isinstance(errors[0], Blocked),
                    "cancellation/revocation did not terminate active execution")
            require(fixture.docker.inspect(fixture.docker.name(operation)) is None, "cancelled container remains")
            preserved()
            outcomes.append(name + " interrupts real running workload")

        run = start("interrupted", "sleep", 5)
        child = subprocess.Popen([sys.executable, "-I", "-B", str(Path(__file__).resolve()),
            "--docker", str(executable), "--worker", str(fixture.store.root), str(fixture.package), run],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        try:
            operation = wait_running(fixture, "interrupted")
            child.kill()
            child.wait(timeout=10)
            end = time.monotonic() + 10
            while time.monotonic() < end:
                info = fixture.docker.inspect(fixture.docker.name(operation))
                if info is not None and info.get("State", {}).get("Running") is False:
                    break
                time.sleep(0.2)
            else:
                raise AssertionError("container outlived its internal deadline after controller termination")
            require(operation in control.recover()["operations"], "interrupted operation was not recovered")
            require(fixture.docker.inspect(fixture.docker.name(operation)) is None, "recovered container remains")
            require(fixture.store.get("authorization", "interrupted")["calls_used"] == 1, "recovery reset budget")
            preserved()
            outcomes.append("controller death, internal deadline and authenticated recovery")
        finally:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=10)
        print(json.dumps({"result": "passed", "checks": outcomes, "target_sha256": sha256(original),
                          "runtime": fixture.docker.observe()}, indent=2))
    finally:
        os.environ.pop("CYBER_TEST_SECRET", None)
        if isinstance(fixture.docker, Docker):
            fixture.controller.recover()
        fixture.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--docker", required=True, type=Path)
    parser.add_argument("--worker", nargs=3)
    args = parser.parse_args()
    if args.worker:
        state, package, run = args.worker
        store = Store(state, package)
        Controller(store, package, docker=Docker(args.docker, store)).execute(run, "check")
    else:
        run_suite(args.docker)


if __name__ == "__main__":
    main()
