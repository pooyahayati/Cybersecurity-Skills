#!/usr/bin/env python3
"""Trusted bounded broker. k6 sees generated loopback tickets, never target data."""

import http.server
import json
import math
import os
from pathlib import Path
import secrets
import subprocess
from subprocess import Popen as start_generator
import sys
import threading
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from security_runtime.common import canonical, parse, require
from security_runtime.process import bounded_process


def collect_bounded(value, timeout, guard):
    # A socket timeout only bounds inactivity. The separate M4 process also
    # bounds DNS, headers and trickled bodies if this broker loses its parent.
    env = {"PATH": os.defpath}
    for name in ("SYSTEMROOT", "WINDIR", "TEMP", "TMP"):
        if os.name == "nt" and name in os.environ: env[name] = os.environ[name]
    result = bounded_process([sys.executable, "-I", "-B", str(Path(__file__).with_name("web_worker.py"))],
        env, timeout, 16384, guard=guard, input_data=canonical(value))
    require(result["exit_code"] == 0, "bounded request unavailable")
    return parse(result["content"], 16384)


def percentile(values, fraction):
    return sorted(values)[max(0, math.ceil(len(values) * fraction) - 1)] if values else None


def run(value):
    spec, workspace = value["spec"], Path(value["workspace"])
    limits, route = spec["web"]["limits"], spec["web"]["routes"][0]
    deadline = min(time.monotonic() + sum(p["seconds"] for p in spec["phases"]),
                   time.monotonic() + max(0, limits["expires_at"] - time.time()))
    cancelled, lock = threading.Event(), threading.RLock()
    samples, results = [], []
    state = {"phase": None, "count": 0, "offered": 0, "seen": set(), "rejected": 0, "active": 0, "peak": 0, "next": 0.0, "errors": 0, "reason": None, "phase_end": 0.0, "request_deadlines": {}}

    def alive():
        # Parent heartbeat is private and contains no commands. A dead controller
        # loses its authority within one second, even if this child survives.
        try:
            heartbeat = (workspace / "heartbeat").stat().st_mtime
            with lock:
                if any(time.monotonic() >= end for end in state["request_deadlines"].values()):
                    state["reason"] = "abort_threshold"
                    cancelled.set()
            return not cancelled.is_set() and time.time() - heartbeat < 1 and time.monotonic() < deadline
        except OSError:
            return False

    token = secrets.token_hex(24)

    class Broker(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.0"

        def do_GET(self):
            ok = False
            admitted = False
            ticket = self.path.split("/")
            with lock:
                phase = state["phase"]
                valid = (phase is not None and len(ticket) == 4 and ticket[1] == token and ticket[2] == phase["id"]
                    and ticket[3].isascii() and ticket[3].isdecimal() and len(ticket[3]) <= 3
                    and str(int(ticket[3])) == ticket[3] and int(ticket[3]) < phase["requests"]
                    and ticket[3] not in state["seen"] and self.headers.get("Host") == "127.0.0.1:" + str(self.server.server_port))
                if valid:
                    state["seen"].add(ticket[3]); state["offered"] += 1
                else: state["rejected"] += 1
            if valid:
                while alive():
                    with lock:
                        phase = state["phase"]
                        now = time.monotonic()
                        if phase is None or state["count"] >= phase["requests"] or now >= state["phase_end"]: break
                        if state["active"] < phase["concurrency"] and now >= state["next"]:
                            state["count"] += 1
                            state["active"] += 1
                            state["peak"] = max(state["peak"], state["active"])
                            state["next"] = now + 1 / phase["rps"]
                            request_key = (phase["id"], ticket[3])
                            state["request_deadlines"][request_key] = now + min(limits["timeout_seconds"], spec["abort"]["latency_ms"] / 1000)
                            admitted = True
                            break
                    time.sleep(0.005)
                else: phase = None
                if admitted:
                    started = time.monotonic()
                    output = None
                    try:
                        def request_guard():
                            require(alive() and time.monotonic() < state["phase_end"], "request authority ended")
                        output = collect_bounded({"url": route["url"], "method": route["method"], "addresses": spec["web"]["addresses"],
                            "network": spec["web"]["network"], "timeout": limits["timeout_seconds"], "limit": limits["response_bytes"],
                            "credential": value["credential"], "ca": value["ca"]},
                            min(limits["timeout_seconds"], spec["abort"]["latency_ms"] / 1000), request_guard)
                        ok = output["status"] == 200 and output["body_sha256"] == route["body_sha256"]
                    except Exception:
                        pass
                    elapsed = (time.monotonic() - started) * 1000
                    with lock:
                        state["active"] -= 1
                        state["request_deadlines"].pop(request_key, None)
                        state["errors"] += int(not ok)
                        samples.append({"phase": phase["id"], "started": started, "latency_ms": elapsed, "ok": ok,
                            "status": output["status"] if output else None, "bytes": output["body_bytes"] if output else None})
                        if state["errors"] >= spec["abort"]["errors"] or elapsed >= spec["abort"]["latency_ms"] or output and output["status"] in {429, 503}:
                            state["reason"] = "abort_threshold"
                            cancelled.set()
            try:
                self.send_response(200 if ok else 503)
                self.send_header("Content-Length", "0")
                self.end_headers()
            except OSError: pass

        def log_message(self, *_args): pass

    class BrokerServer(http.server.ThreadingHTTPServer):
        def handle_error(self, _request, _address):
            # Never mix traceback text with the closed JSON producer. An
            # unexpected handler failure remains a failed workload result.
            with lock:
                state["reason"] = "broker_error"
                cancelled.set()

    server = BrokerServer(("127.0.0.1", 0), Broker)
    server.daemon_threads = True
    listener = threading.Thread(target=lambda: server.serve_forever(poll_interval=.05), daemon=True)
    listener.start()
    started_all = time.monotonic()
    # Generated static code, no target imports, configuration, extensions or data.
    broker_url = "http://127.0.0.1:" + str(server.server_port) + "/" + token
    try:
        for phase in spec["phases"]:
            if not alive(): break
            start = time.monotonic()
            with lock:
                state.update(phase=phase, count=0, offered=0, seen=set(), rejected=0, active=0, peak=0, phase_end=min(deadline, start + phase["seconds"]))
            options = {"scenarios": {"bounded": {"executor": "shared-iterations", "vus": phase["concurrency"],
                "iterations": phase["requests"], "maxDuration": str(phase["seconds"]) + "s", "gracefulStop": "0s"}},
                "maxRedirects": 0, "discardResponseBodies": True, "noConnectionReuse": True, "noVUConnectionReuse": True}
            script = "import http from 'k6/http';\nimport exec from 'k6/execution';\nexport const options=" + json.dumps(options) + ";\nexport default function(){http.get(" + json.dumps(broker_url + "/" + phase["id"] + "/") + "+exec.scenario.iterationInTest,{redirects:0,timeout:" + json.dumps(str(phase["seconds"]) + "s") + "});}\n"
            (workspace / "load.js").write_text(script, encoding="utf-8")
            env = {"PATH": os.defpath, "HOME": str(workspace), "USERPROFILE": str(workspace), "K6_NO_USAGE_REPORT": "true",
                   "K6_AUTO_EXTENSION_RESOLUTION": "false", "K6_WEB_DASHBOARD": "false", "K6_ADDRESS": "", "K6_LOG_OUTPUT": "none"}
            for name in ("SYSTEMROOT", "WINDIR", "TEMP", "TMP"):
                if os.name == "nt" and name in os.environ: env[name] = os.environ[name]
            process = start_generator([value["binary"], "run", "--quiet", "--no-usage-report", "--address", "", "--config", str(workspace / "empty.json"),
                "--log-output", "none", str(workspace / "load.js")], cwd=workspace, env=env, stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            try:
                while process.poll() is None and alive() and time.monotonic() < state["phase_end"]: time.sleep(0.01)
                if process.poll() is None: process.kill()
                code = process.wait(timeout=5)
                # Abort closes admission; already sent reads may finish within
                # the same deadline. Never lose them from the denominator.
                while state["active"] and time.monotonic() < state["phase_end"] and time.time() - (workspace / "heartbeat").stat().st_mtime < 1:
                    time.sleep(0.01)
            finally:
                if process.poll() is None: process.kill(); process.wait(timeout=5)
            with lock:
                measured = [s for s in samples if s["phase"] == phase["id"]]
                results.append({"id": phase["id"], "planned": phase["requests"], "started": state["count"], "completed": len(measured),
                    "offered": state["offered"], "rejected_tickets": state["rejected"], "not_offered": phase["requests"] - state["offered"],
                    "not_admitted": state["offered"] - state["count"], "unfinished": state["count"] - len(measured),
                    "peak_in_flight": state["peak"], "elapsed_seconds": time.monotonic() - start, "generator_exit": code})
                if len(measured) != phase["requests"] or code != 0 or state["rejected"]:
                    state["reason"] = state["reason"] or "incomplete_workload"
                    cancelled.set()
                state["phase"] = None
        elapsed = time.monotonic() - started_all
        with lock: observations = list(samples)
        latencies = [s["latency_ms"] for s in observations]
        success = sum(s["ok"] for s in observations)
        errors = len(observations) - success
        planned = sum(p["requests"] for p in spec["phases"])
        offered = sum(p["offered"] for p in results)
        admitted = sum(p["started"] for p in results)
        complete = len(observations) == planned and not cancelled.is_set() and len(results) == len(spec["phases"])
        p95 = percentile(latencies, .95)
        overloaded = sum(s["status"] in {429, 503} for s in observations)
        passed = complete and not overloaded and p95 is not None and p95 <= spec["acceptance"]["p95_ms"] and errors / planned <= spec["acceptance"]["error_rate"] and success / elapsed >= spec["acceptance"]["minimum_success_rps"]
        return {"schema_version": 1, "adapter": "k6-broker", "complete": complete, "workload_passed": passed,
            "stop_reason": state["reason"] or ("completed" if complete else "deadline_or_controller_stop"), "planned": planned,
            "offered": offered, "admitted": admitted, "not_offered": planned - offered, "not_admitted": offered - admitted,
            "unfinished": admitted - len(observations), "completed": len(observations), "successful": success, "errors": errors, "overload_responses": overloaded,
            "elapsed_seconds": elapsed, "successful_rps": success / elapsed, "p50_ms": percentile(latencies, .5), "p95_ms": p95,
            "p99_ms": percentile(latencies, .99), "phases": results, "target_resource_saturation": "not_observed",
            "persisted_state": "not_observed", "security_verdict": "not_established"}
    finally:
        cancelled.set()
        server.shutdown()
        server.server_close()
        listener.join(1)


if __name__ == "__main__":
    try:
        value = parse(sys.stdin.buffer.read(8193), 8192)
        # The trusted child must stop even if its controller dies during a socket read.
        timer = threading.Timer(sum(p["seconds"] for p in value["spec"]["phases"]) + 2, lambda: os._exit(124))
        timer.daemon = True
        timer.start()
        print(canonical(run(value)).decode(), flush=True)
        timer.cancel()
    except Exception:
        print('{"status":"blocked"}', flush=True)
        raise SystemExit(1)
