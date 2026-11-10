import os
from pathlib import Path
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from security_runtime.common import Blocked, canonical
import security_runtime.process as process_runtime
from security_runtime.process import bounded_process
from security_runtime.sandbox import Docker
from security_runtime.sources import Http


class ProcessBoundaryTests(unittest.TestCase):
    def child(self, code, timeout=3, limit=4096, **kwargs):
        return bounded_process([sys.executable, "-I", "-B", "-c", code], dict(os.environ),
                               timeout, limit, **kwargs)

    def test_small_trickled_output_is_bounded_before_process_exit(self):
        started = time.monotonic()
        with self.assertRaisesRegex(Blocked, "output limit"):
            self.child("import sys,time; print('12345678', flush=True); time.sleep(10)", timeout=5, limit=4)
        self.assertLess(time.monotonic() - started, 3)

    def test_hard_deadline_stops_future_side_effect(self):
        with tempfile.TemporaryDirectory(prefix="cyber-process-") as directory:
            marker = Path(directory) / "not-created"
            code = "import time,pathlib; time.sleep(2); pathlib.Path(" + repr(str(marker)) + ").write_text('bad')"
            with self.assertRaisesRegex(Blocked, "deadline"):
                self.child(code, timeout=0.2)
            self.assertFalse(marker.exists())

    def test_private_pipe_input_does_not_need_command_line_credentials(self):
        value = self.child("import sys; data=sys.stdin.buffer.read(); print(len(data))",
                           input_data=b"synthetic private input")
        self.assertEqual(value["content"].strip(), b"23")

    def test_blocking_guard_cannot_allow_effect_after_child_deadline(self):
        with tempfile.TemporaryDirectory(prefix="cyber-guard-deadline-") as directory:
            marker = Path(directory) / "forbidden-effect"
            code = "import time,pathlib; time.sleep(1.4); pathlib.Path(" + repr(str(marker)) + ").write_text('bad')"
            with self.assertRaisesRegex(Blocked, "deadline"):
                self.child(code, timeout=1, guard=lambda: time.sleep(1.8))
            self.assertFalse(marker.exists())

    def test_late_guard_cannot_certify_unobserved_timely_completion(self):
        original_start = threading.Thread.start
        def delayed_monitor(thread):
            if thread.name == "cyber-process-deadline":time.sleep(0.4)
            return original_start(thread)
        with patch("security_runtime.process.threading.Thread.start", new=delayed_monitor):
            with self.assertRaisesRegex(Blocked, "deadline"):
                self.child("print('completed')", timeout=0.2, guard=lambda: time.sleep(0.5))

    def test_independently_observed_timely_child_survives_slow_guard(self):
        with tempfile.TemporaryDirectory(prefix="cyber-observed-exit-") as directory:
            marker = Path(directory) / "allowed-effect"
            gate = Path(directory) / "guard-started"
            code = "import pathlib,time\ngate=pathlib.Path(" + repr(str(gate)) + ")\nwhile not gate.exists(): time.sleep(0.01)\npathlib.Path(" + repr(str(marker)) + ").write_text('allowed')\nprint('completed')"
            calls = [0]
            def guard():
                calls[0] += 1
                if calls[0] == 1:
                    gate.write_text("proceed")
                    time.sleep(3.5)
            result = self.child(code, timeout=3, guard=guard)
            self.assertEqual(result["exit_code"], 0)
            self.assertEqual(result["content"].strip(), b"completed")
            self.assertEqual(marker.read_text(), "allowed")
            self.assertGreaterEqual(calls[0], 2)

    def test_final_guard_rejection_wins_after_observed_timely_exit(self):
        with tempfile.TemporaryDirectory(prefix="cyber-observed-revoke-") as directory:
            gate = Path(directory) / "guard-started"
            code = "import pathlib,time\ngate=pathlib.Path(" + repr(str(gate)) + ")\nwhile not gate.exists(): time.sleep(0.01)\nprint('completed')"
            calls = [0]
            def guard():
                calls[0] += 1
                if calls[0] == 1:
                    gate.write_text("proceed")
                    time.sleep(3.5)
                else:raise Blocked("owned final revocation")
            with self.assertRaisesRegex(Blocked, "owned final revocation"):
                self.child(code, timeout=3, guard=guard)
            self.assertGreaterEqual(calls[0], 2)

    def test_guarded_timely_effect_and_pipe_result_remain_available(self):
        with tempfile.TemporaryDirectory(prefix="cyber-guard-timely-") as directory:
            marker = Path(directory) / "allowed-effect"
            code = "import pathlib,sys; pathlib.Path(" + repr(str(marker)) + ").write_text('allowed'); print(len(sys.stdin.buffer.read()))"
            result = self.child(code, timeout=3, guard=lambda: time.sleep(0.01), input_data=b"owned input")
            self.assertEqual(result["exit_code"], 0)
            self.assertEqual(result["content"].strip(), b"11")
            self.assertEqual(marker.read_text(), "allowed")

    def test_resumed_main_observer_preserves_independent_timely_exit(self):
        original_require = process_runtime.require
        paused = threading.Event()
        def checked(condition, message):
            original_require(condition, message)
            if message == "process output limit exceeded" and not paused.is_set():
                paused.set()
                time.sleep(1.3)
        with patch.object(process_runtime, "require", new=checked):
            result = self.child("import time; time.sleep(0.05); print('completed')",
                                timeout=1, guard=lambda: None)
        self.assertTrue(paused.is_set())
        self.assertEqual(result["exit_code"], 0)
        self.assertEqual(result["content"].strip(), b"completed")

    def test_monitor_poll_error_stops_effect_while_guard_is_blocked(self):
        with tempfile.TemporaryDirectory(prefix="cyber-monitor-error-") as directory:
            marker = Path(directory) / "forbidden-effect"
            gate = Path(directory) / "guard-started"
            code = "import pathlib,time\ngate=pathlib.Path(" + repr(str(gate)) + ")\nwhile not gate.exists(): time.sleep(0.005)\ntime.sleep(1.4)\npathlib.Path(" + repr(str(marker)) + ").write_text('bad')"
            original_popen = process_runtime.subprocess.Popen
            injected = threading.Event()
            children = []
            def start(*args, **kwargs):
                child = original_popen(*args, **kwargs)
                children.append(child)
                original_poll = child.poll
                def poll():
                    if threading.current_thread().name == "cyber-process-deadline" and gate.exists() and not injected.is_set():
                        injected.set()
                        raise OSError("owned monitor poll failure")
                    return original_poll()
                child.poll = poll
                return child
            def guard():
                gate.write_text("proceed")
                time.sleep(1.8)
            with patch.object(process_runtime.subprocess, "Popen", new=start):
                with self.assertRaisesRegex(Blocked, "cannot enforce process deadline"):
                    self.child(code, timeout=1, guard=guard)
            self.assertTrue(injected.is_set())
            self.assertTrue(gate.exists())
            self.assertFalse(marker.exists())
            self.assertTrue(all(child.poll() is not None for child in children))
            self.assertFalse(any(t.name == "cyber-process-deadline" for t in threading.enumerate()))

    def test_deadline_monitor_start_failure_stops_owned_child(self):
        with tempfile.TemporaryDirectory(prefix="cyber-guard-start-") as directory:
            marker = Path(directory) / "forbidden-effect"
            code = "import time,pathlib; time.sleep(0.4); pathlib.Path(" + repr(str(marker)) + ").write_text('bad')"
            original_start = threading.Thread.start
            def start(thread):
                if thread.name == "cyber-process-deadline":
                    raise RuntimeError("owned monitor startup failure")
                return original_start(thread)
            with patch("security_runtime.process.threading.Thread.start", new=start):
                with self.assertRaisesRegex(RuntimeError, "owned monitor startup failure"):
                    self.child(code, guard=lambda: None)
            time.sleep(0.6)
            self.assertFalse(marker.exists())
            self.assertFalse(any(t.name == "cyber-process-deadline" for t in threading.enumerate()))

    def test_guard_rejection_stops_process(self):
        def stop():
            raise Blocked("revoked fixture")
        with self.assertRaisesRegex(Blocked, "revoked fixture"):
            self.child("import time; time.sleep(10)", guard=stop)

    def test_source_worker_enforces_deadline_even_before_headers(self):
        with tempfile.TemporaryDirectory(prefix="cyber-http-worker-") as directory:
            worker = Path(directory) / "stall.py"
            worker.write_text("import sys,time\nsys.stdin.buffer.read()\ntime.sleep(30)\n", encoding="utf-8")

            def bounded(argv, env, timeout, limit, **kwargs):
                self.assertEqual(timeout, 120)
                self.assertNotIn("synthetic-token", " ".join(argv))
                self.assertIn(b"synthetic-token", kwargs["input_data"])
                return bounded_process(argv[:-1] + [str(worker)], env, 0.2, limit, **kwargs)

            started = time.monotonic()
            with patch("security_runtime.sources.bounded_process", side_effect=bounded):
                with self.assertRaisesRegex(Blocked, "deadline"):
                    Http("synthetic-token").get("https://api.github.com/repos/fixture/project")
            self.assertLess(time.monotonic() - started, 3)

    def test_real_source_worker_rejects_nonofficial_host_without_success(self):
        with self.assertRaises(Blocked):
            Http().get("https://127.0.0.1/never-contacted")

    def test_unconfined_or_custom_daemon_seccomp_cannot_pass_preflight(self):
        backend = Docker.__new__(Docker)
        backend.identity, backend.endpoint = "fixture", "unix:///fixture"
        info = {"MemoryLimit": True, "SwapLimit": True, "CpuCfsQuota": True, "PidsLimit": True,
                "CgroupVersion": "2", "Runtimes": {"runc": {}},
                "SecurityOptions": ["name=seccomp,profile=builtin"]}
        backend.checked = lambda args, **kwargs: canonical(
            {"Server": {"Os": "linux", "Version": "fixture"}, "Client": {"Version": "fixture"}}
            if args[0] == "version" else info)
        self.assertEqual(backend.observe()["server_version"], "fixture")
        for option in ("name=seccomp,profile=unconfined", "name=seccomp,profile=custom", "name=seccomp-pretend"):
            info["SecurityOptions"] = [option]
            with self.subTest(option=option), self.assertRaises(Blocked):
                backend.observe()

    def test_container_created_during_inventory_is_observed_before_deciding(self):
        backend = Docker.__new__(Docker)
        observed = {"Id": "synthetic-container"}
        attempts = iter([{"exit_code": 1, "content": b"not yet present"},
                         {"exit_code": 0, "content": canonical([observed])}])
        backend.command = lambda _args: next(attempts)
        backend.checked = lambda _args: b"fixture-name\n"
        self.assertEqual(backend.inspect("fixture-name"), observed)
        backend.command = lambda _args: {"exit_code": 1, "content": b"unavailable"}
        with self.assertRaises(Blocked):
            backend.inspect("fixture-name")


if __name__ == "__main__":
    unittest.main()
