import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from security_runtime.common import Blocked, canonical
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
