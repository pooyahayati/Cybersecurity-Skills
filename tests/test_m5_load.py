import copy
import io
from http.server import BaseHTTPRequestHandler
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
import zipfile

from m5_support import FakeGenerator, M5World, Server
from security_runtime.common import Blocked
from security_runtime.load_scope import workload
from security_runtime.load_worker import collect_bounded, run
from security_runtime.common import sha256
from security_runtime.sources import unpack


class LoadTests(unittest.TestCase):
    def exercise(self, server, change=None, heartbeat=True, generator=FakeGenerator):
        world = M5World(server)
        self.addCleanup(world.close)
        spec = world.workload()
        if change: change(spec)
        with tempfile.TemporaryDirectory(prefix="m5-broker-") as directory:
            workspace = Path(directory)
            (workspace / "heartbeat").touch()
            (workspace / "empty.json").write_text("{}")
            done = threading.Event()
            def beat():
                while not done.wait(.05): (workspace / "heartbeat").touch()
            thread = threading.Thread(target=beat, daemon=True)
            if heartbeat: thread.start()
            try:
                with patch("security_runtime.load_worker.start_generator", generator):
                    output = run({"spec": spec, "workspace": directory, "binary": "test-double", "credential": None, "ca": None})
            finally:
                done.set()
                if heartbeat: thread.join(1)
        return output

    def test_actual_reads_obey_rate_count_concurrency_and_body(self):
        calls, active, peak, lock = [], [0], [0], threading.Lock()
        def handler(*_):
            with lock:
                calls.append(time.monotonic()); active[0] += 1; peak[0] = max(peak[0], active[0])
            time.sleep(.13)
            with lock: active[0] -= 1
            return 200, {}, b"safe"
        server = Server(handler); self.addCleanup(server.close)
        admissions = []
        def observed_collect(*args):
            admissions.append(time.monotonic())
            return collect_bounded(*args)
        with patch("security_runtime.load_worker.collect_bounded", observed_collect):
            result = self.exercise(server)
        self.assertTrue(result["complete"] and result["workload_passed"])
        self.assertEqual(len(calls), 6)
        self.assertTrue(1 < peak[0] <= 3)
        # Rate is enforced at collector admission. TCP scheduling may bunch
        # arrivals at the independent listener; it cannot prove admission times.
        self.assertTrue(all(b-a >= .045 for a,b in zip(admissions,admissions[1:])))
        self.assertTrue(peak[0] <= result["phases"][0]["peak_in_flight"] <= 3)

    def test_trickled_body_stops_at_wall_deadline_without_later_admission(self):
        server = Server(); self.addCleanup(server.close)
        sent = []
        class Trickle(BaseHTTPRequestHandler):
            def do_GET(self):
                server.calls.append(time.monotonic())
                try:
                    self.send_response(200); self.send_header("Content-Length", "20"); self.end_headers()
                    for _ in range(20):
                        self.wfile.write(b"x"); self.wfile.flush(); sent.append(time.monotonic()); time.sleep(.15)
                except OSError: pass
            def log_message(self, *_args): pass
        server.http.RequestHandlerClass = Trickle
        def change(spec):
            spec["phases"][0]["concurrency"] = 1
            spec["abort"]["latency_ms"] = 450
            spec["acceptance"]["p95_ms"] = 400
            spec["web"]["routes"][0]["body_sha256"] = sha256(b"x" * 20)
        result = self.exercise(server, change)
        self.assertFalse(result["workload_passed"])
        self.assertEqual(result["stop_reason"], "abort_threshold")
        self.assertEqual(len(server.calls), 1)
        self.assertLess(result["elapsed_seconds"], 1.5)
        self.assertLess(len(sent), 20)
        self.assertEqual(result["completed"], result["admitted"])

    def test_fast_overload_aborts_and_never_passes(self):
        server = Server(lambda *_: (503, {}, b"safe")); self.addCleanup(server.close)
        result = self.exercise(server)
        self.assertFalse(result["workload_passed"])
        self.assertLess(len(server.calls), 6)
        self.assertEqual(result["stop_reason"], "abort_threshold")
        self.assertGreater(result["overload_responses"], 0)

    def test_replayed_ticket_and_generator_shortfall_cannot_pass(self):
        class Replay(FakeGenerator):
            def tickets(self,count):return [0] * count
        class Shortfall(FakeGenerator):
            def tickets(self,count):return range(count-1)
        for generator in (Replay,Shortfall):
            server=Server()
            try:
                result=self.exercise(server,generator=generator)
                self.assertFalse(result["workload_passed"])
                self.assertLess(len(server.calls),result["planned"])
                self.assertEqual(result["admitted"],len(server.calls))
                self.assertEqual(result["offered"]+result["not_offered"],result["planned"])
                self.assertEqual(result["completed"]+result["unfinished"],result["admitted"])
            finally:server.close()

    def test_redirect_and_oversized_body_never_qualify(self):
        sink = Server(); self.addCleanup(sink.close)
        for handler in (lambda *_:(302,{"Location":sink.url},b"safe"),lambda *_:(200,{},b"x"*2048)):
            server=Server(handler)
            try: self.assertFalse(self.exercise(server)["workload_passed"])
            finally: server.close()
        self.assertEqual(sink.calls, [])

    def test_wrong_pins_have_zero_target_effect(self):
        server = Server(); self.addCleanup(server.close)
        result = self.exercise(server, lambda s:s["web"].update(addresses=["127.0.0.2"]))
        self.assertFalse(result["workload_passed"])
        self.assertEqual(server.calls, [])

    def test_dead_controller_stops_admission(self):
        server=Server(lambda *_:(time.sleep(.2) or 200,{},b"safe"));self.addCleanup(server.close)
        def change(s):
            s["phases"][0].update(requests=30,rps=20,seconds=4)
        started=time.monotonic(); result=self.exercise(server,change,heartbeat=False)
        stopped=len(server.calls);time.sleep(.25)
        self.assertEqual(len(server.calls),stopped)
        self.assertLess(stopped,30)
        self.assertLess(time.monotonic()-started,4)
        self.assertFalse(result["workload_passed"])

    def test_closed_scope_and_heavy_production_rejected(self):
        server=Server(); self.addCleanup(server.close)
        world=M5World(server);self.addCleanup(world.close)
        with world.state.transaction() as tx: case=world.control._case(tx,"resilience")
        spec=world.workload()
        self.assertEqual(workload(spec,case,world.now[0]),(6,5))
        for change in (lambda s:s.update(command="anything"),lambda s:s["web"]["routes"][0].update(method="POST"),
                       lambda s:s["web"]["routes"][0].update(redirects=[server.url+"other"]),
                       lambda s:s["phases"][0].update(rps=True),lambda s:s["phases"][0].update(requests=101),
                       lambda s:s["web"]["limits"].update(body_bytes=1)):
            candidate=copy.deepcopy(spec);change(candidate)
            with self.assertRaises((Blocked,ValueError)):workload(candidate,case,world.now[0])
        production=copy.deepcopy(case);production["scope"]["deployments"][0].update(environment="production",url="https://example.com/")
        spec["web"].update(network="public",addresses=["8.8.8.8"])
        spec["web"]["routes"][0]["url"]="https://example.com/"
        spec["scenario"]="stress"
        with self.assertRaises(Blocked):workload(spec,production,world.now[0])
        self.assertEqual(server.calls,[])

    def test_release_member_templates_resolve_without_traversal(self):
        stream=io.BytesIO()
        with zipfile.ZipFile(stream,"w") as archive:archive.writestr("tool-v2.3.0/bin",b"fixture")
        selection={"format":"zip","members":["tool-v{version}/bin"]}
        self.assertEqual(unpack(stream.getvalue(),selection,1024,"2.3.0"),{"tool-v2.3.0/bin":b"fixture"})
        for version in (None,"../../escape","2/other","2\\other"):
            with self.assertRaises(Blocked):unpack(stream.getvalue(),selection,1024,version)


if __name__ == "__main__":unittest.main()
