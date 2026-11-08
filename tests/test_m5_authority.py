import copy
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

from m5_support import M5World, ROOT, Server
from m5_workflow import k6_source
from runtime_support import Publisher, acceptance
from security_runtime.common import Blocked, canonical, digest


class ReleaseFixture(Publisher):
    def resolve(self, spec):
        result = super().resolve(spec)
        if spec["id"] == "k6": result["identity"]["label"] = "v1.0.0"
        return result


class AuthorityTests(unittest.TestCase):
    def setUp(self):
        self.server=Server();self.addCleanup(self.server.close)
        self.world=M5World(self.server);self.addCleanup(self.world.close)
        w=self.world
        publisher=ReleaseFixture();publisher.contents=w.publisher.contents;publisher.published_at=w.publisher.published_at
        w.publisher=publisher
        w.runtime.upstream=w.control.load.controller.upstream=w.control.web.controller.upstream=publisher
        source=k6_source();member=source["asset"]["members"][0].replace("{version}","1.0.0")
        publisher.contents["k6"]={member:b"not an executable; unit provenance fixture"}
        w.runtime.enroll(source)
        candidate=w.runtime.prepare("k6")["candidate"]
        w.runtime.review(acceptance(candidate));w.runtime.activate(candidate)

    def authorize(self):
        self.world.control.load_authorize("resilience",self.world.workload())

    def test_stale_unavailable_revoked_and_cancelled_have_zero_effect(self):
        w=self.world;self.authorize()
        w.publisher.unavailable=True
        with self.assertRaises(Blocked):w.control.load_execute("resilience","load")
        self.assertFalse(w.state.get("load-authority","load")["used"])
        w.publisher.unavailable=False;w.publisher.revisions["k6"]="changed"
        with self.assertRaises(Blocked):w.control.load_execute("resilience","load")
        w.publisher.revisions.pop("k6");w.control.load.cancel("load")
        with self.assertRaises(Blocked):w.control.load_execute("resilience","load")
        w.runtime.revoke(component="k6")
        with self.assertRaises(Blocked):w.control.load_authorize("resilience",w.workload("new"))
        self.assertEqual(self.server.calls,[])

    def test_uncertain_execution_spends_intent_and_blocks_overlap(self):
        w=self.world;self.authorize()
        binary="k6.exe" if os.name=="nt" else "k6"
        def process(argv,*args,**kwargs):
            if argv[-1]=="version":return {"exit_code":0,"content":(binary+" v1.0.0 (fixture)\n").encode()}
            raise Blocked("synthetic interrupted worker")
        with patch("security_runtime.load.bounded_process",process):
            with self.assertRaises(Blocked):w.control.load_execute("resilience","load")
        auth=w.state.get("load-authority","load")
        self.assertTrue(auth["used"])
        self.assertEqual(w.state.get("load-operation",auth["operation"])["status"],"uncertain")
        with self.assertRaises(Blocked):w.control.load_execute("resilience","load")
        w.control.load_authorize("resilience",w.workload("overlap"))
        with self.assertRaises(Blocked):w.control.load_execute("resilience","overlap")
        self.assertFalse(w.state.get("load-authority","overlap")["used"])
        self.assertEqual(self.server.calls,[])

    def test_binary_tampering_cannot_be_executed(self):
        w=self.world;self.authorize()
        candidate=w.state.get("active","k6");record=w.state.get("candidate",candidate)
        path=w.state.root/"objects"/candidate/next(iter(record["manifest"]))
        path.chmod(0o600);path.write_bytes(b"replacement")
        with patch("security_runtime.load.bounded_process") as process:
            with self.assertRaises(Blocked):w.control.load_execute("resilience","load")
        process.assert_not_called()
        self.assertEqual(self.server.calls,[])

    def test_slow_version_probe_keeps_origin_lease_for_worker_lifetime(self):
        w = self.world; self.authorize()
        binary = "k6.exe" if os.name == "nt" else "k6"
        def process(argv, *args, **kwargs):
            if argv[-1] == "version":
                w.now[0] += 9
                return {"exit_code": 0, "content": (binary + " v1.0.0 (fixture)\n").encode()}
            w.now[0] += 3  # Beyond the old reservation+phase+5 deadline.
            w.control.load_authorize("resilience", w.workload("overlap"))
            with self.assertRaises(Blocked): w.control.load_execute("resilience", "overlap")
            self.assertFalse(w.state.get("load-authority", "overlap")["used"])
            raise Blocked("synthetic interrupted worker")
        with patch("security_runtime.load.bounded_process", process):
            with self.assertRaises(Blocked): w.control.load_execute("resilience", "load")
        self.assertEqual(self.server.calls, [])

    def test_unfinished_request_tail_cannot_release_origin_lease(self):
        w = self.world; self.authorize()
        binary = "k6.exe" if os.name == "nt" else "k6"
        def process(argv, *args, **kwargs):
            if argv[-1] == "version":
                return {"exit_code": 0, "content": (binary + " v1.0.0 (fixture)\n").encode()}
            return {"exit_code": 0, "content": canonical({"schema_version": 1, "adapter": "k6-broker", "planned": 6,
                    "unfinished": 1, "workload_passed": False})}
        with patch("security_runtime.load.bounded_process", process):
            result = w.control.load_execute("resilience", "load")
        self.assertFalse(result["workload_passed"])
        w.control.load_authorize("resilience", w.workload("overlap"))
        with self.assertRaises(Blocked): w.control.load_execute("resilience", "overlap")
        self.assertFalse(w.state.get("load-authority", "overlap")["used"])
        self.assertEqual(self.server.calls, [])

    def test_outside_credentials_block_before_workload_intent(self):
        w=self.world;self.authorize()
        outside=w.root/"credentials.json";outside.write_bytes(canonical({"sensitive":"fixture"}))
        result=subprocess.run([sys.executable,"-I","-B",str(ROOT/"scripts/m5_review.py"),"--state",str(w.state.root),
            "load","resilience","load","--credentials",str(outside)],capture_output=True,timeout=20)
        self.assertNotEqual(result.returncode,0)
        self.assertNotIn(b"sensitive",result.stdout+result.stderr)
        self.assertFalse(w.state.get("load-authority","load")["used"])
        self.assertEqual(self.server.calls,[])


if __name__=="__main__":unittest.main()
