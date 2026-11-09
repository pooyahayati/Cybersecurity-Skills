import unittest
from pathlib import Path
from unittest.mock import patch

from m5_support import M5World, Server
from security_runtime.common import Blocked, canonical, sha256
from security_assessment.redaction import redact


class IncidentTests(unittest.TestCase):
    def setUp(self):
        self.server=Server();self.addCleanup(self.server.close)
        self.world=M5World(self.server,files={"incident.txt":b"private fixture content"});self.addCleanup(self.world.close)

    def event(self,kind="observation"):
        return {"id":"case","kind":kind,"files":["incident.txt"],"note":"Bearer private-fixture; <script>untrusted</script>","claimed_at":self.world.now[0]}

    def test_preserved_bytes_append_chain_and_minimized_report(self):
        w=self.world;before=(w.target/"incident.txt").read_bytes()
        w.control.incident("resilience",self.event())
        w.control.incident("resilience",self.event("hypothesis"))
        report=w.control.resilience_report("resilience")
        self.assertTrue(report["incidents"][0]["custody_intact"])
        self.assertEqual([r["sequence"] for r in report["incidents"][0]["events"]],[1,2])
        self.assertNotIn(b"private fixture content",canonical(report));self.assertNotIn(b"private-fixture",canonical(report))
        self.assertEqual((w.target/"incident.txt").read_bytes(),before)
        with w.state.transaction() as tx:events=w.control._resilience(tx,"resilience")["incidents"]["case"]
        self.assertEqual((w.state.root/events[0]["evidence"][0]["object"]).read_bytes(),before)

    def test_tampered_missing_and_broken_sequence_are_visible(self):
        w=self.world;w.control.incident("resilience",self.event())
        with w.state.transaction() as tx:ledger=w.control._resilience(tx,"resilience")
        stored=w.state.root/ledger["incidents"]["case"][0]["evidence"][0]["object"]
        stored.write_bytes(b"tampered")
        self.assertFalse(w.control.resilience_report("resilience")["incidents"][0]["custody_intact"])
        stored.unlink()
        self.assertFalse(w.control.resilience_report("resilience")["incidents"][0]["custody_intact"])

    def test_outside_source_and_changed_original_refused(self):
        value=self.event();value["files"]=["../outside"]
        with self.assertRaises(Blocked):self.world.control.incident("resilience",value)
        (self.world.target/"incident.txt").write_bytes(b"new evidence requires new scope")
        with self.assertRaises(Blocked):self.world.control.incident("resilience",self.event())
        self.assertEqual(list(self.world.state.root.glob("incident-*.bin")),[])

    def test_rejected_multifile_capture_cannot_leak_uncharged_objects(self):
        w=M5World(self.server,files={"one.bin":b"a"*1048576,"two.bin":b"b"*1048576});self.addCleanup(w.close)
        value={"id":"quota","kind":"observation","files":["one.bin"],"note":"synthetic","claimed_at":w.now[0]}
        for _ in range(15):w.control.incident("resilience",value)
        before={p.name:p.stat().st_size for p in w.state.root.glob("incident-*.bin")}
        value["files"]=["one.bin","two.bin"]
        for _ in range(2):
            with self.assertRaises(Blocked):w.control.incident("resilience",value)
            self.assertEqual(before,{p.name:p.stat().st_size for p in w.state.root.glob("incident-*.bin")})
        value["files"]=["two.bin"];w.control.incident("resilience",value)
        self.assertEqual(sum(p.stat().st_size for p in w.state.root.glob("incident-*.bin")),16*1048576)
        with self.assertRaises(Blocked):w.control.incident("resilience",value)

    def test_partial_write_remains_charged_and_visibly_incomplete(self):
        w=self.world;original=Path.open
        def fail(path,*args,**kwargs):
            if path.name.startswith("incident-") and args and args[0]=="xb":raise OSError("synthetic disk failure")
            return original(path,*args,**kwargs)
        with patch.object(Path,"open",fail):
            with self.assertRaises(OSError):w.control.incident("resilience",self.event())
        report=w.control.resilience_report("resilience")["incidents"][0]
        self.assertFalse(report["capture_complete"])
        self.assertGreater(report["reserved_bytes"],0)
        self.assertEqual(report["incomplete_captures"][0]["status"],"failed")
        self.assertEqual(report["events"],[])
        w.control.incident("resilience",self.event())
        self.assertFalse(w.control.resilience_report("resilience")["incidents"][0]["capture_complete"])

    def test_report_redacts_heading_and_display_words_but_preserves_event_kinds(self):
        w = self.world
        kinds = ["observation", "hypothesis", "containment-proposal", "recovery-proposal"]
        w.spec["id"] = "hidden-assessment"
        w.spec["redact_values"] = ["hidden-assessment", *kinds]
        w.control.create(w.spec)
        for kind in kinds:
            event = self.event(kind); event["id"] = "observation"
            w.control.incident(w.spec["id"], event)
        report = w.control.resilience_report(w.spec["id"])
        self.assertEqual(report["assessment"], "[REDACTED]")
        self.assertEqual(report["incidents"][0]["id"], "[REDACTED]")
        self.assertEqual([e["kind"] for e in report["incidents"][0]["events"]], kinds)
        paths = w.control.write_resilience_report(w.spec["id"])
        self.assertNotIn("hidden-assessment", (w.state.root / paths["markdown"]).read_text())
        tokens = {"adapter": "k6-broker", "mode": "recovery", "scenario": "load", "method": "GET",
                  "stop_reason": "abort_threshold", "persisted_state": "not_observed", "status": "failed"}
        for key, value in tokens.items():
            self.assertEqual(redact({key: value, "note": value}, [value]), {key: value, "note": "[REDACTED]"})


if __name__=="__main__":unittest.main()
