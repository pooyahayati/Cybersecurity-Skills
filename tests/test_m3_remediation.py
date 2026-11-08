import copy
import unittest

from m3_support import ReviewWorld, behavior, ORIGINAL, GOOD
from security_assessment.remediation import behavior_contract
from security_assessment.source_rules import inspect_sources


class RemediationTests(unittest.TestCase):
    def setUp(self): self.w = ReviewWorld()
    def tearDown(self): self.w.close()

    def complete(self):
        proposal, root = self.w.proposal()
        for row in proposal["behavior"]["cases"]:
            original = copy.deepcopy(row["expected"])
            if row["kind"] != "legitimate": original["response"] = row["forbidden_response"]
            self.w.test_record(proposal, row, "original", payload=original)
            self.w.test_record(proposal, row, "candidate", root, row["expected"])
        return proposal, root

    def test_scan_authentic_and_revoked(self):
        self.w.scan()
        self.assertTrue(self.w.control.source_report("demo")["scans"][0]["valid"])
        self.w.runtime.revoke(component="m3")
        self.assertFalse(self.w.control.source_report("demo")["scans"][0]["valid"])

    def test_forged_scan_and_wrong_operation(self):
        with self.assertRaises(ValueError): self.w.control.import_scan("demo", {"id": "scan", "operation": "op-" + "a" * 32})
        op = self.w.execute(["other"], {})
        with self.assertRaises(ValueError): self.w.control.import_scan("demo", {"id": "scan", "operation": op})

    def test_omitted_mounted_source_rejected(self):
        result = inspect_sources({"app.py": (self.w.target / "app.py").read_bytes()})
        op = self.w.execute(["inspect"], result, inputs=["app.py"])
        with self.assertRaises(ValueError): self.w.control.import_scan("demo", {"id": "scan", "operation": op})

    def test_complete_contract_can_be_accepted_without_production_claim(self):
        _, root = self.complete()
        self.assertEqual(self.w.accept()["status"], "accepted_for_declared_model")
        report = self.w.control.source_report("demo")
        self.assertTrue(report["proposals"][0]["accepted"])
        self.assertFalse(report["proposals"][0]["production_verified"])
        self.assertEqual((self.w.target / "app.py").read_text(), ORIGINAL)
        self.assertEqual((root / "app.py").read_text(), GOOD)

    def test_incomplete_fix_cannot_be_accepted(self):
        self.w.proposal()
        with self.assertRaises(ValueError): self.w.accept()

    def test_denied_write_and_legitimate_regression_fail(self):
        for kind in ("legitimate", "denied", "variant"):
            with self.subTest(kind=kind):
                p, root = self.w.proposal(name="fix-" + kind)
                for row in p["behavior"]["cases"]:
                    baseline = copy.deepcopy(row["expected"])
                    if row["kind"] != "legitimate": baseline["response"] = row["forbidden_response"]
                    self.w.test_record(p, row, "original", payload=baseline)
                    result = copy.deepcopy(row["expected"])
                    if row["kind"] == kind: result["state"]["unexpected"] = "unauthorized mutation"
                    self.w.test_record(p, row, "candidate", root, result)
                with self.assertRaises(ValueError): self.w.accept(p["id"])

    def test_changed_candidate_or_original_invalidates_acceptance(self):
        _, root = self.complete()
        self.w.accept()
        (root / "other.py").chmod(0o600)
        (root / "other.py").write_text("changed dependency")
        self.assertFalse(self.w.control.source_report("demo")["proposals"][0]["accepted"])
        (self.w.target / "app.py").write_text(GOOD)
        self.assertFalse(self.w.control.source_report("demo")["source_current"])

    def test_authorization_revocation_invalidates_fix(self):
        self.complete()
        self.w.accept()
        self.w.runtime.revoke(authorization="check-1")
        self.assertFalse(self.w.control.source_report("demo")["proposals"][0]["accepted"])

    def test_export_rejects_overlaps_and_never_overwrites(self):
        self.w.proposal()
        for destination in (self.w.target / "nested", self.w.state.root / "nested", self.w.root / "candidate-fix"):
            with self.assertRaises(ValueError): self.w.control.export("demo", "fix", destination)
        self.assertEqual((self.w.target / "app.py").read_text(), ORIGINAL)

    def test_behavior_requires_real_variants_and_protected_state(self):
        v = behavior()
        v["cases"][-1]["expected"]["state"] = {}
        with self.assertRaises(ValueError): behavior_contract(v)
        v = behavior()
        v["cases"][-1]["request"] = v["cases"][-2]["request"]
        with self.assertRaises(ValueError): behavior_contract(v)

    def test_reports_withhold_source_payloads_and_escape_markdown(self):
        self.w.proposal()
        result = self.w.control.write_source_report("demo")
        for field in ("json", "markdown"):
            raw = (self.w.state.root / result[field]).read_text()
            self.assertNotIn("synthetic-private", raw)
            self.assertNotIn("def security_probe", raw)

    def test_baseline_mismatch_without_prohibited_effect_is_insufficient(self):
        p, root = self.w.proposal()
        for row in p["behavior"]["cases"]:
            baseline = copy.deepcopy(row["expected"])
            if row["kind"] != "legitimate": baseline["response"] = {"error": "unrelated fixture error"}
            self.w.test_record(p, row, "original", payload=baseline)
            self.w.test_record(p, row, "candidate", root, row["expected"])
        with self.assertRaises(ValueError): self.w.accept()

    def test_rejected_finding_and_expired_support_reopen_acceptance(self):
        self.complete()
        self.w.accept()
        self.w.control.decide("demo", {"schema_version": 1, "finding": "finding", "disposition": "needs_validation", "evidence": ["trace"], "counterevidence": [], "reason": "Synthetic contradictory source interpretation needs another review."})
        self.assertFalse(self.w.control.source_report("demo")["proposals"][0]["accepted"])

    def test_report_has_candidate_contract_and_test_identities(self):
        self.complete()
        self.w.accept()
        report = self.w.control.source_report("demo")
        self.assertEqual(report["assessment"], "demo")
        proposal = report["proposals"][0]
        for field in ("original_manifest_sha256", "candidate_manifest_sha256", "behavior_sha256"):
            self.assertEqual(len(proposal[field]), 64)
        self.assertNotEqual(proposal["original_manifest_sha256"], proposal["candidate_manifest_sha256"])
        self.assertTrue(any(t["violation_observed"] for t in proposal["tests"] if t["variant"] == "original"))
        for row in proposal["tests"]:
            self.assertTrue(row["operation"].startswith("op-"))
            self.assertEqual(len(row["producer_sha256"]), 64)
        written = self.w.control.write_source_report("demo")
        markdown = (self.w.state.root / written["markdown"]).read_text()
        self.assertIn(proposal["candidate_manifest_sha256"], markdown)
        self.assertIn("Finding: finding", markdown)


if __name__ == "__main__": unittest.main()
