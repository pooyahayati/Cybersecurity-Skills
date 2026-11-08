"""Effects and legitimate counterparts for M2 evidence/context boundaries."""

import copy
import json
import unittest

from m2_support import ROOT, World, model
from runtime_support import Fixture, source
from security_assessment.service import Assessment
from security_runtime.common import Blocked


class ContextTests(unittest.TestCase):
    def setUp(self):
        self.w = World()
        self.addCleanup(self.w.close)

    def test_declared_absence_does_not_hide_corroborated_ai_or_unknown_controls(self):
        w = self.w
        (w.target / "package.json").write_text(json.dumps({"dependencies": {"openai": "^9.0.0"}}))
        w.spec["source"]["files"].append("package.json")
        w.spec["model"]["capabilities"]["ai"] = {"state": "absent", "basis": "Unverified operator assertion."}
        w.create()
        report = w.control.report("demo")
        routes = {r["module"]: r for r in report["module_routes"]}
        self.assertEqual(routes["ai-security"]["relevance"], "relevant")
        self.assertEqual(routes["resilience"]["relevance"], "unknown")
        self.assertTrue(all(r["execution"] == "not_activated" for r in routes.values()))
        self.assertTrue(any(c["catalog_id"] == "ai" and c["state"] == "not_started" for c in report["controls"]))

    def test_flow_asset_and_actor_changes_invalidate_only_dependent_evidence(self):
        w = self.w; w.create()
        w.control.record("demo", w.observation("unrelated"))
        control = w.control_id("business", actor="owner")
        w.control.record("demo", w.observation("flow", control=control, actor="owner", context_refs=["flow:read-record"]))
        changed = copy.deepcopy(w.spec["model"])
        changed["assets"][0]["revision"] = "f" * 64
        w.control.refresh("demo", {"schema_version": 1, "model": changed, "deployments": w.spec["deployments"]})
        self.assertEqual({e["id"]: e["valid"] for e in w.control.report("demo")["evidence"]}, {"unrelated": True, "flow": False})
        w.control.record("demo", w.observation("new-flow", control=control, actor="owner", context_refs=["flow:read-record"]))
        changed["actors"][1]["kind"] = "administrator"
        w.control.refresh("demo", {"schema_version": 1, "model": changed, "deployments": w.spec["deployments"]})
        validity = {e["id"]: e["valid"] for e in w.control.report("demo")["evidence"]}
        self.assertTrue(validity["unrelated"])
        self.assertFalse(validity["new-flow"])

    def test_evidence_cannot_be_borrowed_from_another_assessment_or_actor(self):
        w = self.w; w.create(); w.control.record("demo", w.observation())
        other = copy.deepcopy(w.spec); other["id"] = "other"
        w.control.create(other)
        with self.assertRaises(Blocked): w.control.add_finding("other", w.finding())
        control = w.control_id("identity", actor="owner")
        evidence = w.observation("owned", control=control, actor="owner")
        w.control.record("demo", evidence)
        bad = w.finding(control=control, evidence=["owned"]); bad["actor"] = "visitor"
        with self.assertRaises(Blocked): w.control.add_finding("demo", bad)
        bad["actor"] = "owner"
        w.control.add_finding("demo", bad)
        self.assertEqual(len(w.control.report("demo")["findings"]), 1)

    def test_malformed_deep_and_aggregate_manifests_retain_gaps(self):
        w = self.w
        (w.target / "package.json").write_bytes(b'{"dependencies":{},"dependencies":{"fake":"1"}}')
        (w.target / "package-lock.json").write_text('[' * 1100 + ']' * 1100)
        w.spec["source"]["files"] += ["package.json", "package-lock.json"]
        for i in range(3):
            directory = w.target / ("part" + str(i)); directory.mkdir()
            (directory / "composer.json").write_text(json.dumps({"require": {"dependency-" + str(j): "1.0.0" for j in range(3000)}}))
            w.spec["source"]["files"].append(directory.name + "/composer.json")
        w.create(); report = w.control.report("demo")
        self.assertTrue(report["discovery"]["inventory_truncated"])
        self.assertLessEqual(len(report["discovery"]["facts"]), 4096)
        self.assertGreaterEqual(len(report["discovery"]["gaps"]), 3)
        self.assertEqual(report["security_verdict"], "not_established")

    def test_catalog_and_engine_changes_require_a_new_assessment(self):
        w = self.w; w.create()
        original = w.control.engine
        w.control.engine = "e" * 64
        with self.assertRaises(Blocked): w.control.report("demo")
        with self.assertRaises(Blocked): w.create()
        w.control.engine = original
        self.assertEqual(w.control.report("demo")["scope"]["mode"], "combined")

    def test_nested_lockfile_versions_are_not_overwritten_by_package_name(self):
        w = self.w
        (w.target / "package-lock.json").write_text(json.dumps({"packages": {
            "node_modules/example": {"version": "1.0.0"},
            "node_modules/outer/node_modules/example": {"version": "2.0.0"}}}))
        w.spec["source"]["files"].append("package-lock.json")
        w.create()
        facts = [f for f in w.control.report("demo")["discovery"]["facts"] if f["name"] == "example"]
        self.assertCountEqual([f["version"] for f in facts], ["1.0.0", "2.0.0"])
        self.assertEqual(len({f["manifest_entry"] for f in facts}), 2)


class ProducerTests(unittest.TestCase):
    def setUp(self):
        self.f = Fixture()
        self.addCleanup(self.f.close)
        self.f.ready()
        self.assessment = Assessment(self.f.store, ROOT)
        self.assessment.create({"schema_version": 1, "id": "producer", "source": {
            "root": str(self.f.target), "files": ["customer.txt"], "revision": None},
            "deployments": [], "model": model(), "redact_values": []})
        self.control_id = next(c["id"] for c in self.assessment.report("producer")["controls"]
                               if c["catalog_id"] == "application" and c["surface"] == "source")

    def operation(self, name="audit", components=None):
        auth = self.f.authorization(name)
        if components: auth["components"] = components
        result = self.f.controller.execute(self.f.begin(auth), "check")
        record = self.f.store.get("operation", result["operation"])
        return {"schema_version": 1, "id": name, "control": self.control_id,
                "method": "controlled_reproduction", "actor": None, "files": ["customer.txt"],
                "context_refs": [], "summary": "Synthetic bounded operation completed; reviewer interprets its assertions.",
                "operation": result["operation"], "observed_at": record["finished_at"], "expires_at": record["finished_at"] + 1800}

    def test_real_controller_transitions_cannot_promote_forged_or_retimed_evidence(self):
        evidence = self.operation()
        wrong = dict(evidence, observed_at=evidence["observed_at"] + 1)
        with self.assertRaises(Blocked): self.assessment.record("producer", wrong, controller=True)
        wrong = dict(evidence, operation="op-" + "0" * 32)
        with self.assertRaises(Blocked): self.assessment.record("producer", wrong, controller=True)
        self.assessment.record("producer", evidence, controller=True)
        report = self.assessment.report("producer")
        self.assertEqual(report["evidence"][0]["origin"], "m1_controller")
        self.assertTrue(report["evidence"][0]["valid"])
        self.assertEqual(report["coverage"]["reviewed"], 0)
        self.assertFalse(report["evidence"][0]["role_identity_verified"])
        # This test uses a fake Docker backend. The real suite tests the bridge
        # separately; neither test claims vulnerability-detection accuracy.

    def test_modified_output_and_revoked_authority_invalidate_existing_evidence(self):
        evidence = self.operation()
        self.assessment.record("producer", evidence, controller=True)
        output = self.f.store.root / (evidence["operation"] + ".output")
        original = output.read_bytes(); output.write_bytes(b"forged!!")
        self.assertFalse(self.assessment.report("producer")["evidence"][0]["valid"])
        output.write_bytes(original)
        self.f.controller.revoke(authorization="audit")
        self.assertFalse(self.assessment.report("producer")["evidence"][0]["valid"])

    def test_nonzero_operation_does_not_satisfy_a_control(self):
        execute = self.f.docker.execute
        def nonzero(*args, **kwargs):
            return dict(execute(*args, **kwargs), exit_code=7)
        self.f.docker.execute = nonzero
        evidence = self.operation()
        self.assessment.record("producer", evidence, controller=True)
        coverage = {"schema_version": 1, "control": self.control_id, "state": "reviewed",
                    "outcome": "satisfied", "reason": "Tool completed but failed.", "evidence": ["audit"]}
        with self.assertRaises(Blocked): self.assessment.coverage("producer", coverage)
        coverage["outcome"] = "failed"
        self.assessment.coverage("producer", coverage)

    def test_same_bytes_from_another_target_cannot_supply_execution_provenance(self):
        other = self.f.base / "other-target"; other.mkdir()
        (other / "customer.txt").write_bytes((self.f.target / "customer.txt").read_bytes())
        auth = self.f.authorization("other", root=str(other))
        result = self.f.controller.execute(self.f.begin(auth), "check")
        evidence = self.operation()
        record = self.f.store.get("operation", result["operation"])
        evidence.update(operation=result["operation"], observed_at=record["finished_at"])
        with self.assertRaises(Blocked): self.assessment.record("producer", evidence, controller=True)
        self.assertEqual(self.assessment.report("producer")["evidence"], [])

    def test_feed_expiry_or_component_revocation_loses_validity(self):
        self.f.controller.enroll(source("rules", "data", ["rules.json"]))
        self.f.publisher.contents["rules"] = {"rules.json": b"{}"}
        self.f.activate("rules")
        evidence = self.operation(components=["analyzer", "rules"])
        evidence["expires_at"] = evidence["observed_at"] + 7200
        self.assessment.record("producer", evidence, controller=True)
        self.assertTrue(self.assessment.report("producer")["evidence"][0]["valid"])
        observed = evidence["observed_at"]
        self.assessment.clock = lambda: observed + 3601
        self.assertFalse(self.assessment.report("producer")["evidence"][0]["valid"])
        self.assessment.clock = lambda: observed + 1
        self.f.controller.revoke(component="analyzer")
        self.assertFalse(self.assessment.report("producer")["evidence"][0]["valid"])

    def test_uncited_mounted_input_cannot_escape_producer_dependency_checks(self):
        other = self.f.target / "other.py"; other.write_text("# original dependency\n")
        auth = self.f.authorization("multi", inputs=["customer.txt", "other.py"])
        result = self.f.controller.execute(self.f.begin(auth), "check")
        record = self.f.store.get("operation", result["operation"])
        evidence = {"schema_version": 1, "id": "multi", "control": self.control_id,
                    "method": "controlled_reproduction", "actor": None, "files": ["customer.txt"],
                    "context_refs": [], "summary": "Cites one file, but the producer mounted two.",
                    "operation": result["operation"], "observed_at": record["finished_at"], "expires_at": record["finished_at"] + 1800}
        # Missing dependency in assessment scope is not enough for provenance.
        with self.assertRaises(Blocked): self.assessment.record("producer", evidence, controller=True)
        self.assessment.create({"schema_version": 1, "id": "all-inputs", "source": {
            "root": str(self.f.target), "files": ["customer.txt", "other.py"], "revision": None},
            "deployments": [], "model": model(), "redact_values": []})
        self.assessment.record("all-inputs", evidence, controller=True)
        self.assertTrue(self.assessment.report("all-inputs")["evidence"][0]["valid"])
        other.write_text("# changed uncited dependency\n")
        self.assertFalse(self.assessment.report("all-inputs")["evidence"][0]["valid"])
        self.assessment.refresh("all-inputs", {"schema_version": 1, "deployments": [], "model": model()})
        with self.assertRaises(Blocked): self.assessment.record("all-inputs", dict(evidence, id="recaptured"), controller=True)


if __name__ == "__main__":
    unittest.main()
