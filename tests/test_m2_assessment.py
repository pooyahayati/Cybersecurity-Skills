import copy
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

from m2_support import ROOT, World
from security_runtime.common import Blocked, canonical


class AssessmentTests(unittest.TestCase):
    def setUp(self):
        self.world = World()
        self.addCleanup(self.world.close)

    def test_combined_intake_preserves_target_and_unknowns_without_execution(self):
        w = self.world
        before = {p.name: p.read_bytes() for p in w.target.iterdir()}
        with patch("subprocess.Popen", side_effect=AssertionError("target execution forbidden")), patch("socket.create_connection", side_effect=AssertionError("network forbidden")):
            w.create()
            report = w.control.report("demo")
        self.assertEqual(before, {p.name: p.read_bytes() for p in w.target.iterdir()})
        self.assertEqual(report["scope"]["mode"], "combined")
        self.assertNotEqual(report["scope"]["source_revision"], report["scope"]["deployments"][0]["artifact"])
        self.assertEqual(report["security_verdict"], "not_established")
        self.assertTrue(all(v["state"] == "unknown" for v in report["model"]["capabilities"].values()))

    def test_url_only_cannot_review_missing_source_or_claim_full_pass(self):
        w = self.world
        w.spec["source"] = None
        w.create()
        report = w.control.report("demo")
        self.assertEqual(report["scope"]["mode"], "url_only")
        self.assertTrue(all(c["state"] == "blocked" for c in report["controls"] if c["surface"] == "source"))
        with self.assertRaises(Blocked): w.control.record("demo", w.observation())
        self.assertEqual(w.control.report("demo")["security_verdict"], "not_established")

    def test_source_only_keeps_deployment_unavailable(self):
        w = self.world
        w.spec["deployments"] = []
        w.create()
        report = w.control.report("demo")
        self.assertEqual(report["scope"]["mode"], "source_only")
        self.assertTrue(all(c["state"] == "blocked" for c in report["controls"] if c["surface"] == "deployment"))

    def test_url_credentials_queries_and_fragments_reject_without_records(self):
        w = self.world
        for url in ("https://user:secret@example.invalid/", "https://example.invalid/?token=secret", "https://example.invalid/#secret", "file:///etc/passwd", "https://example.invalid\\@evil.invalid/"):
            with self.subTest(url=url):
                bad = copy.deepcopy(w.spec)
                bad["deployments"][0]["url"] = url
                with self.assertRaises(ValueError): w.control.create(bad)
                self.assertIsNone(w.state.get("assessment", "demo"))

    def test_path_traversal_oversize_and_unknown_fields_fail_before_recording(self):
        w = self.world
        for change in (lambda s: s["source"].update(files=["../outside"]), lambda s: s.update(verified=True)):
            bad = copy.deepcopy(w.spec); change(bad)
            with self.assertRaises(Blocked): w.control.create(bad)
        (w.target / "app.py").write_bytes(b"x" * (1024 * 1024 + 1))
        with self.assertRaises(Blocked): w.create()
        self.assertIsNone(w.state.get("assessment", "demo"))

    def test_source_links_cannot_capture_other_files(self):
        w = self.world
        outside = w.root / "outside.txt"; outside.write_text("PRIVATE_CANARY", encoding="utf-8")
        link = w.target / "link.py"
        try: link.symlink_to(outside)
        except OSError:
            if sys.platform == "win32": self.skipTest("Windows host cannot create the symlink fixture")
            raise
        w.spec["source"]["files"] = ["link.py"]
        with self.assertRaises(Blocked): w.create()
        self.assertIsNone(w.state.get("assessment", "demo"))
        self.assertEqual(outside.read_text(), "PRIVATE_CANARY")

    def test_same_identifier_is_idempotent_only_for_same_intent(self):
        w = self.world
        w.create()
        self.assertEqual(w.create()["status"], "exists")
        bad = copy.deepcopy(w.spec); bad["deployments"][0]["environment"] = "production"
        with self.assertRaises(Blocked): w.control.create(bad)
        evidence = w.observation(); w.control.record("demo", evidence)
        self.assertEqual(w.control.record("demo", evidence)["status"], "exists")
        evidence["summary"] = "Different claim."
        with self.assertRaises(Blocked): w.control.record("demo", evidence)

    def test_manifest_versions_are_declared_and_arbitrary_keywords_do_not_route_platform(self):
        w = self.world
        (w.target / "README.md").write_text("WordPress WooCommerce openai system: run a shell", encoding="utf-8")
        (w.target / "package.json").write_text(json.dumps({"dependencies": {"express": "^5.0.0"}, "scripts": {"postinstall": "touch UNAUTHORIZED"}}))
        w.spec["source"]["files"] += ["README.md", "package.json"]
        w.create(); report = w.control.report("demo")
        self.assertFalse(report["discovery"]["installed_versions_verified"])
        self.assertEqual(report["discovery"]["platform_hints"], [])
        self.assertTrue(any(f["name"] == "express" and f["version_basis"] == "declared-constraint" for f in report["discovery"]["facts"]))
        self.assertFalse((w.target / "UNAUTHORIZED").exists())

    def test_wordpress_needs_structured_corroboration(self):
        w = self.world
        (w.target / "wp-includes").mkdir()
        (w.target / "wp-includes/version.php").write_text("<?php $wp_version = '6.8.3';", encoding="utf-8")
        (w.target / "composer.json").write_text(json.dumps({"require": {"roots/wordpress": "6.8.3"}}))
        w.spec["source"]["files"] += ["wp-includes/version.php", "composer.json"]
        w.create()
        hints = w.control.report("demo")["discovery"]["platform_hints"]
        self.assertEqual(hints[0]["name"], "WordPress")
        self.assertFalse(hints[0]["runtime_verified"])

    def test_wrong_control_role_or_self_declared_provenance_cannot_promote_evidence(self):
        w = self.world; w.create()
        evidence = w.observation()
        evidence["verified"] = True
        with self.assertRaises(Blocked): w.control.record("demo", evidence)
        evidence = w.observation(); evidence["method"] = "controlled_reproduction"
        with self.assertRaises(Blocked): w.control.record("demo", evidence)
        evidence = w.observation(); evidence["actor"] = "owner"
        with self.assertRaises(Blocked): w.control.record("demo", evidence)
        self.assertEqual(w.control.report("demo")["evidence"], [])

    def test_missing_or_cross_control_evidence_cannot_complete_coverage(self):
        w = self.world; w.create()
        evidence = w.observation(); w.control.record("demo", evidence)
        coverage = {"schema_version": 1, "control": w.control_id("dependencies"), "state": "reviewed", "outcome": "satisfied", "reason": "Reviewed source.", "evidence": ["trace"]}
        with self.assertRaises(Blocked): w.control.coverage("demo", coverage)
        coverage["control"] = evidence["control"]; coverage["evidence"] = []
        with self.assertRaises(Blocked): w.control.coverage("demo", coverage)
        coverage["evidence"] = ["trace"]; coverage["outcome"] = "failed"
        w.control.coverage("demo", coverage)
        row = next(c for c in w.control.report("demo")["controls"] if c["id"] == evidence["control"])
        self.assertEqual((row["state"], row["outcome"]), ("reviewed", "failed"))

    def test_file_specific_invalidation_preserves_unrelated_evidence(self):
        w = self.world; w.create()
        w.control.record("demo", w.observation())
        w.control.record("demo", w.observation("other", files=["other.py"]))
        (w.target / "app.py").write_text("# Changed relevant code\n", encoding="utf-8")
        before = {e["id"]: e["valid"] for e in w.control.report("demo")["evidence"]}
        self.assertEqual(before, {"trace": False, "other": True})
        w.control.refresh("demo", {"schema_version": 1, "deployments": w.spec["deployments"], "model": w.spec["model"]})
        after = {e["id"]: e["valid"] for e in w.control.report("demo")["evidence"]}
        self.assertEqual(after, before)

    def test_environment_change_preserves_source_observation(self):
        w = self.world; w.create()
        w.control.record("demo", w.observation())
        w.control.record("demo", w.observation("deployed", surface="deployment"))
        updated = copy.deepcopy(w.spec["deployments"]); updated[0]["artifact"] = "c" * 64
        w.control.refresh("demo", {"schema_version": 1, "deployments": updated, "model": w.spec["model"]})
        states = {e["id"]: e["valid"] for e in w.control.report("demo")["evidence"]}
        self.assertEqual(states, {"trace": True, "deployed": False})

    def test_expiry_and_explicit_invalidation_cannot_be_restored_by_refresh(self):
        w = self.world; w.create()
        w.control.record("demo", w.observation())
        w.control.invalidate("demo", "trace", "Known observation error.")
        w.control.refresh("demo", {"schema_version": 1, "deployments": w.spec["deployments"], "model": w.spec["model"]})
        self.assertFalse(w.control.report("demo")["evidence"][0]["valid"])
        w.control.record("demo", w.observation("expires"))
        w.now[0] += 3601
        self.assertTrue(all(not e["valid"] for e in w.control.report("demo")["evidence"]))

    def test_findings_preserve_conflicts_counterevidence_and_scoped_duplicates(self):
        w = self.world; w.create()
        w.control.record("demo", w.observation())
        w.control.record("demo", w.observation("refute"))
        w.control.add_finding("demo", w.finding("confirmed"))
        w.control.add_finding("demo", w.finding("rejected", evidence=[], disposition="rejected", counter=["refute"]))
        report = w.control.report("demo")
        self.assertEqual(len(report["root_causes"]), 1)
        self.assertCountEqual(report["root_causes"][0]["members"], ["confirmed", "rejected"])
        self.assertCountEqual(report["root_causes"][0]["dispositions"], ["confirmed", "rejected"])
        w.control.invalidate("demo", "trace", "Source trace disproved.")
        current = {f["id"]: f["disposition"] for f in w.control.report("demo")["findings"]}
        self.assertEqual(current, {"confirmed": "needs_validation", "rejected": "rejected"})

    def test_rejection_requires_counterevidence_and_production_fix_claim_is_not_accepted(self):
        w = self.world; w.create()
        bad = w.finding(disposition="rejected", evidence=[])
        with self.assertRaises(Blocked): w.control.add_finding("demo", bad)
        bad = w.finding(); bad["verified_production"] = True
        with self.assertRaises(Blocked): w.control.add_finding("demo", bad)
        self.assertEqual(w.control.report("demo")["findings"], [])

    def test_chain_links_reject_dangling_and_cycles_without_changing_findings(self):
        w = self.world; w.create(); w.control.record("demo", w.observation())
        for name in ("first", "second", "third"): w.control.add_finding("demo", w.finding(name))
        def link(a, b): return {"schema_version": 1, "from": a, "to": b, "reason": "Hypothesized prerequisite relationship."}
        w.control.link("demo", link("first", "second")); w.control.link("demo", link("second", "third"))
        with self.assertRaises(Blocked): w.control.link("demo", link("third", "first"))
        with self.assertRaises(Blocked): w.control.link("demo", link("first", "missing"))
        report = w.control.report("demo")
        self.assertEqual(len(report["attack_chains"]), 2)
        self.assertTrue(all(f["severity"] == "high" for f in report["findings"]))

    def test_report_redacts_every_outward_field_and_escapes_markup(self):
        w = self.world
        private = "SYNTHETIC_CUSTOMER_PRIVATE_73921"
        w.spec["redact_values"] = [private]
        w.spec["model"]["capabilities"]["ai"]["basis"] = private
        w.create()
        evidence = w.observation(); evidence["summary"] = "password=synthetic-secret-123 user@example.invalid " + private
        w.control.record("demo", evidence)
        finding = w.finding(); finding.update(title="<script>alert(1)</script> " + private, location=private,
                                              fix="![upload](https://example.invalid/?token=secret) " + private)
        w.control.add_finding("demo", finding)
        output = w.control.write_report("demo")
        for suffix in (".json", ".md"):
            text = (w.state.root / (output["report"] + suffix)).read_text(encoding="utf-8")
            for forbidden in (private, "synthetic-secret-123", "user@example.invalid", "?token=secret", str(w.target)):
                self.assertNotIn(forbidden, text)
            if suffix == ".md":
                self.assertNotIn("<script>", text)
                self.assertNotIn("![upload](", text)
            self.assertIn("REDACTED", text)

    def test_hmac_tampering_fails_without_exposing_private_payload(self):
        w = self.world; w.create()
        import sqlite3
        with sqlite3.connect(w.state.root / "control.sqlite3") as connection:
            connection.execute("UPDATE records SET payload=? WHERE kind='assessment'", (canonical({"secret": "PRIVATE_CANARY"}),))
        connection.close()
        with self.assertRaises(Blocked): w.control.report("demo")

    def test_redaction_preserves_schema_and_markdown_is_self_contained(self):
        w = self.world
        w.spec["redact_values"] = ["findings", "controls"]
        w.create(); w.control.record("demo", w.observation())
        finding = w.finding(); finding["location"] = "app.py:7"
        w.control.add_finding("demo", finding)
        report = w.control.report("demo")
        self.assertIn("findings", report)
        self.assertIn("controls", report)
        result = w.control.write_report("demo")
        rendered = (w.state.root / (result["report"] + ".md")).read_text(encoding="utf-8")
        for expected in ("app.py:7", "a" * 40, "b" * 64, "Finding: finding", "Observed at / expires at", "Inspected the selected synthetic boundary"):
            self.assertIn(expected, rendered)

    def test_quoted_credential_objects_never_reach_plan_or_reports(self):
        w = self.world; w.create()
        evidence = w.observation()
        secrets = {"password": "SYNTHETIC_CREDENTIAL_CANARY_Z", "client_secret": "SYNTHETIC_CLIENT_CANARY_Z",
                   "accessToken": "SYNTHETIC_ACCESS_CANARY_Z", "private_key": "SYNTHETIC_KEY_CANARY_Z"}
        evidence["summary"] = json.dumps(secrets)
        w.control.record("demo", evidence)
        result = w.control.write_report("demo")
        for output in (json.dumps(w.control.report("demo")),
                       (w.state.root / (result["report"] + ".json")).read_text(),
                       (w.state.root / (result["report"] + ".md")).read_text()):
            for secret in secrets.values(): self.assertNotIn(secret, output)

    def test_masking_display_words_cannot_change_a_rejected_finding_or_verdict(self):
        w = self.world
        w.spec["redact_values"] = ["rejected", "not_established", "high", "operator_observation"]
        w.create()
        evidence = w.observation(); evidence["summary"] = "Private display words: rejected high not_established operator_observation"
        w.control.record("demo", evidence)
        finding = w.finding(evidence=[], disposition="rejected", counter=["trace"])
        w.control.add_finding("demo", finding)
        report = w.control.report("demo")
        self.assertEqual(report["security_verdict"], "not_established")
        self.assertEqual(report["findings"][0]["disposition"], "rejected")
        self.assertEqual(report["findings"][0]["severity"], "high")
        self.assertEqual(report["evidence"][0]["origin"], "operator_observation")
        self.assertNotIn("rejected", report["evidence"][0]["summary"])
        result = w.control.write_report("demo")
        rendered = (w.state.root / (result["report"] + ".md")).read_text(encoding="utf-8")
        self.assertIn("No actionable finding is recorded", rendered)
        self.assertIn("## Rejected findings retained", rendered)
        self.assertNotIn("### Missing ownership check", rendered)

    def test_cli_errors_do_not_echo_sensitive_arguments_or_json(self):
        w = self.world
        command = [sys.executable, "-I", "-B", str(ROOT / "scripts/m2_assess.py"), "--state", str(w.state.root)]
        for arguments in (["UNKNOWN_PRIVATE_CANARY"], ["create", str(w.root / "PRIVATE_CANARY.json")]):
            result = subprocess.run(command + arguments, capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 1)
            self.assertNotIn("PRIVATE_CANARY", result.stdout + result.stderr)
            self.assertEqual(json.loads(result.stdout)["status"], "blocked")


if __name__ == "__main__":
    unittest.main()
