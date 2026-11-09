"""Checklist coverage and non-execution boundaries, not target security tests."""

import contextlib
import copy
import hashlib
import io
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from security_assessment.checklist import load_catalog, markdown_plan, plan, validate_catalog
from security_runtime.common import Blocked
from validate_project import ValidationError, validate
import security_checklist


class ChecklistTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="cyber-checklist-test-")
        self.addCleanup(self.temp.cleanup)
        # Hosted Windows may expose a short-name temporary parent. Resolve the
        # owned fixture, preserving the product's noncanonical-root rejection.
        self.root = Path(self.temp.name).resolve(strict=True) / "package"
        shutil.copytree(ROOT, self.root, ignore=shutil.ignore_patterns(".git", "__pycache__", ".venv", "dist", "build"))
        self.catalog = load_catalog(self.root)
        self.modules = {g["module"] for g in self.catalog["groups"]}
        self.legacy = {g["legacy_control"] for g in self.catalog["groups"]}

    def valid(self, value):
        return validate_catalog(value, self.modules, self.legacy)

    def edit(self, name, mutation):
        path = self.root / name
        value = json.loads(path.read_text(encoding="utf-8"))
        mutation(value)
        path.write_text(json.dumps(value), encoding="utf-8")

    def fingerprint(self):
        return {p.relative_to(self.root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                for p in self.root.rglob("*") if p.is_file()}

    def test_complete_plan_preserves_all_unverified_target_outcomes(self):
        value = plan(self.catalog)
        self.assertEqual({r["id"] for r in value["controls"]}, {f"audit-{i:02}" for i in range(1, 37)})
        self.assertFalse(value["assessment_performed"])
        self.assertEqual(value["security_verdict"], "not_established")
        self.assertEqual(value["tool_activation"], "none")
        for row in value["controls"]:
            self.assertEqual((row["progress"], row["outcome"], row["applicability"]),
                             ("not_started", "unverified", "unknown"))
            self.assertEqual(row["evidence"], [])
            self.assertIsNone(row["scope"])
            self.assertTrue(row["required_evidence"] and row["legitimate_test"] and row["prohibited_test"])
        text = markdown_plan(value)
        self.assertEqual(text.count("Outcome: unverified."), 36)
        self.assertIn("not test results", text)
        self.assertIn(value["catalog_sha256"], text)
        self.assertIn(value["source"]["reviewed_on"], text)
        self.assertEqual(text.count("Next implementation phase:"), 36)
        self.assertEqual(text.count("Source group:"), 36)

    def test_missing_duplicate_and_remapped_source_items_cannot_hide_gaps(self):
        mutations = [lambda d: d["controls"].pop(),
                     lambda d: d["controls"].append(copy.deepcopy(d["controls"][0])),
                     lambda d: d["controls"].__setitem__(1, copy.deepcopy(d["controls"][0])),
                     lambda d: d["controls"][0].update(source_item=2),
                     lambda d: d["controls"][0].update(group="identity"),
                     lambda d: d["source"].update(expected_controls=35)]
        for mutation in mutations:
            value = copy.deepcopy(self.catalog)
            mutation(value)
            with self.subTest(mutation=mutation), self.assertRaises(Blocked):
                self.valid(value)
        value = copy.deepcopy(self.catalog)
        value["controls"].reverse()
        value["groups"].reverse()
        self.valid(value)  # Serialization order is not item identity.

    def test_capability_or_default_cannot_claim_target_success(self):
        mutations = [lambda d: d.update(assessment_default="satisfied"),
                     lambda d: d.update(assessment_performed=True),
                     lambda d: d["controls"][0].update(outcome="passed"),
                     lambda d: d["capabilities"][0].update(state="qualified"),
                     lambda d: d["controls"][0].update(remaining_gap=""),
                     lambda d: d["controls"][0].update(required_evidence=[]),
                     lambda d: d["controls"][0].update(prohibited_test="")]
        mutations += [lambda d, name=name: d["controls"][0].update({name: " \t\n"})
                      for name in ("title", "acceptance", "legitimate_test", "prohibited_test", "remaining_gap")]
        mutations.append(lambda d: d["controls"][0].update(required_evidence=[" \t\n"]))
        for mutation in mutations:
            value = copy.deepcopy(self.catalog)
            mutation(value)
            with self.subTest(mutation=mutation), self.assertRaises(Blocked):
                self.valid(value)

    def test_unknown_links_ambiguous_types_and_executable_fields_block(self):
        mutations = [lambda d: d["controls"][0].update(capabilities=["missing"]),
                     lambda d: d["controls"][0].update(phase="C99"),
                     lambda d: d["groups"][0].update(module="missing"),
                     lambda d: d["groups"][0].update(legacy_control="missing"),
                     lambda d: d.update(schema_version=True),
                     lambda d: d["controls"][0].update(source_item=True),
                     lambda d: d["capabilities"][0].update(command="execute-me"),
                     lambda d: d["capabilities"][0].update(paths=["../outside.py"])]
        for mutation in mutations:
            value = copy.deepcopy(self.catalog)
            mutation(value)
            with self.subTest(mutation=mutation), self.assertRaises(Blocked):
                self.valid(value)

    def test_planning_neither_executes_referenced_code_nor_mutates_package(self):
        marker = Path(self.temp.name) / "executed"
        (self.root / "scripts/security_runtime/web.py").write_text(
            "from pathlib import Path\nPath(" + repr(str(marker)) + ").write_text('unexpected')\n",
            encoding="utf-8")
        before = self.fingerprint()
        with patch("subprocess.Popen", side_effect=AssertionError("process forbidden")), \
             patch("socket.getaddrinfo", side_effect=AssertionError("network forbidden")), \
             patch("socket.socket", side_effect=AssertionError("network forbidden")):
            value = plan(load_catalog(self.root))
            markdown_plan(value)
        self.assertFalse(marker.exists())
        self.assertEqual(before, self.fingerprint())

    def test_project_validation_rejects_bad_catalog_and_missing_support(self):
        self.edit("config/security-checklist.json", lambda d: d["controls"].pop())
        with self.assertRaisesRegex(ValidationError, "checklist"):
            validate(self.root)
        (self.root / "config/security-checklist.json").write_text(json.dumps(self.catalog), encoding="utf-8")
        self.edit("config/security-checklist.json", lambda d: d["capabilities"][0].update(paths=["scripts/missing.py"]))
        with self.assertRaises((ValidationError, Blocked)):
            validate(self.root)
        (self.root / "config/security-checklist.json").write_text(json.dumps(self.catalog), encoding="utf-8")
        (self.root / "scripts/security_assessment/checklist.py").unlink()
        with self.assertRaises(ValidationError):
            validate(self.root)

    def test_deprecated_source_stays_disabled_and_legacy_state_is_unchanged(self):
        self.assertEqual(validate(self.root)["deprecated_sources"], 1)
        legacy_before = (self.root / "config/assessment-controls.json").read_bytes()
        plan(load_catalog(self.root))
        self.assertEqual(legacy_before, (self.root / "config/assessment-controls.json").read_bytes())
        self.edit("config/sources.json", lambda d: next(s for s in d["sources"] if s["status"] == "deprecated").update(enabled=True))
        with self.assertRaisesRegex(ValidationError, "cannot be activated"):
            validate(self.root)

    def test_cli_only_generates_unbound_plans_and_refuses_target_arguments(self):
        for args in (["plan"], ["plan", "--format", "markdown"], ["validate"]):
            output = io.StringIO()
            with contextlib.redirect_stdout(output), patch("socket.socket", side_effect=AssertionError("network forbidden")):
                self.assertEqual(security_checklist.main(args), 0)
            if "markdown" not in args:
                self.assertFalse(json.loads(output.getvalue())["assessment_performed"])
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(security_checklist.main(["plan", "--target", "https://example.invalid"]), 1)
        self.assertFalse(json.loads(output.getvalue())["assessment_performed"])

    def test_actual_installed_cli_works_without_checkout_resources(self):
        from m6_support import World, payload
        from security_runtime.package_lifecycle import Manager

        world = World(payload())
        self.addCleanup(world.close)
        Manager(world.state, world.skills, create=True).change(
            "install", world.old, hashlib.sha256(world.old.read_bytes()).hexdigest())
        installed = world.skills / "cybersecurity-skills"
        before = {p.relative_to(installed): p.read_bytes() for p in installed.rglob("*") if p.is_file()}
        self.assertFalse((installed / "tests").exists())
        for args in (["validate"], ["plan"], ["plan", "--format", "markdown"]):
            result = subprocess.run([sys.executable, "-I", "-B",
                                     str(installed / "scripts/security_checklist.py"), *args],
                                    cwd=world.root, capture_output=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
            if "markdown" in args:
                self.assertEqual(result.stdout.count(b"Outcome: unverified."), 36)
            else:
                value = json.loads(result.stdout)
                self.assertFalse(value["assessment_performed"])
                if args == ["plan"]:
                    self.assertEqual(len(value["controls"]), 36)
        self.assertEqual(before, {p.relative_to(installed): p.read_bytes()
                                  for p in installed.rglob("*") if p.is_file()})


if __name__ == "__main__":
    unittest.main()
