"""Regression tests for actual foundation trust and readiness boundaries."""

from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from validate_project import MAX_FILE_BYTES, ValidationError, validate  # noqa: E402


class FoundationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="cybersecurity-foundation-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "package"
        shutil.copytree(ROOT, self.root, ignore=shutil.ignore_patterns(
            ".git", "__pycache__", ".venv", "build", "dist"))

    def edit(self, name, mutation):
        path = self.root / name
        value = json.loads(path.read_text(encoding="utf-8"))
        mutation(value)
        path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")

    def invalid(self, reason):
        with self.assertRaisesRegex(ValidationError, reason):
            validate(self.root)

    def test_valid_package_is_read_only_and_never_claims_an_audit(self):
        before = {p.relative_to(self.root): p.read_bytes()
                  for p in self.root.rglob("*") if p.is_file()}
        result = validate(self.root)
        after = {p.relative_to(self.root): p.read_bytes()
                 for p in self.root.rglob("*") if p.is_file()}
        self.assertEqual(before, after)
        self.assertEqual(result["result"], "structure_valid")
        self.assertFalse(result["operational_assessment"])
        self.assertFalse(result["freshness_verified"])

    def test_catalog_cannot_activate_an_external_source(self):
        self.edit("config/sources.json", lambda d: d["sources"][0].update(enabled=True))
        self.invalid("cannot be activated")

    def test_candidate_cannot_smuggle_an_executable_command(self):
        self.edit("config/sources.json", lambda d: d["sources"][0].update(command="execute-me"))
        self.invalid("unknown fields")

    def test_no_silent_stale_fallback(self):
        self.edit("config/sources.json", lambda d: d["policy"].update(silent_stale_fallback=True))
        self.invalid("freshness policy")

    def test_catalog_flag_cannot_promote_foundation_to_operational(self):
        self.edit("config/project.json", lambda d: d.update(operational=True))
        self.invalid("operational assessment readiness")

    def test_module_cannot_claim_implemented_execution(self):
        self.edit("config/modules.json", lambda d: d["modules"][0].update(state="implemented"))
        self.invalid("remain guidance")

    def test_duplicate_module_identity_is_rejected(self):
        self.edit("config/modules.json", lambda d: d["modules"].append(d["modules"][0]))
        self.invalid("duplicate module ID")

    def test_ambiguous_json_keys_are_rejected(self):
        (self.root / "config/project.json").write_text(
            '{"schema_version":1,"schema_version":2}', encoding="utf-8")
        self.invalid("duplicate object key")

    def test_boolean_does_not_impersonate_schema_version(self):
        self.edit("config/project.json", lambda d: d.update(schema_version=True))
        self.invalid("unsupported project schema")

    def test_traversal_reference_is_rejected(self):
        (Path(self.temp.name) / "outside.md").write_text("private", encoding="utf-8")
        self.edit("config/modules.json", lambda d: d["modules"][0].update(entrypoint="../outside.md"))
        self.invalid("contained relative path")

    def test_relative_document_links_remain_inside_package(self):
        path = self.root / "docs/ARCHITECTURE.md"
        path.write_text("[Readme](../README.md)\n", encoding="utf-8")
        self.assertEqual(validate(self.root)["result"], "structure_valid")
        path.write_text("[Escape](../../outside.md)\n", encoding="utf-8")
        self.invalid("contained relative path")

    def test_nonstring_file_reference_fails_cleanly(self):
        self.edit("config/modules.json", lambda d: d["modules"][0].update(entrypoint={"path": "SKILL.md"}))
        self.invalid("invalid file reference")

    def test_absolute_and_windows_references_are_rejected(self):
        for value in ("/outside.md", "C:/outside.md", "..\\outside.md"):
            with self.subTest(value=value):
                self.edit("config/modules.json", lambda d: d["modules"][0].update(entrypoint=value))
                self.invalid("contained relative path")

    def test_symlink_escape_is_rejected(self):
        target = Path(self.temp.name) / "outside.md"
        target.write_text("private", encoding="utf-8")
        entry = self.root / "references/modules/architecture.md"
        entry.unlink()
        try:
            entry.symlink_to(target)
        except OSError as exc:
            if sys.platform != "win32":
                raise  # Linux CI must exercise this boundary, not silently skip it.
            self.skipTest(f"host cannot create a symlink: {exc.errno}")
        self.invalid("escapes project root")

    def test_missing_module_and_broken_documentation_link_fail(self):
        path = self.root / "references/modules/architecture.md"
        path.unlink()
        self.invalid("missing or unreadable")
        path.write_text("# Architecture\n\n[missing](missing.md)\n", encoding="utf-8")
        self.invalid("missing or unreadable")

    def test_mismatched_skill_version_fails(self):
        self.edit("config/project.json", lambda d: d.update(version="0.999.0-dev"))
        self.invalid("versions differ")

    def test_noncanonical_source_cannot_masquerade_as_github(self):
        self.edit("config/sources.json", lambda d: d["sources"][0].update(
            repository="https://github.com.example.invalid/owner/project"))
        self.invalid("canonical GitHub")

    def test_oversized_input_is_bounded(self):
        (self.root / "config/project.json").write_bytes(b" " * (MAX_FILE_BYTES + 1))
        self.invalid("file size limit")

    def test_evidence_fingerprint_changes_with_reviewed_guidance(self):
        before = validate(self.root)["inputs_sha256"]
        with (self.root / "references/modules/identity.md").open("a", encoding="utf-8") as stream:
            stream.write("\nAn additional reviewed boundary.\n")
        self.assertNotEqual(before, validate(self.root)["inputs_sha256"])

    def test_cli_failure_has_nonzero_exit_without_echoing_sensitive_input(self):
        (self.root / "config/project.json").write_text("SENSITIVE_CANARY invalid JSON", encoding="utf-8")
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts/validate_project.py"), "--root", str(self.root)],
            capture_output=True, text=True, timeout=15, check=False)
        self.assertEqual(result.returncode, 1)
        self.assertNotIn("SENSITIVE_CANARY", result.stdout + result.stderr)
        self.assertEqual(json.loads(result.stdout)["result"], "invalid_structure")


if __name__ == "__main__":
    unittest.main()
