"""Labels and offline diagnostics cannot promote integrity to security readiness."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from m6_support import ROOT, World, payload
from security_runtime.common import Blocked, canonical, sha256
from security_runtime.package import assemble, verify
from security_runtime.package_diagnostics import diagnose
from security_runtime.package_lifecycle import Manager
from security_runtime.package_version import channel, skill_header


def versioned(files, version):
    files = dict(files)
    project = json.loads(files["config/project.json"])
    old = project["version"]
    project["version"] = version
    files["config/project.json"] = canonical(project)
    files["SKILL.md"] = files["SKILL.md"].replace(("  version: " + old).encode(), ("  version: " + version).encode())
    return files


class ReleaseTests(unittest.TestCase):
    def test_release_lifecycle_accepts_candidate_and_stable_forward_baselines(self):
        from release_lifecycle import validate_release_pair
        for before, after in [("1.0.0-rc.6", "1.0.0"), ("1.0.0", "1.1.0"),
                              ("1.9.9", "1.10.0")]:
            with self.subTest(before=before, after=after):
                validate_release_pair({"version": before, "source_revision": "a" * 40},
                                      {"version": after, "source_revision": "b" * 40})

    def test_release_lifecycle_refuses_invalid_pairs_before_creating_installation(self):
        from release_lifecycle import run
        for before, after, source in [("0.7.0-dev", "1.1.0", "b"),
                ("1.0.0", "1.1.0-rc.1", "b"), ("1.1.0", "1.0.0", "b"),
                ("1.1.0", "1.1.0", "b"), ("1.2.0-rc.1", "1.1.0", "b"),
                ("1.0.0", "1.1.0", "a")]:
            with self.subTest(before=before, after=after, source=source):
                records = [(None, {"version": before, "source_revision": "a" * 40}, {}),
                           (None, {"version": after, "source_revision": source * 40}, {})]
                with patch("release_lifecycle.read_archive", side_effect=records), \
                        patch("release_lifecycle.tempfile.mkdtemp") as create:
                    with self.assertRaises(AssertionError):
                        run(Path("old.zip"), "a" * 64, Path("new.zip"), "b" * 64)
                    create.assert_not_called()

    def test_ambiguous_frontmatter_blocks_packaging_install_and_structure(self):
        import io
        import zipfile
        from validate_project import ValidationError, validate
        files = versioned(payload(), "1.0.0-rc.1")
        original = files["SKILL.md"]
        description = next(line for line in original.split(b"\n") if line.startswith(b"description: "))
        for old, replacement in [
                (b"  version: 1.0.0-rc.1", b"  version: 1.0.0-rc.1\n  version: invalid-floating-latest"),
                (b"name: cybersecurity-skills", b"name: cybersecurity-skills\nname: unrelated"),
                (b"metadata:", b"metadata: {}\nmetadata:"),
                (b"  version: 1.0.0-rc.1", b"  version: '1.0.0-rc.1'"),
                (b"  version: 1.0.0-rc.1", b"  version: 1.0.0-rc.1 # shadow"),
                (description, b"description: :"), (description, b"description: ends-with-colon:"),
                (description, b"description: hidden\x7fcontrol"),
                (description, b"description: hidden\xc2\x85separator"),
                (description, b"description: hidden\xe2\x80\xa8separator")]:
            changed = original.replace(old, replacement)
            self.assertNotEqual(changed, original)
            with self.subTest(replacement=replacement):
                with self.assertRaises(Blocked):
                    assemble({**files, "SKILL.md": changed}, "a" * 40)
                world = World(files)
                try:
                    # Mutate a complete archive and update its inventory digest:
                    # malformed metadata, not a mere hash mismatch, must block.
                    output = io.BytesIO()
                    with zipfile.ZipFile(world.old) as source, zipfile.ZipFile(output, "w") as target:
                        for info in source.infolist():
                            data = source.read(info)
                            if info.filename.endswith("/SKILL.md"):
                                data = changed
                            elif info.filename.endswith("/PACKAGE.json"):
                                manifest = json.loads(data)
                                manifest["files"]["SKILL.md"] = {"sha256": sha256(changed), "size": len(changed)}
                                data = canonical(manifest)
                            target.writestr(info, data)
                    invalid = world.root / "ambiguous.zip"
                    invalid.write_bytes(output.getvalue())
                    manager = Manager(world.state, world.skills, create=True)
                    with self.assertRaises(Blocked):
                        manager.change("install", invalid, sha256(output.getvalue()))
                    self.assertFalse(manager.target.exists())
                    structure = world.root / "structure"
                    structure.mkdir()
                    for name, data in {**files, "SKILL.md": changed}.items():
                        path = structure / name
                        path.parent.mkdir(parents=True, exist_ok=True)
                        path.write_bytes(data)
                    with self.assertRaises(ValidationError):
                        validate(structure)
                finally:
                    world.close()

    def test_host_probe_git_init_cannot_redirect_or_copy_ambient_templates(self):
        from host_discovery import initialize_project
        with tempfile.TemporaryDirectory(prefix="cyber-host-env-") as tmp:
            base = Path(tmp).resolve()
            project, home, foreign, template = [base / name for name in ("project", "home", "foreign", "template")]
            for folder in (project, home, foreign, template):
                folder.mkdir()
            (foreign / "keep").write_bytes(b"unrelated")
            (template / "marker").write_bytes(b"must not copy")
            config = base / "host-config"
            config.write_text('[init]\n bare = true\n templateDir = ' + template.as_posix() + '\n', encoding="utf-8")
            with patch.dict(os.environ, {"GIT_DIR": str(foreign), "GIT_WORK_TREE": str(foreign),
                    "GIT_CONFIG_GLOBAL": str(config), "GIT_CONFIG_SYSTEM": str(config),
                    "GIT_TEMPLATE_DIR": str(template), "GIT_CONFIG_COUNT": "1",
                    "GIT_CONFIG_KEY_0": "init.bare", "GIT_CONFIG_VALUE_0": "true"}):
                env = initialize_project(project, home)
            self.assertEqual({p.name: p.read_bytes() for p in foreign.iterdir()}, {"keep": b"unrelated"})
            self.assertTrue((project / ".git/HEAD").is_file())
            self.assertFalse((project / ".git/marker").exists())
            self.assertNotIn("GIT_DIR", env)
            self.assertNotIn("GIT_CONFIG_COUNT", env)

    def test_supported_labels_preserve_exact_package_identity(self):
        files = payload()
        for version, expected in [("0.7.0-dev", "development"), ("1.0.0-rc.1", "release-candidate"),
                                  ("1.0.0", "stable"), ("2.3.4-rc.12", "release-candidate")]:
            with self.subTest(version=version):
                self.assertEqual(channel(version), expected)
                raw = assemble(versioned(files, version), "a" * 40)
                manifest, _ = verify(raw, sha256(raw))
                self.assertEqual(manifest["version"], version)

    def test_ambiguous_unsupported_or_unbounded_labels_block(self):
        for value in (None, 1, "", "latest", "v1.0.0", "1.00.0", "01.0.0", "1.0.0-rc.0",
                      "1.0.0-rc.01", "1.0.0-rc.1\n", "1.0.0+build", "0.7.0", "1.0.0-dev",
                      "0.07.0-dev", "1.0.0-beta.1", "١.0.0", "1" * 65 + ".0.0"):
            with self.subTest(value=value), self.assertRaises(Blocked):
                channel(value)

    def test_release_contract_cannot_claim_operational_or_omit_support(self):
        files = versioned(payload(), "1.0.0")
        for change in ("operational", "support", "maturity"):
            copy = dict(files)
            if change == "support":
                del copy["docs/RELEASE-READINESS.md"]
            else:
                project = json.loads(copy["config/project.json"])
                project[change] = True if change == "operational" else "fully-qualified"
                copy["config/project.json"] = canonical(project)
            with self.subTest(change=change), self.assertRaises(Blocked):
                assemble(copy, "a" * 40)

    def test_diagnosis_is_offline_preserves_files_and_cannot_promote_trust(self):
        world = World(payload())
        self.addCleanup(world.close)
        manager = Manager(world.state, world.skills, create=True)
        identity = sha256(world.old.read_bytes())
        manager.change("install", world.old, identity)
        before = {p: p.read_bytes() for p in world.root.rglob("*") if p.is_file()}
        with patch("socket.socket", side_effect=AssertionError("network is forbidden")), \
                patch("subprocess.Popen", side_effect=AssertionError("execution is forbidden")):
            result = diagnose(manager)
        self.assertTrue(result["integrity_verified"])
        for name in ("freshness_verified", "publisher_authenticated", "stable_release"):
            self.assertFalse(result[name])
        self.assertEqual(result["runtime_readiness"], "not_established")
        self.assertEqual(result["host_discovery"], "not_checked")
        self.assertEqual(before, {p: p.read_bytes() for p in world.root.rglob("*") if p.is_file()})

    def test_diagnosis_rejects_missing_changed_and_pending_installation(self):
        world = World(payload())
        self.addCleanup(world.close)
        manager = Manager(world.state, world.skills, create=True)
        with self.assertRaises(Blocked):
            diagnose(manager)
        manager.change("install", world.old, sha256(world.old.read_bytes()))
        license_path = manager.target / "LICENSE"
        original = license_path.read_bytes()
        license_path.write_bytes(b"local edit")
        with self.assertRaises(Blocked):
            diagnose(manager)
        self.assertEqual(license_path.read_bytes(), b"local edit")
        license_path.write_bytes(original)
        (manager.state / "transaction.json").write_bytes(b"{}")
        with self.assertRaisesRegex(Blocked, "pending"):
            diagnose(manager)

    def test_reviewed_manager_upgrades_legacy_and_explicitly_restores_without_freshness(self):
        world = World(versioned(payload(), "0.7.0-dev"))
        self.addCleanup(world.close)
        manager = Manager(world.state, world.skills, create=True)
        old = sha256(world.old.read_bytes())
        manager.change("install", world.old, old)
        candidate = world.root / "candidate.zip"
        candidate.write_bytes(assemble(versioned(payload(), "1.0.0-rc.1"), "c" * 40))
        new = sha256(candidate.read_bytes())
        manager.change("update", candidate, new, old)
        self.assertEqual(diagnose(manager)["release_channel"], "release-candidate")
        manager.change("update", world.old, old, new)
        self.assertEqual(diagnose(manager)["release_channel"], "development")
        self.assertFalse(diagnose(manager)["freshness_verified"])

    def test_real_cli_diagnosis_uses_managed_bytes_without_running_candidate(self):
        files = payload()
        files["scripts/m1_control.py"] = b"raise AssertionError('candidate must not run')\n"
        world = World(files)
        self.addCleanup(world.close)
        manager = Manager(world.state, world.skills, create=True)
        manager.change("install", world.old, sha256(world.old.read_bytes()))
        result = subprocess.run([sys.executable, "-I", "-B", str(ROOT / "scripts/m6_package.py"),
            "diagnose", "--state", str(world.state), "--skills-root", str(world.skills)],
            capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(json.loads(result.stdout)["integrity_verified"])
