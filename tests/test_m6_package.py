import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import unittest
from unittest.mock import patch
import warnings
import zipfile

from m6_support import ROOT, World, payload
from security_runtime.common import Blocked, canonical, sha256
from security_runtime.package import (MANIFEST, NAME, assemble, build, read_archive, verify)
from security_runtime.package_lifecycle import Manager


class PackageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.files = payload()

    def setUp(self):
        self.world = World(self.files)
        self.addCleanup(self.world.close)
        self.old = sha256(self.world.old.read_bytes())
        self.new = sha256(self.world.new.read_bytes())
        self.manager = Manager(self.world.state, self.world.skills, create=True)

    def install(self):
        return self.manager.change("install", self.world.old, self.old)

    def edited_zip(self, change):
        with zipfile.ZipFile(self.world.old) as source:
            entries = [(i, source.read(i)) for i in source.infolist()]
        entries = change(entries)
        output = io.BytesIO()
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            with zipfile.ZipFile(output, "w") as target:
                for info, data in entries:
                    target.writestr(info, data)
        return output.getvalue()

    def rejected(self, raw):
        with self.assertRaises((Blocked, zipfile.BadZipFile)):
            verify(raw, sha256(raw))

    def test_reproducible_archive_and_complete_digest_inventory(self):
        raw = self.world.old.read_bytes()
        self.assertEqual(raw, assemble(dict(reversed(list(self.files.items()))), "1" * 40))
        manifest, files = verify(raw, self.old)
        self.assertEqual(files, self.files)
        self.assertEqual(manifest["source_revision"], "1" * 40)
        self.assertEqual(set(manifest["files"]), set(self.files))
        self.assertFalse(any(n.startswith(("tests/", ".git/")) for n in files))

    def test_wrong_archive_and_member_digest_are_refused(self):
        with self.assertRaises(Blocked):
            verify(self.world.old.read_bytes(), "0" * 64)
        raw = self.edited_zip(lambda entries: [(i, b"changed" if i.filename.endswith("/LICENSE") else data)
                                              for i, data in entries])
        self.rejected(raw)

    def test_traversal_absolute_duplicate_and_nonportable_members(self):
        for name in ("../escape", "/absolute", NAME + "/../escape", NAME + "/NUL.txt",
                     NAME + "/docs/extra:stream", NAME + "/docs/extra. "):
            with self.subTest(name=name):
                info = zipfile.ZipInfo(name)
                info.external_attr = (stat.S_IFREG | 0o644) << 16
                self.rejected(self.edited_zip(lambda e: e + [(info, b"x")]))
        self.rejected(self.edited_zip(lambda entries: entries + [entries[0]]))
        self.assertFalse((self.world.root / "escape").exists())

    def test_case_prefix_collisions_links_compression_and_unknown_content(self):
        for files in ({**self.files, "readme.md": b"duplicate"},
                      {**self.files, "docs": b"collision"},
                      {**self.files, "scripts/__pycache__/data.pyc": b"private"}):
            with self.assertRaises(Blocked):
                assemble(files, "1" * 40)
        for mode in (stat.S_IFLNK, stat.S_IFDIR):
            def change(entries):
                entries[0][0].external_attr = (mode | 0o777) << 16
                return entries
            self.rejected(self.edited_zip(change))
        def compressed(entries):
            entries[0][0].compress_type = zipfile.ZIP_DEFLATED
            return entries
        self.rejected(self.edited_zip(compressed))

    def test_manifest_unknown_duplicate_and_mismatched_fields(self):
        for mutation in (lambda d: {**d, "run_hook": "anything"},
                         lambda d: {**d, "source_revision": "main"},
                         lambda d: {**d, "version": "0.99.0-dev"}):
            def edit(entries):
                return [(i, canonical(mutation(json.loads(data))) if i.filename.endswith("/" + MANIFEST) else data)
                        for i, data in entries]
            self.rejected(self.edited_zip(edit))
        def duplicate(entries):
            return [(i, data[:-1] + b',"schema_version":1}' if i.filename.endswith("/" + MANIFEST) else data)
                    for i, data in entries]
        self.rejected(self.edited_zip(duplicate))

    def test_inspection_and_install_never_run_candidate_code(self):
        marker = self.world.root / "executed"
        malicious = b"raise RuntimeError('candidate code must never run')\n"
        raw = assemble({**self.files, "scripts/postinstall.py": malicious,
                        "scripts/m1_control.py": malicious}, "3" * 40)
        archive = self.world.root / "hooks.zip"
        archive.write_bytes(raw)
        verify(raw, sha256(raw))
        self.manager.change("install", archive, sha256(raw))
        self.assertEqual((self.manager.target / "scripts/postinstall.py").read_bytes(), malicious)
        self.assertFalse(marker.exists())

    def test_install_update_uninstall_preserve_unrelated_skill_and_data(self):
        other = self.world.skills / "unrelated"
        other.mkdir()
        (other / "SKILL.md").write_bytes(b"keep other skill")
        data = self.world.root / "assessment-private.json"
        data.write_bytes(b"keep assessment evidence")
        self.assertEqual(self.install()["installed_archive_sha256"], self.old)
        result = self.manager.change("update", self.world.new, self.new, self.old)
        self.assertEqual(result["installed_archive_sha256"], self.new)
        self.assertEqual(self.manager.current(), self.new)
        self.manager.change("uninstall", expected_installed=self.new)
        self.assertFalse(self.manager.target.exists())
        self.assertEqual((other / "SKILL.md").read_bytes(), b"keep other skill")
        self.assertEqual(data.read_bytes(), b"keep assessment evidence")
        self.assertEqual(list(self.world.skills.iterdir()), [other])

    def test_unmanaged_install_or_wrong_owner_cannot_be_replaced(self):
        self.manager.target.mkdir()
        marker = self.manager.target / "user.txt"
        marker.write_bytes(b"user content")
        with self.assertRaises(Blocked):
            self.install()
        with self.assertRaises(OSError):
            self.manager.change("uninstall", expected_installed=self.old)
        self.assertEqual(marker.read_bytes(), b"user content")

    def test_local_edits_extra_files_and_missing_files_block_mutation(self):
        self.install()
        path = self.manager.target / "README.md"
        original = path.read_bytes()
        for operation in ("update", "uninstall"):
            path.write_bytes(b"local edits")
            with self.assertRaises(Blocked):
                self.manager.change(operation, self.world.new, self.new, self.old)
            self.assertEqual(path.read_bytes(), b"local edits")
            path.write_bytes(original)
        extra = self.manager.target / "customer.txt"
        extra.write_bytes(b"preserve customer data")
        with self.assertRaises(Blocked):
            self.manager.change("uninstall", expected_installed=self.old)
        self.assertEqual(extra.read_bytes(), b"preserve customer data")
        extra.unlink()
        path.unlink()
        with self.assertRaises(Blocked):
            self.manager.change("update", self.world.new, self.new, self.old)
        self.assertFalse(path.exists())
        self.assertFalse((self.world.state / "transaction.json").exists())

    def test_expected_current_identity_and_management_root_are_required(self):
        self.install()
        with self.assertRaises(Blocked):
            self.manager.change("update", self.world.new, self.new, "0" * 64)
        other = self.world.root / "other-skills"
        other.mkdir()
        with self.assertRaises(Blocked):
            Manager(self.world.state, other)
        with self.assertRaises(Blocked):
            Manager(self.world.skills / "private-state", self.world.skills, create=True)
        self.assertEqual(self.manager.current(), self.old)

    def test_interrupted_update_restores_previous_exact_content(self):
        self.install()
        original_rename = Path.rename
        def interrupt(path, target):
            if path.name.startswith(".cybersecurity-stage-"):
                raise OSError("owned injected activation failure")
            return original_rename(path, target)
        with patch.object(Path, "rename", interrupt), self.assertRaises(OSError):
            self.manager.change("update", self.world.new, self.new, self.old)
        journal = self.manager.status()["pending_transaction"]
        with self.assertRaises(Blocked):
            self.manager.change("install", self.world.old, self.old)
        with self.assertRaises(Blocked):
            self.manager.recover("0" * 32)
        result = self.manager.recover(journal["id"])
        self.assertEqual(result["recovery"], "rolled_back")
        self.assertEqual(self.manager.current(), self.old)
        self.assertEqual((self.manager.target / "README.md").read_bytes(), self.files["README.md"])
        self.assertIsNone(self.manager.status()["pending_transaction"])

    def test_recovery_preserves_unexpected_transaction_content(self):
        self.install()
        with patch.object(self.manager, "populate", side_effect=OSError("owned interruption")), self.assertRaises(OSError):
            self.manager.change("update", self.world.new, self.new, self.old)
        journal = self.manager.journal()
        stage, _ = self.manager.paths(journal)
        stage.mkdir()
        (stage / "unowned.txt").write_bytes(b"must not delete")
        with self.assertRaises(Blocked):
            self.manager.recover(journal["id"])
        self.assertEqual((stage / "unowned.txt").read_bytes(), b"must not delete")
        self.assertEqual(self.manager.current(), self.old)

    def test_recovery_can_itself_be_interrupted_and_resumed(self):
        self.install()
        original_rename = Path.rename
        def interrupt(path, target):
            if path.name.startswith(".cybersecurity-stage-"):
                raise OSError("owned activation interruption")
            return original_rename(path, target)
        with patch.object(Path, "rename", interrupt), self.assertRaises(OSError):
            self.manager.change("update", self.world.new, self.new, self.old)
        transaction = self.manager.journal()["id"]
        original_populate = self.manager.populate
        def interrupt_restore(path, expected):
            original_populate(path, expected)
            raise OSError("owned interruption after restoration staging")
        with patch.object(self.manager, "populate", interrupt_restore), self.assertRaises(OSError):
            self.manager.recover(transaction)
        result = self.manager.recover(transaction)
        self.assertEqual(result["recovery"], "rolled_back")
        self.assertEqual(self.manager.current(), self.old)
        self.assertEqual(list(self.world.skills.iterdir()), [self.manager.target])

    def test_process_lock_prevents_a_second_manager_mutation(self):
        other = Manager(self.world.state, self.world.skills)
        with self.manager.locked(), self.assertRaises(Blocked):
            other.change("install", self.world.old, self.old)
        self.assertFalse(self.manager.target.exists())
        self.install()
        self.assertEqual(self.manager.current(), self.old)

    def test_public_isolated_cli_works_and_parse_errors_do_not_echo_private_values(self):
        command = [sys.executable, "-I", "-B", str(ROOT / "scripts/m6_package.py")]
        result = subprocess.run(command + ["--help"], capture_output=True, timeout=20)
        self.assertEqual(result.returncode, 0)
        self.assertIn(b"install", result.stdout)
        canary = "SYNTHETIC_PRIVATE_ARGUMENT_DO_NOT_ECHO"
        result = subprocess.run(command + [canary], capture_output=True, timeout=20)
        self.assertEqual(result.returncode, 2)
        self.assertNotIn(canary.encode(), result.stdout + result.stderr)
        self.assertFalse(self.manager.target.exists())

    def test_symlinked_member_and_root_are_refused_without_touching_target(self):
        outside = self.world.root / "outside.txt"
        outside.write_bytes(b"preserve outside")
        alias = self.world.root / "alias"
        try:
            alias.symlink_to(self.world.skills, target_is_directory=True)
        except OSError:
            self.skipTest("host cannot create symlink fixtures; real Linux suite required")
        with self.assertRaises(Blocked):
            Manager(self.world.state, alias)
        self.install()
        path = self.manager.target / "README.md"
        path.unlink()
        path.symlink_to(outside)
        with self.assertRaises(Blocked):
            self.manager.change("uninstall", expected_installed=self.old)
        self.assertEqual(outside.read_bytes(), b"preserve outside")


class GitBuildTests(unittest.TestCase):
    def setUp(self):
        self.files = payload()
        self.world = World(self.files)
        self.addCleanup(self.world.close)
        self.repo = self.world.root / "source"
        self.repo.mkdir()
        self.env = {k: v for k, v in os.environ.items() if k.upper() in
                    ("SYSTEMROOT", "WINDIR", "PATH", "TMP", "TEMP")}
        self.env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)
        self.git("init")
        for name, data in self.files.items():
            path = self.repo / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        self.git("add", ".")
        self.git("commit", "--no-gpg-sign", "-m", "owned original fixture")
        self.original = self.git("rev-parse", "HEAD").decode().strip()

    def git(self, *args):
        return subprocess.check_output(["git", "-C", str(self.repo),
            "-c", "user.name=Owned Fixture", "-c", "user.email=fixture@example.invalid",
            "-c", "core.hooksPath=" + os.devnull, "-c", "core.autocrlf=false", *args],
            stderr=subprocess.DEVNULL, env=self.env, timeout=30)

    def test_replace_refs_cannot_substitute_named_commit_content(self):
        original_archive = self.world.root / "original.zip"
        build(self.repo, self.original, original_archive)
        (self.repo / "README.md").write_bytes(b"replacement must never impersonate original\n")
        self.git("add", "README.md")
        self.git("commit", "--no-gpg-sign", "-m", "owned replacement fixture")
        replacement = self.git("rev-parse", "HEAD").decode().strip()
        self.git("replace", self.original, replacement)
        result = self.world.root / "after-replace.zip"
        build(self.repo, self.original, result)
        self.assertEqual(result.read_bytes(), original_archive.read_bytes())
        _, manifest, files = read_archive(result, sha256(result.read_bytes()))
        self.assertEqual(manifest["source_revision"], self.original)
        self.assertEqual(files["README.md"], self.files["README.md"])

    def test_inherited_git_repository_settings_cannot_redirect_selected_root(self):
        original = self.world.root / "expected.zip"
        build(self.repo, self.original, original)
        foreign = self.world.root / "foreign"
        foreign.mkdir()
        subprocess.run(["git", "-C", str(foreign), "init"], env=self.env,
                       capture_output=True, check=True, timeout=30)
        result = self.world.root / "scoped.zip"
        with patch.dict(os.environ, {"GIT_DIR": str(foreign / ".git"), "GIT_WORK_TREE": str(foreign),
                                      "GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "core.bare", "GIT_CONFIG_VALUE_0": "true"}):
            build(self.repo, self.original, result)
        self.assertEqual(result.read_bytes(), original.read_bytes())

    def test_missing_promisor_object_cannot_trigger_implicit_fetch(self):
        remote = self.world.root / "owned-remote.git"
        self.git("clone", "--bare", "--no-hardlinks", str(self.repo), str(remote))
        self.git("config", "remote.origin.url", str(remote))
        self.git("config", "remote.origin.promisor", "true")
        self.git("config", "remote.origin.partialclonefilter", "blob:none")
        self.git("config", "extensions.partialClone", "origin")
        oid = self.git("rev-parse", self.original + ":README.md").decode().strip()
        object_root = (self.repo / ".git/objects").resolve(strict=True)
        victim = (object_root / oid[:2] / oid[2:]).resolve(strict=True)
        self.assertTrue(victim.is_relative_to(object_root) and victim.is_file())
        victim.chmod(0o600)
        victim.unlink()  # Only an inspected object in this newly owned fixture.
        before = set((object_root / "pack").iterdir())
        output = self.world.root / "must-not-build.zip"
        with self.assertRaises((Blocked, subprocess.SubprocessError)):
            build(self.repo, self.original, output)
        self.assertFalse(output.exists())
        self.assertEqual(set((object_root / "pack").iterdir()), before)


if __name__ == "__main__":
    unittest.main()
