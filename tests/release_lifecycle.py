#!/usr/bin/env python3
"""Qualify two explicitly reviewed real archives in owned private directories.

This executes first-party installed helpers. It is not an untrusted-package
inspection tool. Supply independently verified baseline and release digests.
No network, global installation, customer target or model is invoked. Retain
the private directory on success and failure; never clean unrelated paths.
"""

import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from security_runtime.package import read_archive
from security_runtime.package_version import channel
from security_runtime.private import private_directory


def digest(data):
    return hashlib.sha256(data).hexdigest()


def access_identity(path):
    """Observe owner/access metadata independently of the package manager."""
    if os.name != "nt":
        info = path.stat()
        return [info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)]
    from ctypes import wintypes
    api = ctypes.WinDLL("advapi32", use_last_error=True)
    api.GetFileSecurityW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD,
        ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    api.GetFileSecurityW.restype = wintypes.BOOL
    needed = wintypes.DWORD()
    api.GetFileSecurityW(str(path), 5, None, 0, ctypes.byref(needed))
    assert 0 < needed.value <= 65536, "cannot observe private access descriptor"
    buffer = ctypes.create_string_buffer(needed.value)
    assert api.GetFileSecurityW(str(path), 5, buffer, len(buffer), ctypes.byref(needed))
    return digest(buffer.raw[:needed.value])


def inventory(root):
    result = {}
    for path in [root, *sorted(root.rglob("*"))]:
        assert not path.is_symlink() and path.resolve().is_relative_to(root)
        assert not getattr(path.lstat(), "st_file_attributes", 0) & 0x400
        assert path.is_file() or path.is_dir()
        result[path.relative_to(root).as_posix()] = {
            "sha256": digest(path.read_bytes()) if path.is_file() else None,
            "access": access_identity(path)}
    return result


def run(baseline, baseline_digest, archive, archive_digest):
    _, old_manifest, old_files = read_archive(baseline, baseline_digest)
    _, new_manifest, new_files = read_archive(archive, archive_digest)
    assert channel(old_manifest["version"]) == "release-candidate"
    assert channel(new_manifest["version"]) == "stable"
    assert old_manifest["source_revision"] != new_manifest["source_revision"]
    private = Path(tempfile.mkdtemp(prefix="cyber-release-lifecycle-")).resolve(strict=True)
    assert not private.is_relative_to(ROOT.resolve())
    print(json.dumps({"private_evidence": str(private)}), flush=True)
    receipts = []
    environment = {k: v for k, v in os.environ.items() if k.upper() in
                   ("SYSTEMROOT", "WINDIR", "COMSPEC", "PATH", "PATHEXT", "TMP", "TEMP", "LANG")}
    command = [sys.executable, "-I", "-B", str(ROOT / "scripts/m6_package.py")]

    def execute(args, name, expected=0):
        outcome = subprocess.run(args, capture_output=True, timeout=90, env=environment)
        number = str(len(receipts) + 1)
        (private / (number + ".stdout")).write_bytes(outcome.stdout)
        (private / (number + ".stderr")).write_bytes(outcome.stderr)
        receipts.append({"operation": name, "exit": outcome.returncode,
            "stdout_sha256": digest(outcome.stdout), "stderr_sha256": digest(outcome.stderr)})
        assert outcome.returncode == expected, "unexpected operation result; inspect private evidence"
        return json.loads(outcome.stdout)

    def cli(*args, expected=0):
        return execute(command + list(map(str, args)), str(args[0]), expected)

    def installed_bytes(target, manifest, files):
        assert all((target / name).read_bytes() == data for name, data in files.items())
        assert json.loads((target / "PACKAGE.json").read_text()) == manifest
        assert {p.relative_to(target).as_posix() for p in target.rglob("*") if p.is_file()} == \
            set(files) | {"PACKAGE.json", ".managed-package.json"}

    def diagnose(options, identity, manifest):
        result = cli("diagnose", *options)
        assert result["installed_archive_sha256"] == identity
        assert result["source_revision"] == manifest["source_revision"]
        assert result["version"] == manifest["version"] and result["integrity_verified"]
        assert result["release_channel"] == channel(manifest["version"])
        assert not result["freshness_verified"] and not result["stable_release"]
        assert result["runtime_readiness"] == "not_established"

    state_program = '''import json,pathlib,sys
package=pathlib.Path(sys.argv[1]);sys.path.insert(0,str(package/'scripts'))
from security_runtime.store import Store
import security_runtime.store as module
assert pathlib.Path(module.__file__).resolve().is_relative_to(package)
state=Store(sys.argv[2],package,initialize=sys.argv[3]=='seed')
expected={'tenant':'synthetic-owner','events':[{'id':'retained-event','value':37}],
          'private_marker':'SYNTHETIC_RELEASE_PRIVATE_61024'}
if sys.argv[3]=='seed':
    with state.transaction() as tx:tx.put('release-fixture','prior-observation',expected)
assert state.get('release-fixture','prior-observation')==expected
print(json.dumps({'authenticated_read':True,'module':str(module.__file__)}))
'''

    def private_probe(package, state, seed=False):
        return execute([sys.executable, "-I", "-B", "-c", state_program,
                        str(package), str(state), "seed" if seed else "read"], "private-state")

    try:
        fresh = private / "fresh-skills"
        fresh.mkdir()
        fresh_options = ("--skills-root", fresh, "--state", private / "fresh-manager")
        cli("install", "--archive", archive, "--sha256", archive_digest, *fresh_options)
        installed_bytes(fresh / "cybersecurity-skills", new_manifest, new_files)
        diagnose(fresh_options, archive_digest, new_manifest)
        cli("uninstall", "--expected-installed-sha256", archive_digest, *fresh_options)
        assert not list(fresh.iterdir())

        skills = private / "upgrade-skills"
        skills.mkdir()
        unrelated = skills / "unrelated-skill"
        unrelated.mkdir()
        (unrelated / "SKILL.md").write_bytes(b"Owned unrelated fixture; preserve exactly.\n")
        unrelated_before = inventory(unrelated)
        manager = private / "upgrade-manager"
        options = ("--skills-root", skills, "--state", manager)
        cli("install", "--archive", baseline, "--sha256", baseline_digest, *options)
        target = skills / "cybersecurity-skills"
        installed_bytes(target, old_manifest, old_files)
        state = private / "existing-private-state"
        private_probe(target, state, seed=True)
        before = inventory(state)
        backup = private_directory(private / "private-state-backup", create=True)
        for path in sorted(state.rglob("*")):
            destination = backup / path.relative_to(state)
            if path.is_dir():
                destination.mkdir(mode=0o700)
            else:
                destination.write_bytes(path.read_bytes())
                if os.name != "nt":
                    destination.chmod(stat.S_IMODE(path.stat().st_mode))
        private_probe(target, backup)
        backup_before = inventory(backup)
        manager_access = access_identity(manager)

        def preserved():
            assert inventory(state) == before, "private state or permissions changed"
            assert inventory(backup) == backup_before, "backup or permissions changed"
            assert inventory(unrelated) == unrelated_before, "unrelated skill changed"
            assert access_identity(manager) == manager_access, "manager access changed"

        def refused(*args):
            owned_before, manager_before = inventory(skills), inventory(manager)
            cli(*args, expected=2)
            assert inventory(skills) == owned_before, "refusal changed owned installation files"
            assert inventory(manager) == manager_before, "refusal changed recovery/cache state"
            preserved()

        update = ("update", "--archive", archive, "--sha256", archive_digest)
        refused(*update, "--expected-installed-sha256", "0" * 64, *options)
        installed_bytes(target, old_manifest, old_files)
        refused("update", "--archive", archive, "--sha256", "0" * 64,
                "--expected-installed-sha256", baseline_digest, *options)
        installed_bytes(target, old_manifest, old_files)
        edited = target / "LICENSE"
        original = edited.read_bytes()
        edited.write_bytes(original + b"\nOwned local edit must survive refusal.\n")
        edited_before = inventory(target)
        refused(*update, "--expected-installed-sha256", baseline_digest, *options)
        assert inventory(target) == edited_before
        preserved()
        # Explicitly restore only this fixture's edit after observing preservation.
        edited.write_bytes(original)
        extra = target / "owned-extra-note.txt"
        extra.write_bytes(b"Owned unmanaged note must survive refusal.\n")
        extra_before = inventory(target)
        refused(*update, "--expected-installed-sha256", baseline_digest, *options)
        assert inventory(target) == extra_before
        preserved()
        assert extra.resolve().parent == target.resolve() and target.parent == skills
        extra.unlink()  # Remove only the known fixture note after the blocked update.

        ready = private / "owned-controller-displaced"
        child_program = '''import pathlib,sys,time
sys.path.insert(0,sys.argv[1])
from security_runtime.package_lifecycle import Manager
original=pathlib.Path.rename
def pause(path,target):
    if path.name.startswith('.cybersecurity-stage-'):
        pathlib.Path(sys.argv[7]).write_text('displaced',encoding='utf-8')
        time.sleep(30)
        raise OSError('owned pause expired without activation')
    return original(path,target)
pathlib.Path.rename=pause
Manager(sys.argv[2],sys.argv[3]).change('update',sys.argv[4],sys.argv[5],sys.argv[6])
'''
        with (private / "killed-controller.stderr").open("wb") as error:
            child = subprocess.Popen([sys.executable, "-I", "-B", "-c", child_program,
                str(ROOT / "scripts"), str(manager), str(skills), str(archive),
                archive_digest, baseline_digest, str(ready)], stdout=subprocess.DEVNULL,
                stderr=error, env=environment, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            try:
                deadline = time.monotonic() + 25
                while not ready.exists() and child.poll() is None and time.monotonic() < deadline:
                    time.sleep(.05)
                assert ready.exists() and child.poll() is None and not target.exists()
                child.kill()
                child.wait(timeout=10)
            finally:
                if child.poll() is None:
                    child.kill()
                    child.wait(timeout=10)
        pending = cli("status", *options)["pending_transaction"]
        assert pending["operation"] == "update"
        assert pending["old"] == baseline_digest and pending["new"] == archive_digest
        refused("diagnose", *options)
        refused("recover", "--transaction", "0" * 32, *options)
        assert cli("status", *options)["pending_transaction"] == pending
        preserved()
        recovered = cli("recover", "--transaction", pending["id"], *options)
        assert recovered["recovery"] == "rolled_back"
        assert recovered["installed_archive_sha256"] == baseline_digest
        installed_bytes(target, old_manifest, old_files)
        private_probe(target, state)
        preserved()

        cli(*update, "--expected-installed-sha256", baseline_digest, *options)
        installed_bytes(target, new_manifest, new_files)
        diagnose(options, archive_digest, new_manifest)
        private_probe(target, state)
        private_probe(target, backup)
        plan = execute([sys.executable, "-I", "-B", str(target / "scripts/security_checklist.py"),
                        "plan", "--format", "json"], "installed-checklist")
        assert len(plan["controls"]) == 36
        assert all(item["outcome"] == "unverified" for item in plan["controls"])
        assert not plan["assessment_performed"] and plan["tool_activation"] == "none"
        preserved()

        cli("update", "--archive", baseline, "--sha256", baseline_digest,
            "--expected-installed-sha256", archive_digest, *options)
        installed_bytes(target, old_manifest, old_files)
        diagnose(options, baseline_digest, old_manifest)
        private_probe(target, state)
        preserved()
        cli(*update, "--expected-installed-sha256", baseline_digest, *options)
        refused("uninstall", "--expected-installed-sha256", baseline_digest, *options)
        installed_bytes(target, new_manifest, new_files)
        preserved()
        cli("uninstall", "--expected-installed-sha256", archive_digest, *options)
        assert not target.exists() and list(skills.iterdir()) == [unrelated]
        private_probe(ROOT.resolve(), state)
        preserved()
        result = {"result": "passed", "platform": sys.platform,
            "baseline_source": old_manifest["source_revision"], "baseline_version": old_manifest["version"],
            "baseline_archive_sha256": baseline_digest, "source_revision": new_manifest["source_revision"],
            "version": new_manifest["version"], "archive_sha256": archive_digest,
            "fresh_install": True, "actual_candidate_upgrade": True, "actual_controller_termination": True,
            "interrupted_upgrade_recovered": True, "explicit_baseline_restoration": True,
            "private_authenticated_state_preserved": True, "private_backup_readable": True,
            "access_metadata_preserved": True, "unrelated_skill_preserved": True,
            "installed_plan_unverified_items": 36, "uninstalled": True,
            "historical_restore_authorizes_stale_execution": False,
            "global_installation": False, "public_release": False, "security_verdict": "not_established",
            "private_evidence": str(private)}
        (private / "result.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(result))
    finally:
        (private / "operations.json").write_text(json.dumps(receipts, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline-archive", type=Path, required=True)
    parser.add_argument("--baseline-sha256", required=True)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--sha256", required=True)
    args = parser.parse_args()
    run(args.baseline_archive.resolve(strict=True), args.baseline_sha256,
        args.archive.resolve(strict=True), args.sha256)
