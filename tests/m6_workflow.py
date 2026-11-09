#!/usr/bin/env python3
"""Real package CLI, installed operator behavior and killed-process recovery.

Only owned temporary paths are mutated. No network, candidate hooks, external
skills, model/provider calls, customer code or global installation is exercised.
"""

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from security_runtime.common import sha256
from security_runtime.package import assemble, read_archive


def run(root, revision):
    private = Path(tempfile.mkdtemp(prefix="cyber-m6-workflow-")).resolve(strict=True)
    require_root = root.resolve(strict=True)
    assert not private.is_relative_to(require_root)
    skills = private / "skills"
    skills.mkdir()
    other = skills / "unrelated-skill"
    other.mkdir()
    (other / "SKILL.md").write_bytes(b"unrelated skill must stay byte-identical\n")
    assessment = private / "existing-assessment.bin"
    assessment.write_bytes(b"private synthetic assessment state must survive\n")
    preserved = {(other / "SKILL.md"): (other / "SKILL.md").read_bytes(), assessment: assessment.read_bytes()}
    state = private / "manager"
    command = [sys.executable, "-I", "-B", str(root / "scripts/m6_package.py")]
    environment = {k: v for k, v in os.environ.items() if k.upper() in
                   ("SYSTEMROOT", "COMSPEC", "PATH", "PATHEXT", "TMP", "TEMP", "HOME", "LANG")}
    receipts = []

    def cli(*args, code=0):
        outcome = subprocess.run(command + list(map(str, args)), capture_output=True, timeout=90, env=environment)
        receipts.append({"command": str(args[0]), "exit": outcome.returncode,
                         "stdout_sha256": sha256(outcome.stdout), "stderr_sha256": sha256(outcome.stderr)})
        assert outcome.returncode == code, "package CLI outcome differs; private fixture retained at " + str(private)
        return json.loads(outcome.stdout)

    options = ("--skills-root", skills, "--state", state)
    try:
        first, second = private / "first.zip", private / "second.zip"
        built = cli("build", "--root", root, "--revision", revision, "--output", first)
        cli("build", "--root", root, "--revision", revision, "--output", second)
        assert first.read_bytes() == second.read_bytes(), "package is not reproducible"
        identity = built["archive_sha256"]
        _, manifest, files = read_archive(first, identity)
        assert manifest["source_revision"] == revision
        cli("inspect", "--archive", first, "--sha256", "0" * 64, code=2)
        inspected = cli("inspect", "--archive", first, "--sha256", identity)
        assert inspected["integrity_verified"] and not inspected["freshness_verified"]
        cli("install", "--archive", first, "--sha256", identity, *options)
        installed = skills / "cybersecurity-skills"
        for name, data in files.items():
            assert (installed / name).read_bytes() == data
        help_checks = 0
        for script in ("m1_control.py", "m2_assess.py", "m3_review.py", "m4_review.py", "m5_review.py", "m6_package.py"):
            result = subprocess.run([sys.executable, "-I", "-B", str(installed / "scripts" / script), "--help"],
                                    capture_output=True, timeout=30, env=environment)
            assert result.returncode == 0, "installed entrypoint failed"
            help_checks += 1
        result = subprocess.run([sys.executable, "-I", "-B", str(installed / "scripts/validate_project.py")],
                                cwd=installed, capture_output=True, timeout=30, env=environment)
        (private / "installed-structure.stdout").write_bytes(result.stdout)
        (private / "installed-structure.stderr").write_bytes(result.stderr)
        assert result.returncode == 0, "installed package structural check failed"
        # Reuse the existing unchanged assertions; only select the executable path.
        code = ("import pathlib,sys; sys.path.insert(0," + repr(str(root / "tests")) + "); "
                "import m2_workflow; m2_workflow.ROOT=pathlib.Path(" + repr(str(installed)) + "); m2_workflow.run()")
        result = subprocess.run([sys.executable, "-I", "-B", "-c", code],
                                capture_output=True, timeout=90, env=environment)
        (private / "installed-m2.stdout").write_bytes(result.stdout)
        (private / "installed-m2.stderr").write_bytes(result.stderr)
        assert result.returncode == 0, "installed M2 operator workflow failed"
        operator = json.loads(result.stdout)
        assert operator["commands"] == 15 and operator["result"] == "passed"
        successor = private / "successor.zip"
        raw = assemble({**files, "docs/owned-m6-successor.txt": b"Synthetic reviewed update fixture.\n"}, "f" * 40)
        successor.write_bytes(raw)
        new_identity = sha256(raw)
        ready = private / "child-displaced"
        # Pause only our first-party fixture controller after displacement, then
        # actually terminate it. The pause never activates later if its parent dies.
        child_code = '''import pathlib,sys,time
sys.path.insert(0,sys.argv[1])
from security_runtime.package_lifecycle import Manager
original=pathlib.Path.rename
def interrupted(path,target):
    if path.name.startswith('.cybersecurity-stage-'):
        pathlib.Path(sys.argv[7]).write_text('displaced',encoding='utf-8')
        time.sleep(15)
        raise OSError('owned fixture pause expired without activation')
    return original(path,target)
pathlib.Path.rename=interrupted
Manager(sys.argv[2],sys.argv[3]).change('update',sys.argv[4],sys.argv[5],sys.argv[6])
'''
        with (private / "killed-child.stderr").open("wb") as err:
            child = subprocess.Popen([sys.executable, "-I", "-B", "-c", child_code,
                str(root / "scripts"), str(state), str(skills), str(successor), new_identity, identity, str(ready)],
                stdout=subprocess.DEVNULL, stderr=err, env=environment)
            try:
                deadline = time.monotonic() + 15
                while not ready.exists() and child.poll() is None and time.monotonic() < deadline:
                    time.sleep(0.05)
                assert ready.exists() and child.poll() is None and not installed.exists(), "fixture did not reach displaced state"
                child.kill()
                child.wait(timeout=10)
            finally:
                if child.poll() is None:
                    child.kill()
                    child.wait(timeout=10)
        pending = cli("status", *options)["pending_transaction"]
        cli("recover", "--transaction", "0" * 32, *options, code=2)
        recovered = cli("recover", "--transaction", pending["id"], *options)
        assert recovered["recovery"] == "rolled_back" and recovered["installed_archive_sha256"] == identity
        for name, data in files.items():
            assert (installed / name).read_bytes() == data, "recovery changed original package"
        cli("update", "--archive", successor, "--sha256", new_identity,
            "--expected-installed-sha256", identity, *options)
        assert (installed / "docs/owned-m6-successor.txt").read_bytes() == b"Synthetic reviewed update fixture.\n"
        cli("uninstall", "--expected-installed-sha256", identity, *options, code=2)
        assert installed.exists()
        cli("uninstall", "--expected-installed-sha256", new_identity, *options)
        assert not installed.exists() and list(skills.iterdir()) == [other]
        assert all(path.read_bytes() == data for path, data in preserved.items())
        result = {"result": "passed", "source_revision": revision, "archive_sha256": identity,
                  "payload_files": len(files), "package_cli_outcomes": len(receipts),
                  "installed_help_checks": help_checks, "installed_m2_cli_outcomes": operator["commands"],
                  "actual_controller_termination": True, "originals_preserved": True,
                  "reproducible_archive": True, "successor": "explicit synthetic fixture, not a publisher release",
                  "agent_evaluation": "not_run_by_this_workflow", "security_verdict": "not_established"}
        (private / "result.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({**result, "private_evidence": str(private)}))
    finally:
        (private / "cli-receipts.json").write_text(json.dumps(receipts, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--revision")
    arguments = parser.parse_args()
    revision = arguments.revision or subprocess.check_output(
        ["git", "-C", str(arguments.root), "rev-parse", "HEAD"], text=True).strip()
    run(arguments.root.resolve(strict=True), revision)
