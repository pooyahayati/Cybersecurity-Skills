#!/usr/bin/env python3
"""Run unchanged real M1-M5 assertions from an exact managed skill artifact.

The test harness remains in the checkout. Product modules, CLI commands and
worker bytes must resolve to the verified install. Network use is limited to
existing current-publisher preflight and owned loopback fixtures in those suites.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from security_runtime.package import build
from security_runtime.package_lifecycle import Manager
from security_runtime.package_diagnostics import diagnose


def run(docker, revision, trivy_archive=None, k6_archive=None):
    private = Path(tempfile.mkdtemp(prefix="cyber-installed-runtime-")).resolve()
    skills = private / "skills"
    skills.mkdir()
    archive = private / "skill.zip"
    built = build(ROOT, revision, archive)
    manager = Manager(private / "manager", skills, create=True)
    manager.change("install", archive, built["archive_sha256"])
    installed = manager.target
    diagnostic = diagnose(manager)
    assert diagnostic["integrity_verified"] and not diagnostic["freshness_verified"]
    environment = dict(os.environ)
    for name in tuple(environment):
        if name.startswith("CYBER_TEST_"):
            del environment[name]
    environment.update(CYBER_TEST_PACKAGE_ROOT=str(installed),
                       CYBER_TEST_MANIFEST_SHA256=hashlib.sha256((installed / "PACKAGE.json").read_bytes()).hexdigest())
    results = []
    suites = [("docker_integration.py", ["--docker", docker]), ("m2_workflow.py", []),
              ("m3_workflow.py", ["--docker", docker]),
              ("m4_workflow.py", ["--docker", docker] + (["--trivy-archive", trivy_archive] if trivy_archive else [])),
              ("m5_workflow.py", ["--docker", docker] + (["--k6-archive", k6_archive] if k6_archive else []))]
    print(json.dumps({"private_evidence": str(private), "source_revision": revision}), flush=True)
    for script, options in suites:
        name = Path(script).stem
        prefix = private / (name + "-imports")
        environment["CYBER_TEST_IMPORT_RECEIPT"] = str(prefix)
        result = subprocess.run([sys.executable, "-I", "-B", str(ROOT / "tests" / script), *map(str, options)],
                                capture_output=True, env=environment, timeout=600)
        (private / (name + ".stdout")).write_bytes(result.stdout)
        (private / (name + ".stderr")).write_bytes(result.stderr)
        assert result.returncode == 0, script + " failed; retain " + str(private)
        receipts = [json.loads(p.read_text(encoding="utf-8")) for p in private.glob(name + "-imports.*.json")]
        assert receipts and all(r["modules"] for r in receipts), "missing actual installed-module attribution"
        for receipt in receipts:
            assert receipt["package_root"] == str(installed)
            assert all(Path(path).is_relative_to(installed / "scripts") for path in receipt["modules"].values())
        assert manager.status()["installed_archive_sha256"] == built["archive_sha256"]
        results.append({"suite": script, "exit": result.returncode, "attributed_processes": len(receipts),
                        "stdout_sha256": hashlib.sha256(result.stdout).hexdigest(),
                        "stderr_sha256": hashlib.sha256(result.stderr).hexdigest()})
        print(json.dumps(results[-1]), flush=True)
    record = {"result": "passed", "source_revision": revision, "archive_sha256": built["archive_sha256"],
              "payload_files": len(built["manifest"]["files"]), "suites": results,
              "installed_integrity": diagnose(manager), "security_verdict": "not_established"}
    (private / "result.json").write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(record))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--docker", type=Path, required=True)
    parser.add_argument("--revision")
    parser.add_argument("--trivy-archive", type=Path)
    parser.add_argument("--k6-archive", type=Path)
    args = parser.parse_args()
    revision = args.revision or subprocess.check_output(["git", "-C", str(ROOT), "rev-parse", "HEAD"], text=True).strip()
    run(args.docker, revision, args.trivy_archive, args.k6_archive)
