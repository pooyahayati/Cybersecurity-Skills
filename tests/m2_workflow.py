#!/usr/bin/env python3
"""Real CLI, disposable synthetic files, no network or target execution."""

import copy
import json
from pathlib import Path
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from m2_support import ROOT, World


def run():
    world = World()
    try:
        private = world.root / "cli-private"
        command = [sys.executable, "-I", "-B", str(ROOT / "scripts/m2_assess.py"), "--state", str(private)]
        protected = "SYNTHETIC_CUSTOMER_WORKFLOW_84739"
        marker = world.target / "MUST_NOT_RUN"
        (world.target / "app.py").write_text("from pathlib import Path\nPath(" + repr(str(marker)) + ").write_text('UNAUTHORIZED')\n", encoding="utf-8")
        original = {p.name: p.read_bytes() for p in world.target.iterdir()}
        counter = 0

        def cli(*arguments, payload=None, success=True):
            nonlocal counter
            counter += 1
            if payload is not None:
                path = world.root / ("input-" + str(counter) + ".json")
                path.write_text(json.dumps(payload), encoding="utf-8")
                arguments += (str(path),)
            result = subprocess.run(command + list(arguments), capture_output=True, text=True, encoding="utf-8", timeout=30)
            assert protected not in result.stdout + result.stderr, "private fixture leaked in CLI output"
            assert result.returncode == (0 if success else 1), "CLI outcome differs from expected contract"
            return json.loads(result.stdout)

        cli("init")
        plans = {}
        for mode in ("combined", "source_only", "url_only"):
            spec = copy.deepcopy(world.spec)
            spec["id"] = mode.replace("_", "-")
            spec["redact_values"] = [protected]
            if mode == "source_only": spec["deployments"] = []
            if mode == "url_only": spec["source"] = None
            cli("create", payload=spec)
            plans[mode] = cli("plan", spec["id"])
            assert plans[mode]["scope"]["mode"] == mode
            assert plans[mode]["security_verdict"] == "not_established"
        control = next(c["id"] for c in plans["combined"]["controls"] if c["catalog_id"] == "application" and c["surface"] == "source")
        now = time.time()
        evidence = {"schema_version": 1, "id": "source-trace", "control": control, "method": "source_reasoning",
                    "actor": None, "files": ["app.py"], "context_refs": [], "summary": "Synthetic observation " + protected,
                    "observed_at": now, "expires_at": now + 600}
        cli("observe", "combined", payload=dict(evidence, verified=True), success=False)
        cli("observe", "combined", payload=evidence)
        coverage = {"schema_version": 1, "control": control, "state": "reviewed", "outcome": "failed",
                    "reason": "Synthetic source finding needs a scoped fix and retest.", "evidence": ["source-trace"]}
        cli("coverage", "url-only", payload=coverage, success=False)
        cli("coverage", "combined", payload=coverage)
        # Fixture text is independently authored, not a scanner-generated claim.
        finding = world.finding(control=control, evidence=["source-trace"])
        finding["location"] = "app.py:2"
        finding["impact"] += " " + protected
        cli("finding", "combined", payload=finding)
        report = cli("report", "combined")
        for extension in (".json", ".md"):
            content = (private / (report["report"] + extension)).read_text(encoding="utf-8")
            assert protected not in content and str(world.target) not in content
            assert "app.py:2" in content
            assert ("not established" if extension == ".md" else "not_established") in content
        assert original == {p.name: p.read_bytes() for p in world.target.iterdir()}, "target changed during intake/report"
        assert not marker.exists(), "target source executed"
        (world.target / "app.py").write_text("# synthetic source has changed\n", encoding="utf-8")
        changed = cli("plan", "combined")
        assert changed["evidence"][0]["valid"] is False
        assert changed["findings"][0]["disposition"] == "needs_validation"
        cli("coverage", "combined", payload=coverage, success=False)
        assert not marker.exists()
        print(json.dumps({"result": "passed", "scope": "synthetic M2 CLI workflow", "commands": counter,
                          "modes": list(plans), "target_execution": False, "security_assessment": False}))
    finally:
        world.close()


if __name__ == "__main__":
    run()
