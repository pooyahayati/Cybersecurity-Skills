#!/usr/bin/env python3
"""Real M1 containers plus the public M3 CLI on disposable synthetic source."""

import argparse
import copy
import json
from pathlib import Path
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
import workflow_package
from m3_support import ReviewWorld, ROOT, GOOD, PARTIAL, DENY_ALL, DENY_AFTER_WRITE, ORIGINAL, behavior
from security_runtime.common import canonical, require, sha256
from security_runtime.sandbox import Docker, LABEL


def run_suite(executable):
    world = ReviewWorld(lambda store: Docker(executable, store))
    outcomes = []
    commands = 0
    def cli(command, value=None, extra=(), success=True):
        nonlocal commands
        commands += 1
        args = [sys.executable, "-I", "-B", str(ROOT / "scripts/m3_review.py"), "--state", str(world.state.root), command, "demo"]
        if command == "invalidate":
            args.append(str(extra[0]))
            extra = extra[1:]
        if value is not None:
            request = world.root / ("request-" + str(commands) + ".json")
            request.write_bytes(canonical(value))
            args.append(str(request))
        args.extend(map(str, extra))
        result = subprocess.run(args, capture_output=True, timeout=30, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        require((result.returncode == 0) == success, "CLI result differs from expected outcome")
        require(not result.stderr and b"synthetic-private" not in result.stdout and b"def security_probe" not in result.stdout, "CLI leaked private source or state")
        return json.loads(result.stdout)

    def batch(root, cases):
        world.sequence += 1
        auth_id = "batch-" + str(world.sequence)
        operations = [{"id": row["id"], "component": "m3", "entrypoint": "scripts/m3_worker.py", "interpreter": "python", "arguments": ["probe", "app.py", canonical({"request": row["request"], "state": row["state"]}).decode()], "timeout_seconds": 10, "max_output_bytes": 65536} for row in cases]
        world.runtime.authorize({"id": auth_id, "root": str(root), "inputs": world.spec["source"]["files"], "components": ["m3"], "network": "none", "operations": operations, "limits": {"calls": len(cases), "seconds": 10 * len(cases), "expires_at": time.time() + 600, "memory_mb": 128, "cpus": 0.5, "pids": 32, "tmpfs_mb": 8}})
        run = world.runtime.begin(auth_id)["run"]
        return {row["id"]: world.runtime.execute(run, row["id"])["operation"] for row in cases}

    try:
        original = {p: (world.target / p).read_bytes() for p in world.spec["source"]["files"]}
        # No fake analyzer output: the real read-only worker generates this result.
        operation = world.execute(["inspect"])
        cli("scan", {"id": "static", "operation": operation})
        cli("scan", {"id": "forged", "operation": "op-" + "0" * 32}, success=False)
        cli("observe", world.observation())
        cli("finding", world.finding())
        outcomes.append("real static worker and forged producer rejection")
        cases = behavior()["cases"]
        baseline = batch(world.target, cases)
        for name, source, accepted in (("partial", PARTIAL, False), ("deny-all", DENY_ALL, False), ("deny-after-write", DENY_AFTER_WRITE, False), ("complete", GOOD, True)):
            proposal = {"id": name, "finding": "finding", "rationale": "Synthetic owner and tenant boundary correction.", "replacements": [{"path": "app.py", "before_sha256": sha256(original["app.py"]), "content": source}], "behavior": behavior()}
            cli("propose", proposal)
            root = world.root / ("candidate-" + name)
            cli("export", extra=(name, root))
            candidate = batch(root, cases)
            for row in cases:
                for variant, operations, target in (("original", baseline, None), ("candidate", candidate, str(root))):
                    cli("test", {"proposal": name, "case": row["id"], "variant": variant, "operation": operations[row["id"]], "root": target})
            decision = {"proposal": name, "reviewer": "Real synthetic workflow evaluator", "reason": "Inspected exact subject and frozen finite owner/tenant model.", "oracle_review": "Reviewed the declared response/state seam and original policy; all actual original/candidate observations are imported from M1.", "residual_risk": "No persistent database, malicious-source integrity or deployed-environment verification."}
            cli("accept", decision, success=accepted)
            require({p: (world.target / p).read_bytes() for p in original} == original, "original source changed")
            outcomes.append(name + (" accepted within declared model" if accepted else " rejected by behavioral evidence"))
            print(json.dumps({"case": name, "result": "passed"}), flush=True)
        report = cli("plan")
        require([p["id"] for p in report["proposals"] if p["accepted"]] == ["complete"], "incorrect proposal acceptance")
        cli("report")
        # Relevant evidence expiry invalidates a previously accepted fix.
        cli("invalidate", {"reason": "Synthetic supporting-evidence revocation"}, extra=("trace",))
        require(not any(p["accepted"] for p in cli("plan")["proposals"]), "accepted fix survived invalid supporting evidence")
        require(world.docker.checked(["container", "ls", "--all", "--filter", "label=" + LABEL + ".instance=" + world.docker.instance, "--format", "{{.ID}}"]).strip() == b"", "owned container remains")
        print(json.dumps({"result": "passed", "commands": commands, "real_operations": 26, "scenarios": outcomes, "scope": "synthetic declared serialized model; fixture publisher, real current Docker runtime"}), flush=True)
    finally:
        world.runtime.recover()
        world.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--docker", required=True, type=Path)
    run_suite(parser.parse_args().docker)
