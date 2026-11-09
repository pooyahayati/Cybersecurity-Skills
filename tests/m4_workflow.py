#!/usr/bin/env python3
"""Real offline scanners, an owned local container and public M4 CLI reads.

Head/worker enrollment uses an explicit synthetic publisher for the unmerged
checkout. Trivy resolves the actual current official release on every preflight;
an optional predownloaded archive is usable only if that live digest matches.
"""

import argparse
import base64
import copy
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
import workflow_package
from m4_support import ROOT, RuntimeWorld, Server, role_plan, roles
from runtime_support import acceptance, source
from security_runtime.common import canonical, parse, read_file, require, sha256
from security_runtime.controller import selected_tree
from security_runtime.sandbox import Docker, LABEL
from security_runtime.sources import GitHub, Http, unpack


class MixedPublisher:
    def __init__(self, fixture, archive):
        self.fixture, self.archive = fixture, archive
        self.official = GitHub(Http(os.environ.get("GITHUB_TOKEN")))

    def resolve(self, spec):
        return self.official.resolve(spec) if spec["id"] == "trivy" else self.fixture.resolve(spec)

    def fetch(self, spec, resolved):
        if spec["id"] != "trivy": return self.fixture.fetch(spec, resolved)
        if self.archive is None: return self.official.fetch(spec, resolved)
        content = read_file(self.archive.parent, self.archive.name, spec["max_download_bytes"])
        expected = resolved["identity"]["asset"]
        require(len(content) == expected["size"] and sha256(content) == expected["sha256"], "provided archive is not the current official release")
        return unpack(content, spec["asset"], spec["max_unpacked_bytes"])


def run_suite(executable, archive=None):
    # Random disposable text, not an account credential or usable private key.
    marker = base64.b64encode(secrets.token_bytes(96))
    fixture_files = {"Dockerfile": b"FROM scratch\nUSER root\n",
        "fixture.pem": b"-----BEGIN PRIVATE KEY-----\n" + marker + b"\n-----END PRIVATE KEY-----\n",
        "trivy.yaml": b"scan:\n  scanners: []\nskip-files: [Dockerfile, fixture.pem]\n",
        "trivy-secret.yaml": b"disable-builtin-rules: true\n",
        ".trivyignore": b"DS002\nAVD-DS-0002\nprivate-key\n",
        "target.py": b"raise RuntimeError('target code must never run during configuration inspection')\n"}
    server = Server(roles())
    world = RuntimeWorld(server, files=fixture_files)
    docker = Docker(executable, world.state)
    world.runtime.docker = docker
    world.control.docker = docker
    publisher = MixedPublisher(world.publisher, archive)
    world.runtime.upstream = publisher
    world.control.web.controller.upstream = publisher
    world.runtime.clock = world.control.clock = world.control.web.clock = time.time
    commands, operations, checks = 0, [], []
    owned, completed = None, False
    owner_label = "cybersecurity-m4-fixture-" + secrets.token_hex(12)

    def cli(command, value=None, extra=(), success=True, assessment="demo"):
        nonlocal commands
        commands += 1
        argv = [sys.executable, "-I", "-B", str(ROOT / "scripts/m4_review.py"), "--state", str(world.state.root), command]
        if command not in {"cancel", "create"}: argv += [assessment]
        if value is not None:
            path = world.root / ("request-" + str(commands) + ".json")
            path.write_bytes(canonical(value)); argv.append(str(path))
        argv += list(map(str, extra))
        result = subprocess.run(argv, capture_output=True, timeout=30, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        require((result.returncode == 0) == success and not result.stderr, "M4 CLI outcome differs for " + command)
        require(marker not in result.stdout and b"synthetic-protected-record" not in result.stdout and b"Bearer fixture-" not in result.stdout, "private payload appeared in CLI output")
        return parse(result.stdout)

    try:
        world.publisher.contents["m4"] = {p: read_file(ROOT, p) for p in selected_tree(ROOT, ["scripts"])}
        world.runtime.enroll(source("m4", "tool", ["scripts"]))
        trivy = source("trivy")
        trivy.update(repository="aquasecurity/trivy", repository_id=180687624, owner_id=12783832, include=[],
            asset={"name": "trivy_{version}_Linux-64bit.tar.gz", "format": "tar.gz", "members": ["trivy"]},
            max_download_bytes=128 * 1024 * 1024, max_unpacked_bytes=512 * 1024 * 1024)
        world.runtime.enroll(trivy)
        for name in ("runtime", "m4", "trivy"):
            candidate = world.runtime.prepare(name)["candidate"]
            review = acceptance(candidate)
            if name == "trivy":
                review["reviewer"] = "Synthetic integration operator"
                for area in review["checks"]:
                    review["checks"][area]["evidence"] = "Test-only official Trivy release, Apache-2.0 upstream license, one fixed offline secret/misconfiguration adapter; exact API digest verified. No target hooks, config or network."
            world.runtime.review(review); world.runtime.activate(candidate)
        runtime = world.state.get("candidate", world.state.get("active", "runtime"))["resolved"]["identity"]
        scanner = world.state.get("candidate", world.state.get("active", "trivy"))["resolved"]["identity"]
        world.runtime.authorize({"id": "offline", "root": str(world.target), "inputs": sorted(fixture_files), "components": ["m4", "trivy"], "network": "none",
            "operations": [{"id": mode, "component": "m4", "entrypoint": "scripts/m4_worker.py", "interpreter": "python", "arguments": [mode], "timeout_seconds": 120, "max_output_bytes": 4 * 1024 * 1024} for mode in ("infra", "trivy")],
            "limits": {"calls": 2, "seconds": 240, "expires_at": time.time() + 600, "memory_mb": 1024, "cpus": 1, "pids": 128, "tmpfs_mb": 128}})
        run = world.runtime.begin("offline")["run"]
        for mode in ("infra", "trivy"):
            operation = world.runtime.execute(run, mode)["operation"]
            operations.append(operation)
            cli("infrastructure", {"id": mode, "operation": operation, "adapter": mode})
        report = cli("plan")
        built = next(s for s in report["scans"] if s["id"] == "infra")
        external = next(s for s in report["scans"] if s["id"] == "trivy")
        require(all(s["valid"] for s in report["scans"]), "authentic scanner evidence invalid")
        require(any(l["rule"] == "root-user" for l in built["output"]["leads"]), "builtin root lead absent")
        require(any(l["path"] == "Dockerfile" for l in external["output"]["leads"]) and any(l["path"] == "fixture.pem" for l in external["output"]["leads"]), "target config or ignore suppressed actual Trivy leads")
        require(external["output"]["tool_version"] == scanner["label"].removeprefix("v"), "actual scanner version differs")
        cli("infrastructure", {"id": "forged", "operation": "op-" + "0" * 32, "adapter": "infra"}, success=False)
        checks += ["real builtin and current Trivy workers", "target configuration and ignores not inherited", "forged scanner producer rejected"]
        print(json.dumps({"stage": "offline-scanners", "result": "passed", "trivy": scanner["label"]}), flush=True)

        spec, credentials = role_plan(world)
        world.authorize(spec)
        credentials_path = world.state.root / "fixture-credentials.json"
        credentials_path.write_bytes(canonical(credentials))
        cases = []
        for actor in ("owner", "outsider", "tenant"):
            proof = cli("request", extra=("web-audit", actor + "-identity", "--credentials", credentials_path))["operation"]
            record = cli("request", extra=("web-audit", actor + "-read", "--credentials", credentials_path))["operation"]
            cases.append({"operation": record, "identity_operation": proof, "expectation": "allowed" if actor == "owner" else "denied"})
        anonymous = cli("request", extra=("web-audit", "anonymous-read"))["operation"]
        cases.append({"operation": anonymous, "identity_operation": None, "expectation": "denied"})
        comparison = {"id": "roles", "deployment": "local", "policy_basis": "Fixture owner alone may read the same protected record.", "identity_basis": "Complete distinct synthetic user/tenant assertions; not independent attestation.", "cases": cases}
        require(cli("compare", comparison)["expectations_satisfied"], "legitimate role comparison failed")
        cli("request", extra=("web-audit", "anonymous-read"), success=False)
        require(len(server.calls) == 7, "unexpected network request count")
        checks += ["actual owner/outsider/cross-tenant/anonymous CLI reads", "single-use intent blocks replay"]

        # Disposable deployment fixture: network none, no mounts, no target code.
        raw = docker.checked(["container", "run", "--detach", "--label", "org.pooyahayati.m4-fixture=" + owner_label,
            "--network", "none", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges=true",
            "--user", "65532:65532", "--memory", "64m", "--memory-swap", "64m", "--cpus", "0.5", "--pids-limit", "16",
            "--log-driver", "none", "--entrypoint", "/usr/local/bin/python", runtime["reference"], "-I", "-B", "-c", "import time; time.sleep(300)"])
        owned = raw.decode().strip()
        require(len(owned) == 64, "full owned container identity unavailable")
        value = {"id": "actual-container", "deployment": "local", "container_id": owned, "expected_image": runtime["image_id"], "expires_at": time.time() + 600}
        require(world.control.inspect_container("demo", value)["matches_declared_image"], "actual container identity mismatch")
        wrong = dict(value, id="mismatch", expected_image="sha256:" + "d" * 64)
        require(not world.control.inspect_container("demo", wrong)["matches_declared_image"], "wrong artifact was accepted")
        # The assessment deliberately declares a different artifact: no release
        # correspondence may be claimed from the independently correct API reads.
        release = {"id": "delivery", "deployment": "local", "stage": "post-release", "artifact": world.spec["deployments"][0]["artifact"],
            "container": "actual-container", "comparisons": ["roles"], "reviewer": "Synthetic operator", "basis": "Declared artifact deliberately differs from observed owned container."}
        cli("release-check", release, success=False)
        checks += ["actual local container/image observation", "declared versus observed artifact mismatch blocks delivery"]
        matching = copy.deepcopy(world.spec)
        matching["id"] = "matching"
        matching["deployments"][0]["artifact"] = runtime["image_id"]
        cli("create", matching)
        spec["id"] = "matching-authority"
        world.control.web_authorize("matching", spec)
        matching_cases = []
        proof = cli("request", extra=(spec["id"], "owner-identity", "--credentials", credentials_path), assessment="matching")["operation"]
        record = cli("request", extra=(spec["id"], "owner-read", "--credentials", credentials_path), assessment="matching")["operation"]
        matching_cases.append({"operation": record, "identity_operation": proof, "expectation": "allowed"})
        record = cli("request", extra=(spec["id"], "anonymous-read"), assessment="matching")["operation"]
        matching_cases.append({"operation": record, "identity_operation": None, "expectation": "denied"})
        matching_comparison = dict(comparison, cases=matching_cases)
        require(cli("compare", matching_comparison, assessment="matching")["expectations_satisfied"], "matching case role checks failed")
        world.control.inspect_container("matching", value)
        matching_release = dict(release, artifact=runtime["image_id"], basis="Exact owned local image and separately collected local reads; routing/build provenance remain unknown.")
        result = cli("release-check", matching_release, assessment="matching")
        require(result["declared_correspondence"] and result["deployment_approved"] is False, "legitimate correspondence or its claim boundary differs")
        matching_report = cli("plan", assessment="matching")
        require(matching_report["releases"][0]["valid"] and matching_report["releases"][0]["bindings"]["url_to_container_routing"] == "not_established", "unsupported routing claim")
        checks.append("matching real artifact permits only declared correspondence, not deployment approval")
        written = cli("report")
        for name in (written["json"], written["markdown"]):
            raw = (world.state.root / name).read_bytes()
            require(marker not in raw and b"Bearer fixture-" not in raw and b"synthetic-protected-record" not in raw, "private payload appeared in standalone report")
        cli("invalidate-runtime", extra=("web", cases[0]["identity_operation"]))
        require(not cli("plan")["comparisons"][0]["valid"], "role comparison survived identity invalidation")
        require({p: (world.target / p).read_bytes() for p in fixture_files} == fixture_files, "target files changed")
        require(docker.checked(["container", "ls", "--all", "--filter", "label=" + LABEL + ".instance=" + docker.instance, "--format", "{{.ID}}"]).strip() == b"", "M1 owned execution container remains")
        checks += ["standalone report privacy", "producer revocation retracts comparison", "original inputs unchanged and M1 cleanup"]
        print(json.dumps({"result": "passed", "commands": commands, "real_scanner_operations": len(operations), "actual_web_requests": len(server.calls),
            "trivy_version": scanner["label"], "image": runtime["reference"], "checks": checks,
            "scope": "synthetic publisher for checkout; live current official Trivy/Docker; owned local HTTP fixture and container; no customer target"}), flush=True)
        completed = True
    finally:
        if owned:
            rows = parse(docker.checked(["container", "inspect", owned]))
            require(len(rows) == 1 and rows[0]["Id"] == owned and rows[0]["Config"]["Labels"].get("org.pooyahayati.m4-fixture") == owner_label, "fixture cleanup ownership differs")
            docker.checked(["container", "rm", "--force", owned])
        world.runtime.recover()
        server.close()
        if completed: world.close()
        else: print(json.dumps({"result": "failed", "retained_private_fixture": str(world.root)}), flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--docker", required=True, type=Path)
    parser.add_argument("--trivy-archive", type=Path)
    args = parser.parse_args()
    run_suite(args.docker, args.trivy_archive.resolve(strict=True) if args.trivy_archive else None)
