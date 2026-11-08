#!/usr/bin/env python3
"""Offline M1 infrastructure and current-release bundled Trivy adapters."""

import json
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from security_assessment.infrastructure import inspect_files, normalize_trivy
from security_runtime.common import parse, read_file, require
from security_runtime.process import bounded_process


def inspect(mode):
    contents, total = {}, 0
    for root, dirs, files in os.walk("/inputs", followlinks=False):
        for name in dirs: require(not (Path(root) / name).is_symlink(), "input link")
        for name in files:
            path = (Path(root) / name).relative_to("/inputs").as_posix()
            contents[path] = read_file("/inputs", path, 1024 * 1024)
            total += len(contents[path])
            require(len(contents) <= 256 and total <= 16 * 1024 * 1024, "selected input limit")
    require(contents, "no selected input")
    if mode == "infra": return inspect_files(contents)
    require(mode == "trivy", "unsupported adapter")
    # The only supported rule source is the current reviewed release's embedded
    # rules. No external DB/check cache fallback, config, ignore file or plugins.
    require(not any(b"trivy:ignore" in raw.lower() or b"tfsec:ignore" in raw.lower() for raw in contents.values()), "inline suppression requires separate review")
    env = {"PATH": "/usr/bin:/bin", "HOME": "/tmp", "TMPDIR": "/tmp"}
    binary = "/resources/trivy/trivy"
    identity = bounded_process([binary, "version", "--config=", "--quiet", "--cache-dir", "/tmp/m4-trivy-cache", "--format", "json"], env, 10, 16384)
    require(identity["exit_code"] == 0, "scanner identity unavailable")
    version = parse(identity["content"]).get("Version")
    result = bounded_process([binary, "filesystem", "--config=", "--ignorefile=", "--secret-config=", "--disable-telemetry",
        "--skip-check-update", "--offline-scan", "--scanners", "secret,misconfig", "--format", "json", "--quiet",
        "--cache-dir", "/tmp/m4-trivy-cache", "--exit-code", "0", "/inputs"], env, 90, 4 * 1024 * 1024)
    require(result["exit_code"] == 0, "scanner failed")
    return normalize_trivy(parse(result["content"]), contents, version)


if __name__ == "__main__":
    try:
        require(len(sys.argv) == 2, "invalid arguments")
        print(json.dumps(inspect(sys.argv[1]), allow_nan=False))
    except Exception:
        print('{"status":"unavailable"}')
        raise SystemExit(1)
