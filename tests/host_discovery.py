#!/usr/bin/env python3
"""Observe selected local Codex skill metadata without starting a model turn.

Requires an explicitly selected trusted host executable and archive digest. Uses
an owned private home/project, frozen empty cloud skill snapshot and only the
initialize/skills-list protocol. No credentials are copied or global install made.
The host may still enumerate ambient user metadata outside the private home.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import queue
import subprocess
import sys
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from security_runtime.package_lifecycle import Manager


def isolated_environment(home):
    env = {k: v for k, v in os.environ.items() if k.upper() in
           ("SYSTEMROOT", "WINDIR", "COMSPEC", "PATH", "PATHEXT", "TMP", "TEMP", "LANG")}
    env.update(HOME=str(home), USERPROFILE=str(home), CODEX_HOME=str(home / ".codex"),
               LOCALAPPDATA=str(home / "AppData/Local"), APPDATA=str(home / "AppData/Roaming"),
               GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull,
               GIT_CONFIG_SYSTEM=os.devnull, GIT_TERMINAL_PROMPT="0")
    return env


def initialize_project(project, home):
    env = isolated_environment(home)
    empty = home / "empty-git-template"
    empty.mkdir()
    # Never inherit GIT_DIR, worktree/index/object redirects or host templates.
    subprocess.run(["git", "init", "--quiet", "--template=" + str(empty), str(project)],
                   env=env, cwd=project, check=True, timeout=30,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return env


def run(codex, archive, identity):
    private = Path(tempfile.mkdtemp(prefix="cyber-host-discovery-")).resolve()
    project, home = private / "project", private / "home"
    project.mkdir()
    home.mkdir()
    skills = project / ".agents/skills"
    skills.mkdir(parents=True)
    # An owned repository bounds project discovery at this directory.
    env = initialize_project(project, home)
    manager = Manager(private / "manager", skills, create=True)
    manager.change("install", archive, identity)
    frozen = private / "cloud.json"
    frozen.write_text('{"skills": []}\n', encoding="utf-8")
    (home / ".codex").mkdir()
    version = subprocess.check_output([str(codex), "--version"], env=env, timeout=15).decode().strip()
    incoming = queue.Queue(maxsize=128)
    transcript = []
    with (private / "host.stderr").open("wb") as err:
        process = subprocess.Popen([str(codex), "app-server", "--listen", "stdio://",
                                    "--cloud-skills-snapshot", str(frozen)],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=err,
                                   env=env, cwd=project, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        def collect():
            total = 0
            for line in iter(lambda: process.stdout.readline(1024 * 1024 + 1), b""):
                total += len(line)
                if len(line) > 1024 * 1024 or total > 4 * 1024 * 1024:
                    process.kill()
                    return
                try:
                    incoming.put_nowait(line)
                except queue.Full:
                    process.kill()
                    return
        thread = threading.Thread(target=collect, daemon=True)
        thread.start()
        def send(value):
            process.stdin.write(json.dumps(value).encode() + b"\n")
            process.stdin.flush()
        def response(ident):
            deadline = time.monotonic() + 20
            while time.monotonic() < deadline:
                try:
                    line = incoming.get(timeout=min(1, max(.01, deadline - time.monotonic())))
                except queue.Empty:
                    if process.poll() is not None:
                        raise AssertionError("host exited; retained private evidence at " + str(private))
                    continue
                value = json.loads(line)
                transcript.append(value)
                if value.get("id") == ident:
                    assert "error" not in value, "host rejected metadata request"
                    return value["result"]
            raise AssertionError("host metadata deadline exceeded")
        try:
            send({"id": 1, "method": "initialize", "params": {
                "clientInfo": {"name": "cybersecurity-skill-catalog-check", "version": "1.0.0"}}})
            response(1)
            send({"method": "initialized"})
            send({"id": 2, "method": "skills/list", "params": {"cwds": [str(project)], "forceReload": True}})
            catalog = response(2)
            entries = catalog["data"]
            assert len(entries) == 1 and not entries[0]["errors"], "host reported skill parsing errors"
            matches = [s for s in entries[0]["skills"] if s["name"] == "cybersecurity-skills"]
            assert len(matches) == 1, "host did not discover exactly one candidate skill"
            skill = matches[0]
            assert Path(skill["path"]).resolve() == manager.target / "SKILL.md"
            assert skill["enabled"] is True and skill["scope"] == "repo"
            assert skill["description"] and skill.get("interface", {}).get("displayName") == "Cybersecurity Skills"
            assert manager.status()["installed_archive_sha256"] == identity
            result = {"result": "passed", "host_version": version, "archive_sha256": identity,
                      "host_executable_sha256": hashlib.sha256(codex.read_bytes()).hexdigest(),
                      "skill_name": skill["name"], "scope": skill["scope"], "enabled": skill["enabled"],
                      "metadata_discovery": True, "model_invocation": False,
                      "ambient_skill_metadata_may_be_visible": True,
                      "other_catalog_entries": len(entries[0]["skills"]) - 1,
                      "autonomous_routing_verified": False, "runtime_readiness": "not_established",
                      "private_evidence": str(private)}
            (private / "result.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
            print(json.dumps(result))
        finally:
            (private / "transcript.json").write_text(json.dumps(transcript, indent=2) + "\n", encoding="utf-8")
            if process.poll() is None:
                process.kill()
            process.wait(timeout=10)
            thread.join(timeout=2)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--codex", type=Path, required=True)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--sha256", required=True)
    args = parser.parse_args()
    run(args.codex.resolve(strict=True), args.archive.resolve(strict=True), args.sha256)
