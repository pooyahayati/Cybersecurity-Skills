"""Synthetic publishers and disposable control state; never production targets."""

from copy import deepcopy
from pathlib import Path
import os
import tempfile
import time

from security_runtime.common import digest, sha256
from security_runtime.controller import Controller, HEAD_RESOURCES, REVIEW_AREAS
from security_runtime.store import Store


def source(component="analyzer", kind="tool", include=None):
    return {"id": component, "kind": kind, "repository": "fixture/project",
            "repository_id": 10, "owner_id": 20, "include": include or ["check.py"], "asset": None,
            "max_download_bytes": 8 * 1024 * 1024, "max_unpacked_bytes": 8 * 1024 * 1024,
            "data_max_age_seconds": 3600 if kind == "data" else None}


def acceptance(candidate):
    return {"candidate": candidate, "reviewer": "Synthetic fixture operator", "decision": "accept",
            "checks": {area: {"result": "pass", "evidence": "Inspected the synthetic fixture for " + area}
                       for area in REVIEW_AREAS}}


class Publisher:
    def __init__(self):
        self.contents = {}
        self.revisions = {}
        self.unavailable = False
        self.published_at = time.time()

    def resolve(self, spec):
        from security_runtime.common import require
        require(not self.unavailable, "fixture upstream unavailable")
        now = time.time()
        if spec["kind"] == "data":
            require(now - self.published_at <= spec["data_max_age_seconds"], "data component is too old")
        revision = self.revisions.get(spec["id"], digest(self.contents[spec["id"]].keys().__str__()))
        return {"identity": {"revision": revision, "repository_id": spec["repository_id"],
                             "published_at": self.published_at},
                "provenance": {"basis": "synthetic test publisher"}, "checked_at": now}

    def fetch(self, spec, _resolved):
        return deepcopy(self.contents[spec["id"]])


class FakeDocker:
    def __init__(self):
        self.calls = []
        self.cleanup_failure = False
        self.callback = None
        self.identity = {"image_id": "sha256:" + "a" * 64, "reference": "python@sha256:" + "b" * 64}

    def latest(self):
        return {"identity": deepcopy(self.identity), "prerequisite": {"basis": "unit-test fake"}}

    def execute(self, operation, image, component, inputs, specification, limits, guard, output, resources=None):
        guard()
        self.calls.append(deepcopy(specification))
        if self.callback:
            self.callback()
        guard()
        output.write(b"fixture\n")
        return {"exit_code": 0, "bytes": 8, "sha256": sha256(b"fixture\n"), "elapsed_seconds": 0.01}

    def cleanup(self, _operation):
        from security_runtime.common import require
        require(not self.cleanup_failure, "fixture cleanup unavailable")


class Fixture:
    def __init__(self, script=b"print('fixture')\n"):
        self.temp = tempfile.TemporaryDirectory(prefix="cybersecurity-m1-test-")
        self.base = Path(self.temp.name).resolve()
        self.package, self.target = self.base / "package", self.base / "target"
        self.package.mkdir()
        self.target.mkdir()
        self.publisher = Publisher()
        head = {name: b"synthetic document\n" for name in HEAD_RESOURCES if "." in name or name == "LICENSE"}
        for directory in (name for name in HEAD_RESOURCES if "." not in name and name != "LICENSE"):
            head[directory + "/fixture.txt"] = b"synthetic resource\n"
        for name, value in head.items():
            path = self.package / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(value)
        self.publisher.contents = {"head": head, "analyzer": {"check.py": script}}
        (self.target / "customer.txt").write_bytes(b"synthetic original\n")
        self.store = Store(self.base / "private", self.package, initialize=True)
        self.docker = FakeDocker()
        self.controller = Controller(self.store, self.package, self.publisher, self.docker)
        self.controller.enroll(source("head", "head", HEAD_RESOURCES))
        self.controller.enroll(source())

    def activate(self, component):
        candidate = self.controller.prepare(component)["candidate"]
        self.controller.review(acceptance(candidate))
        self.controller.activate(candidate)
        return candidate

    def ready(self):
        for component in ("head", "runtime", "analyzer"):
            self.activate(component)

    def authorization(self, name="audit", **changes):
        value = {"id": name, "root": str(self.target), "inputs": ["customer.txt"],
                 "components": ["analyzer"], "network": "none",
                 "operations": [{"id": "check", "component": "analyzer", "entrypoint": "check.py",
                     "interpreter": "python", "arguments": [], "timeout_seconds": 5, "max_output_bytes": 4096}],
                 "limits": {"calls": 3, "seconds": 15, "expires_at": time.time() + 600,
                            "memory_mb": 128, "cpus": 0.5, "pids": 32, "tmpfs_mb": 8}}
        value.update(changes)
        return value

    def begin(self, value=None):
        value = value or self.authorization()
        self.controller.authorize(value)
        return self.controller.begin(value["id"])["run"]

    def close(self):
        # Only this test-owned TemporaryDirectory is writable/removed.
        for base, dirs, files in os.walk(self.base):
            Path(base).chmod(0o700)
            for name in files:
                path = Path(base) / name
                if not path.is_symlink():
                    path.chmod(0o600)
        self.temp.cleanup()
