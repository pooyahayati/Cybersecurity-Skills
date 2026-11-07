"""Authenticated freshness, review, run authorization and recovery transitions."""

from __future__ import annotations

import os
from pathlib import Path
import secrets
import time

from .common import (Blocked, digest, fields, identifier, integer, number, portable_tree,
                     read_file, relpath, require, sha256, text)
from .sources import GitHub, source_spec


HEAD_RESOURCES = ["SKILL.md", "README.md", "AGENTS.md", "ROADMAP.md", "STATUS.md", "CHANGELOG.md",
                  "CONTRIBUTING.md", "SECURITY.md", "THIRD_PARTY_NOTICES.md", "LICENSE",
                  "scripts", "references", "config", "agents", "docs", "templates"]
REVIEW_AREAS = {"instructions", "dependencies", "permissions", "license", "compatibility", "provenance"}


def selected_tree(root, prefixes):
    result = {}
    for prefix in prefixes:
        item = root / prefix
        if item.is_file():
            result[prefix] = sha256(read_file(root, prefix, 512 * 1024 * 1024))
        else:
            require(item.is_dir() and not item.is_symlink(), "selected resource is unavailable")
            for base, dirs, files in os.walk(item, followlinks=False):
                dirs[:] = [d for d in dirs if d != "__pycache__"]
                for name in dirs + files:
                    path = Path(base) / name
                    require(not path.is_symlink() and not getattr(path.lstat(), "st_file_attributes", 0) & 0x400,
                            "selected resource contains a link")
                for name in files:
                    path = (Path(base) / name).relative_to(root).as_posix()
                    result[path] = sha256(read_file(root, path, 512 * 1024 * 1024))
                    require(len(result) <= 4096, "resource bundle exceeds its limit")
    return dict(sorted(result.items()))


def write_bundle(parent, contents):
    """Stage outside visible objects. No hooks, archive extraction or overwrites."""
    temporary = parent / ("stage-" + secrets.token_hex(16))
    temporary.mkdir(mode=0o700)
    for name, content in contents.items():
        relpath(name)
        path = temporary / name
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with path.open("xb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        if os.name != "nt":
            path.chmod(0o555)  # Native entrypoints are allowed only by exact authorization.
    manifest = portable_tree(temporary)
    for base, dirs, _files in os.walk(temporary, topdown=False):
        # Keep the staging root writable until its cross-directory rename has
        # updated '..'. POSIX forbids that move for a non-root owner otherwise.
        if os.name != "nt" and Path(base) != temporary:
            Path(base).chmod(0o555)
    return temporary, manifest


class Controller:
    def __init__(self, store, package_root, upstream=None, docker=None, clock=time.time):
        self.store, self.package = store, Path(package_root).resolve(strict=True)
        self.upstream, self.docker, self.clock = upstream or GitHub(), docker, clock

    def enroll(self, spec):
        spec = source_spec(spec)
        require((spec["id"] == "head") == (spec["kind"] == "head"), "head identity is reserved")
        require(spec["id"] != "runtime", "runtime identity is reserved")
        if spec["kind"] == "head":
            require(sorted(spec["include"]) == sorted(HEAD_RESOURCES),
                    "head must include all controller and skill resources")
        with self.store.transaction() as tx:
            require(tx.get("source", spec["id"]) is None, "source is already enrolled; identity is immutable")
            tx.put("source", spec["id"], {"spec": spec, "revoked": False})
        return {"component": spec["id"], "status": "enrolled"}

    def source(self, component, tx=None):
        result = (tx or self.store).get("source", component)
        require(result is not None and result["revoked"] is False, "component is absent or revoked")
        return result["spec"]

    def prepare(self, component):
        if component == "runtime":
            require(self.docker is not None, "local Docker backend is unavailable")
            resolved = self.docker.latest()
            record = {"component": component, "kind": "runtime", "resolved": resolved,
                      "manifest": {}, "spec_sha256": None}
        else:
            spec = self.source(component)
            resolved = self.upstream.resolve(spec)
            contents = self.upstream.fetch(spec, resolved)
            temporary, manifest = write_bundle(self.store.root / "quarantine", contents)
            record = {"component": component, "kind": spec["kind"], "resolved": resolved,
                      "manifest": manifest, "spec_sha256": digest(spec)}
        candidate = "candidate-" + digest(record)
        if component != "runtime":
            destination = self.store.root / "objects" / candidate
            if destination.exists():
                require(portable_tree(destination) == manifest, "existing candidate bytes changed")
            else:
                temporary.rename(destination)
                if os.name != "nt":
                    destination.chmod(0o555)
        with self.store.transaction() as tx:
            if component != "runtime":
                require(digest(self.source(component, tx)) == record["spec_sha256"], "source changed during acquisition")
            require(not tx.get("revocation", component, False), "component is revoked")
            previous = tx.get("candidate", candidate)
            require(previous is None or previous == record, "candidate identity collision")
            tx.put("candidate", candidate, record)
            active = tx.get("active", component)
            prior = tx.get("candidate", active)["manifest"] if active else {}
        changes = {"added": sorted(set(record["manifest"]) - set(prior)),
                   "removed": sorted(set(prior) - set(record["manifest"])),
                   "changed": sorted(k for k in prior.keys() & record["manifest"].keys()
                                     if prior[k] != record["manifest"][k])}
        return {"candidate": candidate, "record": record, "changes": changes,
                "quarantine_path": str(self.store.root / "objects" / candidate) if component != "runtime" else None,
                "status": "review_required"}

    def candidate(self, candidate, tx=None):
        value = (tx or self.store).get("candidate", candidate)
        require(value is not None, "candidate is unavailable")
        if value["kind"] != "runtime":
            require(portable_tree(self.store.root / "objects" / candidate) == value["manifest"],
                    "candidate bytes differ from their authenticated manifest")
        return value

    def review(self, decision):
        fields(decision, {"candidate", "reviewer", "decision", "checks"})
        text(decision["reviewer"], 256)
        require(decision["decision"] in ("accept", "reject"), "invalid review decision")
        fields(decision["checks"], REVIEW_AREAS)
        for check in decision["checks"].values():
            fields(check, {"result", "evidence"})
            require(check["result"] in ("pass", "fail"), "review check must pass or fail")
            text(check["evidence"], 4096)
        if decision["decision"] == "accept":
            require(all(c["result"] == "pass" for c in decision["checks"].values()),
                    "failed checks cannot accept a candidate")
        with self.store.transaction() as tx:
            record = self.candidate(decision["candidate"], tx)
            tx.put("review", decision["candidate"], {"decision": decision,
                "record_sha256": digest(record), "reviewed_at": self.clock()})
        return {"candidate": decision["candidate"], "status": decision["decision"]}

    def check_current(self, candidate):
        record = self.candidate(candidate)
        if record["kind"] == "runtime":
            require(self.docker is not None, "local Docker backend is unavailable")
            latest = self.docker.latest()
        else:
            spec = self.source(record["component"])
            require(digest(spec) == record["spec_sha256"], "source specification changed")
            latest = self.upstream.resolve(spec)
        require(latest["identity"] == record["resolved"]["identity"],
                "accepted component is not current; prepare and review an update")
        return record

    def reviewed(self, candidate, record, tx):
        review = tx.get("review", candidate)
        require(review is not None and review["decision"]["decision"] == "accept"
                and review["record_sha256"] == digest(record), "candidate lacks an accepted bound review")
        require(not tx.get("revocation", record["component"], False), "component is revoked")
        if record["kind"] != "runtime":
            self.source(record["component"], tx)

    def activate(self, candidate):
        record = self.check_current(candidate)
        with self.store.transaction() as tx:
            self.reviewed(candidate, record, tx)
            tx.put("active", record["component"], candidate)
        return {"component": record["component"], "candidate": candidate,
                "status": "reload_required" if record["kind"] == "head" else "activated"}

    def authorize(self, value):
        fields(value, {"id", "root", "inputs", "components", "operations", "limits", "network"})
        identifier(value["id"])
        require(value["network"] == "none", "network-enabled execution is unsupported")
        root = Path(text(value["root"])).absolute()
        require(root == root.resolve(strict=True) and root.is_dir(), "target must be a canonical existing directory")
        require(not root.is_relative_to(self.store.root) and not self.store.root.is_relative_to(root)
                and not root.is_relative_to(self.package) and not self.package.is_relative_to(root),
                "target, package and control state must be disjoint")
        inputs = value["inputs"]
        require(isinstance(inputs, list) and all(isinstance(i, str) for i in inputs) and 0 < len(inputs) <= 256
                and len(set(inputs)) == len(inputs), "inputs must be a bounded unique file list")
        for name in inputs:
            relpath(name)
        components = value["components"]
        require(isinstance(components, list) and all(isinstance(i, str) for i in components)
                and 0 < len(components) <= 16 and len(set(components)) == len(components),
                "components must be a bounded unique list")
        for component in components:
            identifier(component)
            require(component not in ("head", "runtime"), "head and runtime are selected automatically")
        limits = value["limits"]
        fields(limits, {"calls", "seconds", "expires_at", "memory_mb", "cpus", "pids", "tmpfs_mb"})
        integer(limits["calls"], 1, 100)
        integer(limits["seconds"], 1, 3600)
        number(limits["expires_at"], self.clock() + 1, self.clock() + 8 * 3600)
        integer(limits["memory_mb"], 64, 2048)
        number(limits["cpus"], 0.1, 4)
        integer(limits["pids"], 16, 256)
        integer(limits["tmpfs_mb"], 1, 256)
        operations = value["operations"]
        require(isinstance(operations, list) and 0 < len(operations) <= 32, "invalid operation selection")
        ids = set()
        for operation in operations:
            fields(operation, {"id", "component", "entrypoint", "interpreter", "arguments",
                               "timeout_seconds", "max_output_bytes"})
            identifier(operation["id"])
            require(operation["id"] not in ids, "duplicate operation ID")
            ids.add(operation["id"])
            identifier(operation["component"])
            require(operation["component"] in components, "operation component is not selected")
            relpath(operation["entrypoint"])
            require(operation["interpreter"] in ("python", "native"), "unsupported interpreter")
            arguments = operation["arguments"]
            require(isinstance(arguments, list) and len(arguments) <= 64, "invalid argument list")
            for argument in arguments:
                text(argument, 4096)
            integer(operation["timeout_seconds"], 1, min(600, limits["seconds"]))
            integer(operation["max_output_bytes"], 1, 8 * 1024 * 1024)
        contents, total = {}, 0
        for name in inputs:
            contents[name] = read_file(root, name, 64 * 1024 * 1024)
            total += len(contents[name])
            require(total <= 128 * 1024 * 1024, "input snapshot exceeds its limit")
        staged, manifest = write_bundle(self.store.root / "inputs", contents)
        destination = self.store.root / "inputs" / value["id"]
        info = root.stat()
        record = {"spec": value, "root_identity": [info.st_dev, info.st_ino], "manifest": manifest,
                  "calls_used": 0, "seconds_used": 0, "operation": None, "run": None, "revoked": False}
        with self.store.transaction() as tx:
            require(tx.get("authorization", value["id"]) is None and not destination.exists(),
                    "authorization IDs cannot be reused")
            staged.rename(destination)
            if os.name != "nt":
                destination.chmod(0o555)
            tx.put("authorization", value["id"], record)
        return {"authorization": value["id"], "status": "authorized", "inputs_sha256": digest(manifest)}

    def authority(self, tx, authorization):
        auth = tx.get("authorization", authorization)
        require(auth is not None and not auth["revoked"], "authorization is unavailable or revoked")
        require(self.clock() < auth["spec"]["limits"]["expires_at"], "authorization expired")
        return auth

    def begin(self, authorization):
        # Invalidate first. Failure at any later step cannot resurrect the previous run.
        with self.store.transaction() as tx:
            auth = self.authority(tx, authorization)
            require(auth["operation"] is None, "an operation is unfinished; cancel/recover before resuming")
            if auth["run"]:
                old = tx.get("run", auth["run"])
                old["cancelled"] = True
                tx.put("run", auth["run"], old)
            auth["run"] = None
            tx.put("authorization", authorization, auth)
        root = Path(auth["spec"]["root"])
        info = root.stat()
        require(root == root.resolve(strict=True) and [info.st_dev, info.st_ino] == auth["root_identity"],
                "target root identity changed")
        require({name: sha256(read_file(root, name, 64 * 1024 * 1024)) for name in auth["manifest"]}
                == auth["manifest"], "authorized target bytes changed; a new authorization is required")
        require(portable_tree(self.store.root / "inputs" / authorization) == auth["manifest"],
                "input snapshot changed")
        components = {"head", "runtime"} | set(auth["spec"]["components"])
        bindings = {}
        for component in sorted(components):
            candidate = self.store.get("active", component)
            require(candidate is not None, "a selected component has not been activated")
            record = self.check_current(candidate)
            if component == "head":
                require(selected_tree(self.package, HEAD_RESOURCES) == record["manifest"],
                        "reload_required: executing head differs from the accepted current bundle")
            for operation in auth["spec"]["operations"]:
                if operation["component"] == component:
                    require(operation["entrypoint"] in record["manifest"], "operation entrypoint is not a verified resource")
            bindings[component] = candidate
        run = "run-" + secrets.token_hex(16)
        with self.store.transaction() as tx:
            auth = self.authority(tx, authorization)
            require(auth["run"] is None and auth["operation"] is None, "authorization changed during preflight")
            for component, candidate in bindings.items():
                require(tx.get("active", component) == candidate, "activation changed during preflight")
                self.reviewed(candidate, self.candidate(candidate, tx), tx)
            tx.put("run", run, {"authorization": authorization, "bindings": bindings,
                                "cancelled": False, "started_at": self.clock()})
            auth["run"] = run
            tx.put("authorization", authorization, auth)
        return {"run": run, "status": "ready", "bindings": bindings}

    def guard(self, run, operation=None):
        with self.store.transaction() as tx:
            session = tx.get("run", run)
            require(session is not None and not session["cancelled"], "run is absent or cancelled")
            auth = self.authority(tx, session["authorization"])
            require(auth["run"] == run and (operation is None or auth["operation"] == operation),
                    "run or operation is no longer authorized")
            for component, candidate in session["bindings"].items():
                require(not tx.get("revocation", component, False), "selected component was revoked")
                if component != "runtime":
                    spec = self.source(component, tx)
                    if spec["kind"] == "data":
                        record = tx.get("candidate", candidate)
                        require(self.clock() - record["resolved"]["identity"]["published_at"]
                                <= spec["data_max_age_seconds"], "selected data expired during the run")
        return session, auth

    def execute(self, run, operation_id):
        require(self.docker is not None, "local Docker backend is unavailable")
        session, auth = self.guard(run)
        chosen = [o for o in auth["spec"]["operations"] if o["id"] == operation_id]
        require(len(chosen) == 1, "operation is outside the authorization")
        specification = chosen[0]
        # Recheck all frozen bytes, including the head and selected data, before launch.
        records = {component: self.candidate(candidate) for component, candidate in session["bindings"].items()}
        require(selected_tree(self.package, HEAD_RESOURCES) == records["head"]["manifest"],
                "executing head changed during the run")
        inputs = self.store.root / "inputs" / session["authorization"]
        require(portable_tree(inputs) == auth["manifest"], "input snapshot changed")
        operation = "op-" + secrets.token_hex(16)
        with self.store.transaction() as tx:
            live = tx.get("run", run)
            auth = self.authority(tx, session["authorization"])
            require(not live["cancelled"] and auth["run"] == run and auth["operation"] is None,
                    "run changed or an operation is already active")
            limits = auth["spec"]["limits"]
            require(auth["calls_used"] < limits["calls"]
                    and auth["seconds_used"] + specification["timeout_seconds"] <= limits["seconds"],
                    "aggregate authorization budget exhausted")
            auth["calls_used"] += 1
            auth["seconds_used"] += specification["timeout_seconds"]
            auth["operation"] = operation
            tx.put("authorization", session["authorization"], auth)
            tx.put("operation", operation, {"run": run, "authorization": session["authorization"],
                "specification": specification, "status": "unfinished", "started_at": self.clock()})
        result, failure, cleaned = None, None, False
        output_path = self.store.root / (operation + ".output")
        try:
            with output_path.open("xb") as output:
                result = self.docker.execute(operation, records["runtime"]["resolved"]["identity"],
                    self.store.root / "objects" / session["bindings"][specification["component"]],
                    inputs, specification, limits, lambda: self.guard(run, operation), output,
                    resources={component: self.store.root / "objects" / session["bindings"][component]
                               for component in auth["spec"]["components"]})
            cleaned = True
        except BaseException as exc:
            failure = exc
            try:
                self.docker.cleanup(operation)
                cleaned = True
            except Exception:
                cleaned = False
        finally:
            if cleaned:
                with self.store.transaction() as tx:
                    evidence = tx.get("operation", operation)
                    evidence.update({"status": "completed" if failure is None else "blocked",
                                     "result": result, "finished_at": self.clock()})
                    tx.put("operation", operation, evidence)
                    latest = tx.get("authorization", session["authorization"])
                    if latest["operation"] == operation:
                        latest["operation"] = None
                        tx.put("authorization", session["authorization"], latest)
        require(cleaned, "cleanup unverified; authorization remains locked until recovery")
        if failure is not None:
            raise failure
        return {"operation": operation, "status": "completed", "result": result}

    def cancel(self, run):
        with self.store.transaction() as tx:
            value = tx.get("run", run)
            require(value is not None, "run is unavailable")
            value["cancelled"] = True
            tx.put("run", run, value)
        return {"run": run, "status": "cancelled"}

    def revoke(self, component=None, authorization=None):
        require((component is None) != (authorization is None), "select one revocation target")
        with self.store.transaction() as tx:
            if component is not None:
                identifier(component)
                tx.put("revocation", component, True)
                value = tx.get("source", component)
                if value:
                    value["revoked"] = True
                    tx.put("source", component, value)
            else:
                value = tx.get("authorization", authorization)
                require(value is not None, "authorization is unavailable")
                value["revoked"] = True
                tx.put("authorization", authorization, value)
        return {"status": "revoked"}

    def recover(self):
        require(self.docker is not None, "local Docker backend is unavailable")
        with self.store.transaction() as tx:
            records = tx.list("operation")
        recovered = []
        for operation, value in records.items():
            if value["status"] != "unfinished":
                continue
            self.docker.cleanup(operation)
            with self.store.transaction() as tx:
                latest = tx.get("operation", operation)
                if latest["status"] != "unfinished":
                    continue
                latest.update({"status": "interrupted", "finished_at": self.clock()})
                tx.put("operation", operation, latest)
                auth = tx.get("authorization", value["authorization"])
                if auth["operation"] == operation:
                    auth["operation"] = None
                    tx.put("authorization", value["authorization"], auth)
                session = tx.get("run", value["run"])
                session["cancelled"] = True
                tx.put("run", value["run"], session)
            recovered.append(operation)
        return {"status": "recovered", "operations": recovered}
