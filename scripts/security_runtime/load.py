"""M5 single-use persistent authority for a trusted k6 ticket broker."""

import copy
import os
from pathlib import Path
import secrets
import sys
import time

from .common import canonical, digest, fields, parse, read_file, require, sha256
from .controller import HEAD_RESOURCES, selected_tree
from .load_scope import workload
from .process import bounded_process
from .web import WebController
from .web_scope import credential, url


class LoadController(WebController):
    def tool(self, fresh=False, expected=None, tx=None):
        reader = tx or self.store
        candidate = expected["candidate"] if expected else reader.get("active", "k6")
        require(candidate is not None, "current reviewed k6 required")
        record = self.controller.check_current(candidate) if fresh else reader.get("candidate", candidate)
        require(record is not None, "k6 producer unavailable")
        self.controller.reviewed(candidate, record, reader)
        source = self.controller.source("k6", reader)
        name = "k6.exe" if os.name == "nt" else "k6"
        platform = "windows-amd64.zip" if os.name == "nt" else "linux-amd64.tar.gz"
        version = record["resolved"]["identity"]["label"].removeprefix("v")
        member = "k6-v" + version + "-" + platform.split(".")[0] + "/" + name
        require(source["repository"] == "grafana/k6" and record["component"] == "k6" and record["kind"] == "tool"
                and source["asset"] is not None and source["asset"]["name"] == "k6-v{version}-" + platform
                and set(record["manifest"]) == {member}, "unsupported official k6 distribution")
        binding = {"candidate": candidate, "record_sha256": digest(record), "binary": member,
                   "binary_sha256": record["manifest"][member], "version": version}
        require(expected is None or expected == binding, "k6 binding changed")
        return binding

    def authorize(self, case, value):
        requests, seconds = workload(value, case, self.clock())
        head, tool = self.fresh_head(), self.tool(fresh=True)
        record = {"spec": copy.deepcopy(value), "assessment": case["scope"]["id"], "scope_sha256": case["scope_sha256"],
            "head": head, "tool": tool, "used": False, "revoked": False, "operation": None,
            "reserved_requests": requests, "reserved_seconds": seconds, "created_at": self.clock()}
        with self.store.transaction() as tx:
            require(tx.get("load-authority", value["id"]) is None, "load authority ID reused")
            tx.put("load-authority", value["id"], record)
        return {"status": "authorized", "authorization": value["id"], "security_verdict": "not_established"}

    def guard(self, key, case=None, tx=None):
        reader = tx or self.store
        record = reader.get("load-authority", key)
        require(record is not None and not record["revoked"] and self.clock() < record["spec"]["web"]["limits"]["expires_at"], "load authority expired or revoked")
        if case:
            require(case["scope"]["id"] == record["assessment"] and case["scope_sha256"] == record["scope_sha256"], "load scope differs")
        head = reader.get("candidate", record["head"]["candidate"])
        require(head is not None and digest(head) == record["head"]["record_sha256"], "head binding differs")
        self.controller.reviewed(record["head"]["candidate"], head, reader)
        require(selected_tree(self.package, HEAD_RESOURCES) == record["head"]["manifest"], "collector implementation changed")
        self.tool(expected=record["tool"], tx=reader)
        return record

    def cancel(self, key):
        with self.store.transaction() as tx:
            record = tx.get("load-authority", key)
            require(record is not None, "load authority unavailable")
            record["revoked"] = True
            tx.put("load-authority", key, record)
        return {"status": "cancelled"}

    def execute(self, case, key, credentials=None, ca=None):
        auth = self.guard(key, case)
        # Fresh remote checks happen before the operation, then immutable resources
        # remain stable until it finishes. Unavailable current metadata blocks.
        require(self.fresh_head() == auth["head"], "reload head")
        self.tool(fresh=True, expected=auth["tool"])
        spec, supplied = auth["spec"], None
        route = spec["web"]["routes"][0]
        if route["credential"]:
            require(isinstance(credentials, dict) and route["credential"] in credentials, "selected credential unavailable")
            supplied = credentials[route["credential"]]
            credential(supplied)
        require(ca is None and spec["web"]["ca_sha256"] is None or isinstance(ca, str) and sha256(ca.encode("ascii")) == spec["web"]["ca_sha256"], "CA differs")
        operation = "load-" + secrets.token_hex(16)
        lease = digest(url(route["url"])[:3])
        with self.store.transaction() as tx:
            auth = self.guard(key, case, tx)
            require(not auth["used"], "workload intent consumed; uncertain work must not be replayed")
            prior = tx.get("load-lease", lease)
            require(prior is None or self.clock() > prior["expires_at"], "another workload may still be active for this origin")
            auth.update(used=True, operation=operation)
            tx.put("load-authority", key, auth)
            # Covers the version probe, broker lifetime, and the independently
            # bounded request child if its controller dies. No short lease may
            # overlap a surviving collector on the same origin.
            tx.put("load-lease", lease, {"operation": operation, "expires_at": self.clock() + 10 + auth["reserved_seconds"] + 3 + spec["web"]["limits"]["timeout_seconds"] + 5})
            tx.put("load-operation", operation, {"authorization": key, "authority_sha256": digest(spec), "status": "unfinished", "started_at": self.clock(), "invalidated": False})
        workspace = self.store.root / operation
        workspace.mkdir(mode=0o700)
        try:
            tool = auth["tool"]
            raw = read_file(self.store.root / "objects" / tool["candidate"], tool["binary"], 128 * 1024 * 1024)
            require(sha256(raw) == tool["binary_sha256"], "k6 binary differs")
            binary = workspace / Path(tool["binary"]).name
            binary.write_bytes(raw)
            if os.name != "nt": binary.chmod(0o500)
            env = {"PATH": os.defpath, "HOME": str(workspace), "USERPROFILE": str(workspace)}
            for name in ("SYSTEMROOT", "WINDIR", "TEMP", "TMP"):
                if os.name == "nt" and name in os.environ: env[name] = os.environ[name]
            version = bounded_process([str(binary), "version"], env, 10, 4096)
            require(version["exit_code"] == 0 and version["content"].decode("ascii").startswith(binary.name + " v" + tool["version"] + " "), "actual k6 version differs")
            (workspace / "empty.json").write_bytes(b"{}")

            def guard():
                self.guard(key, case)
                current_lease = self.store.get("load-lease", lease)
                require(current_lease["operation"] == operation and self.clock() < current_lease["expires_at"], "origin lease ended")
                (workspace / "heartbeat").touch()

            guard()
            require(self.clock() + auth["reserved_seconds"] + 3 + spec["web"]["limits"]["timeout_seconds"] < self.store.get("load-lease", lease)["expires_at"], "startup exceeded reserved lease")
            payload = {"spec": spec, "workspace": str(workspace), "binary": str(binary), "credential": supplied, "ca": ca}
            with (self.store.root / (operation + ".output")).open("xb") as diagnostic:
                result = bounded_process([sys.executable, "-I", "-B", str(self.package / "scripts/security_runtime/load_worker.py")],
                    env, auth["reserved_seconds"] + 3, 32768, guard=guard, input_data=canonical(payload), sink=diagnostic)
            require(result["exit_code"] == 0, "load producer interrupted; outcome uncertain")
            output = parse(result["content"], 32768)
            require(output.get("schema_version") == 1 and output.get("adapter") == "k6-broker" and output.get("planned") == auth["reserved_requests"], "invalid load producer")
            with self.store.transaction() as tx:
                self.guard(key, case, tx)
                record = tx.get("load-operation", operation)
                record.update(status="completed", finished_at=self.clock(), output=output, output_sha256=digest(output))
                tx.put("load-operation", operation, record)
                require(tx.get("load-lease", lease)["operation"] == operation, "origin lease replaced")
                if output["unfinished"] == 0:
                    tx.put("load-lease", lease, {"operation": operation, "expires_at": self.clock()})
            return {"operation": operation, "status": "observed", "workload_passed": output["workload_passed"], "security_verdict": "not_established"}
        except BaseException:
            # No refund or lease release: in-flight sends may outlive the controller.
            with self.store.transaction() as tx:
                record = tx.get("load-operation", operation)
                record.update(status="uncertain", finished_at=self.clock())
                tx.put("load-operation", operation, record)
            raise

    def observation(self, case, operation, tx):
        record = tx.get("load-operation", operation)
        require(record is not None and record["status"] == "completed" and not record["invalidated"], "complete load producer unavailable")
        auth = self.guard(record["authorization"], case, tx)
        require(auth["operation"] == operation and digest(auth["spec"]) == record["authority_sha256"] and digest(record["output"]) == record["output_sha256"], "load producer binding differs")
        raw = read_file(self.store.root / "objects" / auth["tool"]["candidate"], auth["tool"]["binary"], 128 * 1024 * 1024)
        require(sha256(raw) == auth["tool"]["binary_sha256"], "k6 producer bytes changed")
        return record, auth
