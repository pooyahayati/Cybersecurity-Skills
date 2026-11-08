"""Authenticated, single-use M4 network intentions; M1 execution stays offline."""

import copy
import hmac
import os
from pathlib import Path
import secrets
import sys
import time
from urllib.parse import urljoin

from .common import canonical, digest, fields, identifier, parse, read_file, require, sha256
from .controller import Controller, HEAD_RESOURCES, selected_tree
from .process import bounded_process
from .web_scope import authority, credential, url


class WebController:
    def __init__(self, store, package, upstream=None, clock=time.time):
        self.store, self.package, self.clock = store, Path(package).resolve(), clock
        self.controller = Controller(store, self.package, upstream=upstream, clock=clock)

    def fresh_head(self):
        candidate = self.store.get("active", "head")
        require(candidate is not None, "current reviewed head is required")
        record = self.controller.check_current(candidate)
        require(record["manifest"] == selected_tree(self.package, HEAD_RESOURCES), "reload current head before collection")
        with self.store.transaction() as tx: self.controller.reviewed(candidate, record, tx)
        return {"candidate": candidate, "record_sha256": digest(record), "manifest": record["manifest"]}

    def authorize(self, case, value):
        deployment = next((d for d in case["scope"]["deployments"] if d["id"] == value.get("deployment")), None)
        require(deployment is not None, "deployment unavailable")
        authority(value, deployment, {a["id"]: a for a in case["scope"]["model"]["actors"]}, self.clock())
        head = self.fresh_head()
        record = {"spec": copy.deepcopy(value), "assessment": case["scope"]["id"], "scope_sha256": case["scope_sha256"],
                  "head": head, "revoked": False, "requests_used": 0, "seconds_used": 0, "body_bytes_reserved": 0,
                  "intents": {}, "created_at": self.clock()}
        with self.store.transaction() as tx:
            require(tx.get("web-authority", value["id"]) is None, "authority ID cannot be reused")
            tx.put("web-authority", value["id"], record)
        return {"status": "authorized", "authorization": value["id"], "security_verdict": "not_established"}

    def guard(self, key, case=None, tx=None):
        record = (tx or self.store).get("web-authority", key)
        require(record is not None and not record["revoked"] and self.clock() < record["spec"]["limits"]["expires_at"], "web authority expired or revoked")
        if case is not None:
            require(case["scope"]["id"] == record["assessment"] and case["scope_sha256"] == record["scope_sha256"], "web scope changed")
        head = (tx or self.store).get("candidate", record["head"]["candidate"])
        require(head is not None and digest(head) == record["head"]["record_sha256"]
                and not (tx or self.store).get("revocation", "head", False), "head producer changed or revoked")
        self.controller.reviewed(record["head"]["candidate"], head, tx or self.store)
        require(selected_tree(self.package, HEAD_RESOURCES) == record["head"]["manifest"], "collector implementation changed")
        return record

    def cancel(self, key):
        with self.store.transaction() as tx:
            record = tx.get("web-authority", key)
            require(record is not None, "authority unavailable")
            record["revoked"] = True
            tx.put("web-authority", key, record)
        return {"status": "cancelled", "authorization": key}

    def _request(self, payload, guard):
        env = {"PATH": os.defpath}
        if os.name == "nt":
            for name in ("SYSTEMROOT", "WINDIR", "TEMP", "TMP"):
                if name in os.environ: env[name] = os.environ[name]
        result = bounded_process([sys.executable, "-I", "-B", str(Path(__file__).with_name("web_worker.py"))],
            env, payload["timeout"], 16384, guard=guard, input_data=canonical(payload))
        require(result["exit_code"] == 0, "network observation unavailable")
        output = parse(result["content"], 16384)
        fields(output, {"schema_version", "status", "body_bytes", "body_sha256", "location", "address", "tls", "headers"})
        require(output["schema_version"] == 1, "unsupported collector output")
        return output

    def execute(self, case, key, route_id, credentials=None, ca=None):
        auth = self.guard(key, case)
        route = next((r for r in auth["spec"]["routes"] if r["id"] == route_id), None)
        require(route is not None, "route unavailable")
        supplied = None
        if route["credential"] is not None:
            require(isinstance(credentials, dict) and route["credential"] in credentials, "selected credential is unavailable")
            supplied = credentials[route["credential"]]
            credential(supplied)
        require((ca is None and auth["spec"]["ca_sha256"] is None) or isinstance(ca, str)
                and sha256(ca.encode("ascii")) == auth["spec"]["ca_sha256"], "CA differs from authorization")
        credential_binding = hmac.new(self.store.key, canonical(supplied), "sha256").hexdigest()
        operation = "web-" + secrets.token_hex(16)
        with self.store.transaction() as tx:
            auth = self.guard(key, case, tx)
            require(route_id not in auth["intents"], "route intent already consumed; inspect its outcome before new authority")
            auth["intents"][route_id] = operation
            tx.put("web-authority", key, auth)
            tx.put("web-operation", operation, {"authorization": key, "authority_sha256": digest(auth["spec"]),
                "route": route_id, "credential_binding": credential_binding, "status": "unfinished", "started_at": self.clock(), "hops": [], "invalidated": False})
        limits, destination, visited = auth["spec"]["limits"], route["url"], []
        try:
            while True:
                require(destination not in visited and len(visited) <= len(route["redirects"]), "redirect cycle or hop limit")
                visited.append(destination)
                with self.store.transaction() as tx:
                    auth = self.guard(key, case, tx)
                    require(auth["requests_used"] < limits["requests"] and auth["seconds_used"] + limits["timeout_seconds"] <= limits["seconds"]
                            and auth["body_bytes_reserved"] + limits["response_bytes"] <= limits["body_bytes"], "aggregate web budget exhausted")
                    auth["requests_used"] += 1
                    auth["seconds_used"] += limits["timeout_seconds"]
                    auth["body_bytes_reserved"] += limits["response_bytes"]
                    tx.put("web-authority", key, auth)
                    record = tx.get("web-operation", operation)
                    record["hops"].append({"url_sha256": sha256(destination.encode()), "status": "reserved", "reserved_at": self.clock()})
                    tx.put("web-operation", operation, record)
                output = self._request({"url": destination, "method": route["method"], "addresses": auth["spec"]["addresses"],
                    "network": auth["spec"]["network"], "timeout": limits["timeout_seconds"], "limit": limits["response_bytes"],
                    "credential": supplied, "ca": ca}, lambda: self.guard(key, case))
                with self.store.transaction() as tx:
                    self.guard(key, case, tx)
                    record = tx.get("web-operation", operation)
                    record["hops"][-1].update(status="observed", output={k: v for k, v in output.items() if k != "location"})
                    tx.put("web-operation", operation, record)
                if output["status"] in {301, 302, 303, 307, 308}:
                    require(isinstance(output["location"], str), "redirect destination missing")
                    redirect = urljoin(destination, output["location"])
                    require(url(redirect)[:3] == url(route["url"])[:3] and redirect in route["redirects"], "redirect is outside exact authority")
                    destination = redirect
                    continue
                matched = output["status"] in route["statuses"] and (route["body_sha256"] is None or route["body_sha256"] == output["body_sha256"])
                with self.store.transaction() as tx:
                    self.guard(key, case, tx)
                    record = tx.get("web-operation", operation)
                    record.update(status="completed", finished_at=self.clock(), matched=matched)
                    tx.put("web-operation", operation, record)
                return {"operation": operation, "status": "observed", "expectation_matched": matched, "security_verdict": "not_established"}
        except BaseException:
            # A send may have happened. Never refund budgets or replay this intent.
            with self.store.transaction() as tx:
                record = tx.get("web-operation", operation)
                record.update(status="uncertain", finished_at=self.clock())
                tx.put("web-operation", operation, record)
            raise

    def observation(self, case, operation, tx):
        record = tx.get("web-operation", operation)
        require(record is not None and record["status"] == "completed" and not record["invalidated"], "complete network producer unavailable")
        auth = self.guard(record["authorization"], case, tx)
        require(digest(auth["spec"]) == record["authority_sha256"] and auth["intents"].get(record["route"]) == operation, "network producer binding differs")
        route = next(r for r in auth["spec"]["routes"] if r["id"] == record["route"])
        return record, auth, route

    def invalidate(self, operation):
        with self.store.transaction() as tx:
            record = tx.get("web-operation", operation)
            require(record is not None, "network observation unavailable")
            record["invalidated"] = True
            tx.put("web-operation", operation, record)
        return {"status": "invalidated", "operation": operation}
