"""Synthetic customers, immutable proposals and authenticated fixture producers."""

import copy
import json
import time

from m2_support import ROOT, World
from runtime_support import FakeDocker, Publisher, acceptance, source
from security_assessment.remediation import SourceReview, WORKER
from security_assessment.source_rules import inspect_sources
from security_runtime.common import canonical, read_file, sha256
from security_runtime.controller import Controller, HEAD_RESOURCES, selected_tree


ORIGINAL = '''def security_probe(request, state):
    record = state['records'][request['id']]
    if request['action'] == 'write':
        record['value'] = request['value']
    return {'value': record['value']}
'''
GOOD = '''def security_probe(request, state):
    record = state['records'][request['id']]
    if request.get('user') != record['owner'] or request.get('tenant') != record['tenant']:
        return {'error': 'denied'}
    if request['action'] == 'write':
        record['value'] = request['value']
    return {'value': record['value']}
'''
PARTIAL = GOOD.replace(" or request.get('tenant') != record['tenant']", "")
DENY_ALL = "def security_probe(request, state):\n    return {'error': 'denied'}\n"
DENY_AFTER_WRITE = ORIGINAL.replace("return {'value': record['value']}", "return {'error': 'denied'} if request.get('user') != record['owner'] else {'value': record['value']}")


def behavior():
    state = {"records": {"one": {"owner": "alice", "tenant": "alpha", "value": "synthetic-private"}}}
    cases = []
    for name, kind, actor, user, tenant, action in [
        ("owner-read", "legitimate", "owner", "alice", "alpha", "read"),
        ("owner-write", "legitimate", "owner", "alice", "alpha", "write"),
        ("other-write", "denied", "non-owner", "bob", "alpha", "write"),
        ("anonymous-read", "variant", "anonymous", None, None, "read"),
        ("tenant-read", "variant", "cross-tenant", "alice", "beta", "read")]:
        request = {"user": user, "tenant": tenant, "id": "one", "action": action, "value": "changed"}
        expected_state = copy.deepcopy(state)
        if kind == "legitimate" and action == "write": expected_state["records"]["one"]["value"] = "changed"
        response = {"value": "changed" if action == "write" else "synthetic-private"} if kind == "legitimate" else {"error": "denied"}
        cases.append({"id": name, "kind": kind, "actor": actor, "request": request, "state": copy.deepcopy(state), "expected": {"response": response, "state": expected_state}, "forbidden_response": {"value": "changed" if action == "write" else "synthetic-private"} if kind != "legitimate" else None})
    return {"entrypoint": "app.py", "cases": cases, "oracle_basis": "Synthetic record owner and tenant policy; compare concrete response and all serialized state.", "limitations": "Finite in-memory Python model; no database, deployed identity or hostile-code integrity assurance."}


class OutputDocker(FakeDocker):
    def __init__(self):
        super().__init__()
        self.payload = b"{}"
    def execute(self, operation, image, component, inputs, specification, limits, guard, output, resources=None):
        guard()
        output.write(self.payload)
        return {"exit_code": 0, "bytes": len(self.payload), "sha256": sha256(self.payload), "elapsed_seconds": 0.01}


class ReviewWorld(World):
    def __init__(self, docker=None):
        super().__init__(urls=False)
        (self.target / "app.py").write_bytes(ORIGINAL.encode("utf-8"))
        self.control = SourceReview(self.state, ROOT, lambda: self.now[0])
        self.publisher = Publisher()
        self.publisher.contents["head"] = {p: read_file(ROOT, p) for p in selected_tree(ROOT, HEAD_RESOURCES)}
        self.publisher.contents["m3"] = {p: read_file(ROOT, p) for p in selected_tree(ROOT, ["scripts"])}
        self.docker = docker(self.state) if callable(docker) else docker or OutputDocker()
        self.runtime = Controller(self.state, ROOT, self.publisher, self.docker)
        self.runtime.enroll(source("head", "head", HEAD_RESOURCES))
        self.runtime.enroll(source("m3", "tool", ["scripts"]))
        for name in ("head", "runtime", "m3"):
            candidate = self.runtime.prepare(name)["candidate"]
            self.runtime.review(acceptance(candidate))
            self.runtime.activate(candidate)
        self.sequence = 0
        self.create()

    def execute(self, arguments, payload=None, root=None, inputs=None, components=None):
        self.sequence += 1
        name = "check-" + str(self.sequence)
        self.runtime.authorize({"id": name, "root": str(root or self.target), "inputs": inputs or self.spec["source"]["files"], "components": components or ["m3"], "network": "none",
            "operations": [{"id": "m3-check", "component": "m3", "entrypoint": WORKER, "interpreter": "python", "arguments": arguments, "timeout_seconds": 15, "max_output_bytes": 1024 * 1024}],
            "limits": {"calls": 1, "seconds": 15, "expires_at": time.time() + 600, "memory_mb": 128, "cpus": 0.5, "pids": 32, "tmpfs_mb": 8}})
        run = self.runtime.begin(name)["run"]
        if payload is not None: self.docker.payload = canonical(payload)
        return self.runtime.execute(run, "m3-check")["operation"]

    def scan(self):
        output = inspect_sources({p: (self.target / p).read_bytes() for p in self.spec["source"]["files"]})
        op = self.execute(["inspect"], output)
        return self.control.import_scan("demo", {"id": "scan", "operation": op})

    def proposal(self, content=GOOD, name="fix"):
        if not self.state.get("assessment", "demo")["findings"]:
            self.control.record("demo", self.observation())
            self.control.add_finding("demo", self.finding())
        value = {"id": name, "finding": "finding", "rationale": "Enforce owner and tenant before reading or writing a synthetic record.", "replacements": [{"path": "app.py", "before_sha256": sha256(ORIGINAL.encode()), "content": content}], "behavior": behavior()}
        self.control.propose("demo", value)
        destination = self.root / ("candidate-" + name)
        self.control.export("demo", name, destination)
        return value, destination

    def test_record(self, proposal, scenario, variant, root=None, payload=None):
        args = ["probe", proposal["behavior"]["entrypoint"], canonical({"request": scenario["request"], "state": scenario["state"]}).decode()]
        operation = self.execute(args, payload, root)
        return self.control.test("demo", {"proposal": proposal["id"], "case": scenario["id"], "variant": variant, "operation": operation, "root": str(root) if root else None})

    def accept(self, name="fix"):
        return self.control.accept("demo", {"proposal": name, "reviewer": "Synthetic evaluator", "reason": "Reviewed original, candidate and finite cases.", "oracle_review": "Inspected the synthetic adapter and observed response/state contract; no target-authored pass flags accepted.", "residual_risk": "No live environment, persistence or malicious target-code assurance."})
