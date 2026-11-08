"""Private M2 ledger: bounded intake and evidence semantics, never target execution."""

import copy
from datetime import date
from pathlib import Path
import secrets
import time

from security_runtime.common import (canonical, digest, fields, identifier,
                                     parse, read_file, require, sha256, text)
from security_runtime.controller import write_bundle
from . import contracts as contract
from .discovery import discover
from .redaction import markdown, redact


def load_catalog(package):
    value = parse(read_file(package, "config/assessment-controls.json", 262144))
    fields(value, {"schema_version", "catalog_version", "coverage", "reference_snapshot", "controls"})
    contract.version(value["schema_version"])
    text(value["catalog_version"], 64)
    text(value["coverage"], 256)
    reference = value["reference_snapshot"]
    fields(reference, {"standard", "edition", "release", "checked_on", "selection"})
    require(reference["standard"] == "OWASP ASVS" and reference["edition"] == "5.0.0"
            and reference["release"] == "https://github.com/OWASP/ASVS/releases/tag/v5.0.0_release",
            "unsupported standard mapping")
    date.fromisoformat(text(reference["checked_on"], 10))
    text(reference["selection"], 1024)
    modules = parse(read_file(package, "config/modules.json"))["modules"]
    module_ids = {row["id"] for row in modules}
    names = set()
    for row in contract.items(value["controls"], 64, 1):
        fields(row, {"id", "module", "title", "surfaces", "actor_specific", "methods", "asvs_chapter", "next_step"})
        identifier(row["id"])
        identifier(row["module"])
        require(row["module"] in module_ids, "control refers to an unknown module")
        require(row["id"] not in names and type(row["actor_specific"]) is bool, "invalid control catalog")
        names.add(row["id"])
        for item in contract.items(row["surfaces"], 3, 1): contract.choice(item, {"source", "deployment", "context"})
        for item in contract.items(row["methods"], 5, 1): contract.choice(item, contract.METHODS)
        require(len(set(row["surfaces"])) == len(row["surfaces"]) and len(set(row["methods"])) == len(row["methods"]),
                "duplicate control surface or method")
        text(row["title"], 256)
        text(row["next_step"], 1024)
        require(row["asvs_chapter"] is None or row["asvs_chapter"] in {"V1", "V2", "V6", "V8", "V12", "V13", "V14", "V15"}, "invalid standard reference")
    return value


class Assessment:
    def __init__(self, store, package, clock=time.time):
        self.store, self.package, self.clock = store, Path(package).resolve(), clock
        self.catalog = load_catalog(self.package)
        paths = ["scripts/m2_assess.py", "scripts/security_runtime/common.py", "scripts/security_runtime/store.py",
                 "scripts/security_runtime/controller.py", "scripts/security_runtime/private.py",
                 "config/assessment-controls.json", "config/modules.json"] + ["scripts/security_assessment/" + name + ".py" for name in ("contracts", "discovery", "redaction", "service")]
        self.engine = digest({path: sha256(read_file(self.package, path)) for path in paths})

    def _case(self, tx, key):
        identifier(key)
        case = tx.get("assessment", key)
        require(case is not None, "assessment is unavailable")
        require(case["catalog_sha256"] == digest(self.catalog), "control catalog changed; create a new assessment")
        require(case["engine_sha256"] == self.engine, "assessment engine changed; create a new assessment")
        return case

    def _capture(self, specification):
        if specification is None:
            return None, {"facts": [], "gaps": [{"reason": "source access unavailable"}], "platform_hints": [],
                          "coverage": "no source", "installed_versions_verified": False, "inventory_truncated": False}
        root = Path(specification["root"]).absolute()
        require(root == root.resolve(strict=True) and root.is_dir(), "source root must be a canonical directory")
        for other in (self.store.root, self.package):
            require(not root.is_relative_to(other) and not other.is_relative_to(root), "source, state and package must be disjoint")
        contents = {}
        total = 0
        for path in sorted(specification["files"]):
            contents[path] = read_file(root, path, 1024 * 1024)
            total += len(contents[path])
            require(total <= 16 * 1024 * 1024, "selected source exceeds capture limit")
        temporary, manifest = write_bundle(self.store.root / "quarantine", contents)
        capture = "capture-" + secrets.token_hex(16)
        destination = self.store.root / "objects" / capture
        temporary.rename(destination)
        import os
        if os.name != "nt": destination.chmod(0o555)
        return {"object": capture, "root": str(root), "manifest": manifest,
                "declared_revision": specification["revision"], "captured_at": self.clock()}, discover(contents)

    def _controls(self, spec):
        result = {}
        for template in self.catalog["controls"]:
            for surface in template["surfaces"]:
                environments = [d["id"] for d in spec["deployments"]] or [None] if surface == "deployment" else [None]
                actors = [a["id"] for a in spec["model"]["actors"]] or [None] if template["actor_specific"] else [None]
                for environment in environments:
                    for actor in actors:
                        key = "control-" + digest([template["id"], surface, environment, actor])[:24]
                        accessible = surface == "context" or surface == "source" and spec["source"] is not None or surface == "deployment" and environment is not None
                        result[key] = {"id": key, "definition": copy.deepcopy(template), "surface": surface,
                                       "deployment": environment, "actor": actor, "accessible": accessible,
                                       "state": "not_started" if accessible else "blocked", "outcome": "unverified",
                                       "reason": "No assessment evidence recorded." if accessible else "Required source or environment scope is unavailable.",
                                       "evidence": []}
        require(len(result) <= 2048, "control inventory exceeds its limit")
        return result

    def create(self, value):
        spec = copy.deepcopy(value)
        contract.scope(spec)
        with self.store.transaction() as tx:
            prior = tx.get("assessment", spec["id"])
            if prior is not None:
                self._case(tx, spec["id"])
                require(prior["scope_sha256"] == digest(spec), "assessment ID already binds different inputs")
                return {"status": "exists"}
        capture, discovery = self._capture(spec["source"])
        case = {"schema_version": 1, "id": spec["id"], "scope": spec, "scope_sha256": digest(spec),
                "catalog_sha256": digest(self.catalog), "engine_sha256": self.engine, "source": capture, "discovery": discovery,
                "controls": self._controls(spec), "evidence": {}, "findings": {}, "chains": [],
                "created_at": self.clock()}
        with self.store.transaction() as tx:
            require(tx.get("assessment", spec["id"]) is None, "assessment was created concurrently")
            tx.put("assessment", spec["id"], case)
        return {"status": "created", "controls": len(case["controls"])}

    def _bindings(self, case, control, files, actor, context_refs):
        require(control["accessible"], "required assessment surface is unavailable")
        require(actor == control["actor"], "evidence actor differs from the control scope")
        bindings = {"control": digest(control["definition"])}
        context = {"asset:" + row["id"]: row for row in case["scope"]["model"]["assets"]}
        context.update({"flow:" + row["id"]: row for row in case["scope"]["model"]["flows"]})
        require(all(ref in context for ref in context_refs), "context reference is outside this assessment")
        bindings["context"] = {ref: digest(context[ref]) for ref in context_refs}
        # A flow depends on its actor and asset, even if the caller omits an
        # explicit asset reference. Never let a narrower declaration erase it.
        for ref in context_refs:
            if ref.startswith("flow:"):
                flow = context[ref]
                bindings["context"]["asset:" + flow["asset"]] = digest(context["asset:" + flow["asset"]])
                bindings["context"]["actor:" + flow["actor"]] = digest(next(a for a in case["scope"]["model"]["actors"] if a["id"] == flow["actor"]))
        if control["definition"]["id"] in {"data", "authorization"} and case["scope"]["model"]["assets"]:
            require(any(ref.startswith("asset:") for ref in context_refs), "this control needs an asset binding")
        if control["definition"]["id"] == "business" and case["scope"]["model"]["flows"]:
            require(any(ref.startswith("flow:") for ref in context_refs), "this control needs a flow binding")
        if actor is not None:
            row = next((a for a in case["scope"]["model"]["actors"] if a["id"] == actor), None)
            require(row is not None, "actor is outside this assessment")
            bindings["actor"] = digest(row)
        if control["surface"] == "source":
            require(case["source"] is not None and files, "source evidence needs selected file references")
            capture = case["source"]
            require(all(path in capture["manifest"] for path in files), "evidence path is outside captured source")
            bindings["source_root"] = digest(capture["root"])
            bindings["files"] = {path: capture["manifest"][path] for path in files}
        else:
            require(not files, "file references belong to source evidence")
        if control["surface"] == "deployment":
            deployment = next(d for d in case["scope"]["deployments"] if d["id"] == control["deployment"])
            bindings["deployment"] = digest(deployment)
        if control["surface"] == "context":
            bindings["model"] = digest(case["scope"]["model"])
        return bindings

    def _routes(self, case):
        """Planning relevance only; never activate a tool or exclude a control."""
        spec, discovered = case["scope"], case["discovery"]
        mapping = {"identity": "authentication", "data-protection": "sensitive_data",
                   "business-logic": "transactions", "ai-security": "ai", "infrastructure": "infrastructure",
                   "delivery": "delivery", "resilience": "resilience"}
        routes = []
        for module in dict.fromkeys(row["module"] for row in self.catalog["controls"]):
            feature = mapping.get(module)
            declared = spec["model"]["capabilities"][feature]["state"] if feature else "unknown"
            facts = []
            if module in {"application", "supply-chain"}:
                facts = [f for f in discovered["facts"] if f["kind"] in ({"language"} if module == "application" else {"package"})]
            elif module == "ai-security":
                facts = [f for f in discovered["platform_hints"] if f["name"] == "AI dependency"]
            if module == "architecture":
                state, basis = "relevant", "Architecture and trust-boundary planning is always required."
            elif facts:
                state, basis = "relevant", "Selected structured declarations support planning relevance; runtime use remains unverified."
            elif module == "deployed-web" and spec["deployments"]:
                state, basis = "relevant", "An explicit URL scope exists; this supplies no request permission."
            elif declared == "present":
                state, basis = "needs_confirmation", "The operator declares this capability; independent corroboration is still required."
            elif declared == "absent":
                state, basis = "exclusion_needs_evidence", "Declared absence cannot remove controls without a justified evidence-backed exclusion."
            else:
                state, basis = "unknown", "Available facts do not establish applicability; retain the coverage gap."
            routes.append({"module": module, "relevance": state, "basis": basis, "declared_capability": declared,
                           "observed_fact_count": len(facts), "execution": "not_activated"})
        return routes

    def _validity(self, case, item, tx, file_cache=None):
        if item.get("invalidated"):
            return False, "Explicitly invalidated."
        if self.clock() >= item["spec"]["expires_at"]:
            return False, "Evidence expired."
        spec = item["spec"]
        control = case["controls"].get(spec["control"])
        if control is None:
            return False, "Control is unavailable."
        try:
            bindings = self._bindings(case, control, spec["files"], spec["actor"], spec["context_refs"])
            if bindings != item["bindings"]:
                return False, "Relevant captured context changed."
            if "files" in bindings:
                file_cache = {} if file_cache is None else file_cache
                for path, fingerprint in bindings["files"].items():
                    if path not in file_cache:
                        file_cache[path] = sha256(read_file(case["source"]["root"], path, 1024 * 1024))
                    if file_cache[path] != fingerprint:
                        return False, "Relevant current source changed."
            if item["origin"] == "m1_controller":
                self._operation(case, control, spec, tx, expected=item["producer"], file_cache=file_cache)
        except (OSError, ValueError, KeyError, TypeError):
            return False, "Evidence bindings or producer are unavailable."
        return True, "Bound to the recorded selected inputs; unobserved surfaces remain unknown."

    def _operation(self, case, control, spec, tx, expected=None, file_cache=None):
        require(control["surface"] == "source" and case["source"] is not None,
                "M1 offline operations cannot establish deployed behavior")
        operation = tx.get("operation", spec["operation"])
        require(operation is not None and operation["status"] == "completed" and isinstance(operation.get("result"), dict),
                "controller operation is not completed with a result")
        run = tx.get("run", operation["run"])
        auth = tx.get("authorization", operation["authorization"])
        require(run is not None and auth is not None and run["authorization"] == operation["authorization"],
                "controller execution bindings are unavailable")
        require(not auth["revoked"] and operation["specification"] in auth["spec"]["operations"]
                and set(run["bindings"]) == {"head", "runtime"} | set(auth["spec"]["components"])
                and run["started_at"] <= operation["started_at"] <= operation["finished_at"] <= auth["spec"]["limits"]["expires_at"],
                "controller operation is outside its recorded authority")
        require(auth["spec"]["root"] == case["source"]["root"]
                and all(auth["manifest"].get(path) == case["source"]["manifest"].get(path) for path in spec["files"])
                and all(case["source"]["manifest"].get(path) == fingerprint for path, fingerprint in auth["manifest"].items()),
                "controller target or selected inputs differ")
        # All mounted inputs can affect a producer, regardless of the citations
        # supplied by an operator. Refuse to shrink the dependency closure.
        file_cache = {} if file_cache is None else file_cache
        for path, fingerprint in auth["manifest"].items():
            if path not in file_cache:
                file_cache[path] = sha256(read_file(case["source"]["root"], path, 1024 * 1024))
            require(file_cache[path] == fingerprint, "controller input dependency changed")
        require(spec["observed_at"] == operation["finished_at"], "execution observation time differs from its producer")
        result = operation["result"]
        content = read_file(self.store.root, spec["operation"] + ".output", operation["specification"]["max_output_bytes"])
        require(result["bytes"] == len(content) and result["sha256"] == sha256(content), "controller output integrity failed")
        components = {}
        for component, candidate_id in run["bindings"].items():
            require(not tx.get("revocation", component, False), "evidence producer was revoked")
            candidate = tx.get("candidate", candidate_id)
            require(candidate is not None and candidate["component"] == component, "producer identity is unavailable")
            if candidate["kind"] == "data":
                source = tx.get("source", component)
                require(source is not None and self.clock() < candidate["resolved"]["identity"]["published_at"] + source["spec"]["data_max_age_seconds"],
                        "producer rule or data feed is stale")
            components[component] = digest(candidate)
        producer = {"operation": spec["operation"], "record_sha256": digest(operation), "components": components,
                    "output_sha256": sha256(content), "exit_code": result["exit_code"],
                    "inputs_sha256": digest(auth["manifest"]),
                    "role_identity_verified": False}
        require(expected is None or producer == expected, "producer record changed")
        return producer

    def record(self, key, value, controller=False):
        spec = copy.deepcopy(value)
        contract.observation(spec, self.clock(), controller)
        with self.store.transaction() as tx:
            case = self._case(tx, key)
            control = case["controls"].get(spec["control"])
            require(control is not None and spec["method"] in control["definition"]["methods"], "evidence method does not match this control")
            if spec["method"] == "deployed_observation":
                require(control["surface"] == "deployment", "deployed observations require deployment scope")
            if spec["method"] == "source_reasoning":
                require(control["surface"] == "source", "source reasoning requires source scope")
            bindings = self._bindings(case, control, spec["files"], spec["actor"], spec["context_refs"])
            prior = case["evidence"].get(spec["id"])
            if prior is not None:
                require(prior["spec"] == spec and prior["bindings"] == bindings,
                        "evidence ID already binds different inputs")
                return {"status": "exists"}
            require(len(case["evidence"]) < 256, "evidence inventory exceeds its limit")
            producer = self._operation(case, control, spec, tx) if controller else None
            item = {"spec": spec, "bindings": bindings, "origin": "m1_controller" if controller else "operator_observation",
                    "producer": producer, "recorded_at": self.clock(), "invalidated": False}
            valid, _ = self._validity(case, item, tx)
            require(valid, "new evidence does not match current inputs")
            case["evidence"][spec["id"]] = item
            tx.put("assessment", key, case)
        return {"status": "recorded", "origin": item["origin"]}

    def invalidate(self, key, evidence, reason):
        identifier(evidence)
        text(reason, 1024)
        with self.store.transaction() as tx:
            case = self._case(tx, key)
            require(evidence in case["evidence"], "evidence is outside this assessment")
            case["evidence"][evidence].update(invalidated=True, invalidation_reason=reason)
            tx.put("assessment", key, case)
        return {"status": "invalidated"}

    def refresh(self, key, value):
        fields(value, {"schema_version", "deployments", "model"})
        contract.version(value["schema_version"])
        value = copy.deepcopy(value)
        contract.deployments(value["deployments"])
        contract.model(value["model"])
        with self.store.transaction() as tx:
            previous = self._case(tx, key)
        require({d["id"] for d in value["deployments"]} == {d["id"] for d in previous["scope"]["deployments"]},
                "new deployment scope needs a new assessment")
        require({a["id"] for a in value["model"]["actors"]} == {a["id"] for a in previous["scope"]["model"]["actors"]},
                "new actor scope needs a new assessment")
        capture, discovery = self._capture(previous["scope"]["source"])
        with self.store.transaction() as tx:
            case = self._case(tx, key)
            require(case == previous, "assessment changed during refresh")
            case["scope"]["deployments"] = value["deployments"]
            case["scope"]["model"] = value["model"]
            case["source"], case["discovery"] = capture, discovery
            file_cache = {}
            for item in case["evidence"].values():
                valid, _ = self._validity(case, item, tx, file_cache)
                if not valid: item.update(invalidated=True, invalidation_reason="Relevant bindings changed or evidence became unavailable.")
            tx.put("assessment", key, case)
        return {"status": "refreshed"}

    def _evidence(self, case, control, evidence, tx, require_valid=True):
        contract.ids(evidence, minimum=1)
        result = []
        for name in evidence:
            item = case["evidence"].get(name)
            require(item is not None and item["spec"]["control"] == control["id"], "evidence belongs to another control or assessment")
            if require_valid: require(self._validity(case, item, tx)[0], "required evidence is stale or invalid")
            result.append(item)
        return result

    def coverage(self, key, value):
        fields(value, {"schema_version", "control", "state", "outcome", "reason", "evidence"})
        contract.version(value["schema_version"])
        text(value["control"], 128)
        contract.choice(value["state"], contract.PROGRESS)
        contract.choice(value["outcome"], contract.OUTCOMES)
        text(value["reason"], 2048)
        contract.ids(value["evidence"])
        with self.store.transaction() as tx:
            case = self._case(tx, key)
            control = case["controls"].get(value["control"])
            require(control is not None, "unknown control")
            if value["state"] in {"reviewed", "not_applicable"}:
                observations = self._evidence(case, control, value["evidence"], tx)
                require(control["accessible"], "missing access cannot establish an exclusion or completed review")
                require(value["outcome"] in ({"not_applicable"} if value["state"] == "not_applicable" else {"satisfied", "failed", "inconclusive"}),
                        "coverage progress and outcome disagree")
                require(value["outcome"] != "satisfied" or all(o["producer"] is None or o["producer"]["exit_code"] == 0 for o in observations),
                        "failed execution cannot establish a satisfied control")
            else:
                require(value["outcome"] == "unverified" and not value["evidence"], "unfinished coverage cannot claim an outcome")
            control.update({name: copy.deepcopy(value[name]) for name in ("state", "outcome", "reason", "evidence")})
            tx.put("assessment", key, case)
        return {"status": "coverage_recorded"}

    def _finding_basis(self, case, value, tx):
        control = case["controls"].get(value["control"])
        require(control is not None and value["actor"] == control["actor"], "finding scope or actor differs")
        support = self._evidence(case, control, value["evidence"], tx, False) if value["evidence"] else []
        counter = self._evidence(case, control, value["counterevidence"], tx, False) if value["counterevidence"] else []
        required = support if value["disposition"] == "confirmed" else counter if value["disposition"] == "rejected" else []
        if value["disposition"] != "needs_validation":
            require(required and all(self._validity(case, item, tx)[0] for item in required), "disposition requires valid supporting or refuting evidence")
        return control

    def add_finding(self, key, value):
        spec = copy.deepcopy(value)
        contract.finding(spec)
        with self.store.transaction() as tx:
            case = self._case(tx, key)
            self._finding_basis(case, spec, tx)
            prior = case["findings"].get(spec["id"])
            if prior is not None:
                require(prior["spec"] == spec, "finding ID already binds different inputs")
                return {"status": "exists"}
            require(len(case["findings"]) < 256, "finding inventory exceeds its limit")
            case["findings"][spec["id"]] = {"spec": spec, "recorded_at": self.clock(), "decisions": []}
            tx.put("assessment", key, case)
        return {"status": "finding_recorded"}

    def decide(self, key, value):
        fields(value, {"schema_version", "finding", "disposition", "evidence", "counterevidence", "reason"})
        contract.version(value["schema_version"])
        identifier(value["finding"])
        contract.choice(value["disposition"], {"confirmed", "needs_validation", "rejected"})
        text(value["reason"], 2048)
        contract.ids(value["evidence"])
        contract.ids(value["counterevidence"])
        require(not set(value["evidence"]) & set(value["counterevidence"]), "evidence cannot refute itself")
        with self.store.transaction() as tx:
            case = self._case(tx, key)
            finding = case["findings"].get(value["finding"])
            require(finding is not None and len(finding["decisions"]) < 32, "finding is unavailable or decision limit reached")
            updated = dict(finding["spec"], **{name: copy.deepcopy(value[name]) for name in ("disposition", "evidence", "counterevidence")})
            self._finding_basis(case, updated, tx)
            finding["decisions"].append({"previous": {name: finding["spec"][name] for name in ("disposition", "evidence", "counterevidence")},
                                        "reason": value["reason"], "recorded_at": self.clock()})
            finding["spec"] = updated
            tx.put("assessment", key, case)
        return {"status": "decision_recorded"}

    def link(self, key, value):
        fields(value, {"schema_version", "from", "to", "reason"})
        contract.version(value["schema_version"])
        identifier(value["from"])
        identifier(value["to"])
        text(value["reason"], 2048)
        with self.store.transaction() as tx:
            case = self._case(tx, key)
            require(value["from"] in case["findings"] and value["to"] in case["findings"]
                    and value["from"] != value["to"], "chain endpoint is outside this assessment or self-referential")
            pair = (value["from"], value["to"])
            for row in case["chains"]:
                if (row["from"], row["to"]) == pair:
                    require(row == value, "chain already binds different reasoning")
                    return {"status": "exists"}
            require(len(case["chains"]) < 512, "chain inventory exceeds its limit")
            graph = {}
            for row in case["chains"]: graph.setdefault(row["from"], []).append(row["to"])
            pending, seen = [value["to"]], set()
            while pending:
                node = pending.pop()
                require(node != value["from"], "attack-chain links must not contain cycles")
                if node not in seen:
                    seen.add(node)
                    pending.extend(graph.get(node, []))
            case["chains"].append(copy.deepcopy(value))
            tx.put("assessment", key, case)
        return {"status": "chain_recorded"}

    def report(self, key):
        with self.store.transaction() as tx:
            case = self._case(tx, key)
            file_cache = {}
            validity = {name: self._validity(case, item, tx, file_cache) for name, item in case["evidence"].items()}
            controls, evidence, findings, groups = [], [], [], {}
            for row in case["controls"].values():
                current = copy.deepcopy(row)
                if current["evidence"] and not all(validity[name][0] for name in current["evidence"]):
                    current.update(state="blocked", outcome="unverified", reason="Recorded review has stale or invalid evidence.")
                definition = current.pop("definition")
                current.update(catalog_id=definition["id"], module=definition["module"], title=definition["title"],
                               next_step=definition["next_step"], reference={"standard": "OWASP ASVS", "edition": "5.0.0", "section": definition["asvs_chapter"], "mapping": "chapter only"} if definition["asvs_chapter"] else None)
                current["environment"] = next((d["environment"] for d in case["scope"]["deployments"] if d["id"] == current["deployment"]),
                                               "selected_source" if current["surface"] == "source" else "unknown")
                controls.append(current)
            for name, item in case["evidence"].items():
                spec = item["spec"]
                evidence.append({"id": name, "control": spec["control"], "method": spec["method"], "actor": spec["actor"],
                                 "context_refs": spec["context_refs"], "files": spec["files"], "summary": spec["summary"],
                                 "origin": item["origin"], "observed_at": spec["observed_at"], "expires_at": spec["expires_at"],
                                 "valid": validity[name][0], "validity_reason": validity[name][1],
                                 "execution_exit_code": item["producer"]["exit_code"] if item["producer"] else None,
                                 "producer": {"operation": item["producer"]["operation"], "record_sha256": item["producer"]["record_sha256"],
                                              "output_sha256": item["producer"]["output_sha256"],
                                              "inputs_sha256": item["producer"]["inputs_sha256"],
                                              "components": [{"id": k, "record_sha256": v} for k, v in item["producer"]["components"].items()]} if item["producer"] else None,
                                 "role_identity_verified": False})
            for name, item in case["findings"].items():
                spec = copy.deepcopy(item["spec"])
                basis = spec["evidence"] if spec["disposition"] == "confirmed" else spec["counterevidence"] if spec["disposition"] == "rejected" else []
                spec["recorded_disposition"] = spec["disposition"]
                if basis and not all(validity[eid][0] for eid in basis):
                    spec["disposition"] = "needs_validation"
                    spec["uncertainty"] = "Earlier disposition lost valid evidence. " + spec["uncertainty"]
                spec["remediation_state"] = "not_verified"
                spec["decision_count"] = len(item["decisions"])
                findings.append(spec)
                group = digest([spec["root_cause"], spec["control"], spec["actor"]])[:24]
                groups.setdefault(group, {"root_cause": spec["root_cause"], "control": spec["control"], "members": [], "dispositions": []})
                groups[group]["members"].append(name)
                if spec["disposition"] not in groups[group]["dispositions"]: groups[group]["dispositions"].append(spec["disposition"])
            priority = {name: index for index, name in enumerate(("critical", "high", "medium", "low", "informational"))}
            findings.sort(key=lambda f: (f["disposition"] == "rejected", priority[f["severity"]], f["id"]))
            counts = {state: sum(c["state"] == state for c in controls) for state in sorted(contract.PROGRESS)}
            source = case["source"]
            limitations = ["This is a partial planning inventory, not full standards coverage or a security certificate.",
                          "No target code, website requests, scanner or remediation was executed by M2.",
                          "Operator observations are judgments, not independently authenticated executions.",
                          "Declared actors, assets, flows, revisions and deployment artifacts require corroboration.",
                          "No finding or completed-review count proves that an application is secure.",
                          "Review redaction before sharing; arbitrary sensitive information cannot be recognized automatically."]
            if source is None: limitations.append("Private source and dependencies are unavailable.")
            else: limitations.append("Source coverage includes only the explicitly selected files, not the whole repository.")
            if not case["scope"]["deployments"]: limitations.append("No deployment is in scope; source results do not establish production behavior.")
            if not case["scope"]["model"]["actors"]: limitations.append("Actor and role coverage is unknown.")
            data = {"schema_version": 1, "result": "assessment_record", "assessment": "assessment-" + digest(key)[:16],
                    "generated_at": self.clock(), "security_verdict": "not_established", "catalog_version": self.catalog["catalog_version"],
                    "engine_sha256": self.engine, "component_freshness_verified": False,
                    "scope": {"mode": "combined" if source and case["scope"]["deployments"] else "source_only" if source else "url_only",
                              "selected_files": len(source["manifest"]) if source else 0,
                              "source_snapshot": digest(source["manifest"]) if source else None,
                              "source_revision": source["declared_revision"] if source else None,
                              "revision_provenance": "operator_declared; not deployed identity",
                              "deployments": [{k: d[k] for k in ("id", "environment", "artifact")} for d in case["scope"]["deployments"]]},
                    "model": case["scope"]["model"], "model_provenance": "operator_declared",
                    "discovery": case["discovery"], "module_routes": self._routes(case), "coverage": counts, "controls": controls,
                    "evidence": evidence, "findings": findings, "root_causes": list(groups.values()),
                    "attack_chains": case["chains"], "limitations": limitations}
            literals = list(case["scope"]["redact_values"])
            if source: literals.append(source["root"])
            return redact(data, literals)

    def write_report(self, key):
        data = self.report(key)
        lines = ["# Security assessment record", "", "Security verdict: **not established**.", "",
                 "This report separates observations, coverage gaps and actions. It is not a release approval.", "",
                 "Generated at (Unix UTC seconds): " + markdown(data["generated_at"]), "",
                 "## Inspected scope", "", "Mode: " + markdown(data["scope"]["mode"]) + ". Selected files: " + markdown(data["scope"]["selected_files"]) + ".", "",
                 "Selected source snapshot: " + markdown(data["scope"]["source_snapshot"] or "unavailable"), "",
                 "Declared source revision: " + markdown(data["scope"]["source_revision"] or "unknown") + ". This is not deployed identity.", ""]
        for deployment in data["scope"]["deployments"]:
            lines.extend(["- Deployment " + markdown(deployment["id"]) + "; environment " + markdown(deployment["environment"]) + "; declared artifact " + markdown(deployment["artifact"] or "unknown") + ". Not independently verified.", ""])
        lines.extend(["## What to do next", ""])
        actionable = [f for f in data["findings"] if f["disposition"] != "rejected"]
        for finding in actionable:
            lines.extend(["### " + markdown(finding["title"]), "",
                          "Finding: " + markdown(finding["id"]) + "; control: " + markdown(finding["control"]) + "; location: " + markdown(finding["location"]) + ".", "",
                          "Priority: " + markdown(finding["severity"]) + "; confidence: " + markdown(finding["confidence"]) + "; status: " + markdown(finding["disposition"]) + ".", "",
                          "Why this priority: " + markdown(finding["severity_reason"]), "",
                          "Confidence basis: " + markdown(finding["confidence_reason"]), "",
                          "Prerequisites: " + markdown(finding["prerequisites"]), "",
                          "Trust boundary: " + markdown(finding["trust_boundary"]), "",
                          "Customer impact: " + markdown(finding["impact"]), "",
                          "Fix: " + markdown(finding["fix"]), "",
                          "Preserve: " + markdown(finding["preserve"]), "",
                          "Retest: " + markdown(finding["retest"]), "",
                          "Evidence: " + markdown(", ".join(finding["evidence"]) or "none"), "",
                          "Counterevidence: " + markdown(", ".join(finding["counterevidence"]) or "none recorded"), "",
                          "Uncertainty: " + markdown(finding["uncertainty"]), ""])
        if not actionable: lines.extend(["No actionable finding is recorded. This does not establish safety.", ""])
        rejected = [f for f in data["findings"] if f["disposition"] == "rejected"]
        if rejected:
            lines.extend(["## Rejected findings retained", ""])
            for finding in rejected:
                lines.extend(["- " + markdown(finding["title"]) + ": refuting evidence " + markdown(", ".join(finding["counterevidence"])) + ". " + markdown(finding["uncertainty"]), ""])
        lines.extend(["## Evidence and its limits", ""])
        for evidence in data["evidence"]:
            lines.extend(["### " + markdown(evidence["id"]), "",
                          "Origin: " + markdown(evidence["origin"]) + "; method: " + markdown(evidence["method"]) + "; current bindings valid: " + markdown(evidence["valid"]) + ".", "",
                          "Observed at / expires at (Unix UTC seconds): " + markdown(evidence["observed_at"]) + " / " + markdown(evidence["expires_at"]), "",
                          "Selected files: " + markdown(", ".join(evidence["files"]) or "none") + "; actor: " + markdown(evidence["actor"] or "unknown") + ".", "",
                          markdown(evidence["summary"]), "", markdown(evidence["validity_reason"]), ""])
        if not data["evidence"]: lines.extend(["No assessment evidence has been recorded.", ""])
        if data["attack_chains"]:
            lines.extend(["## Hypothesized relationships", "", "Links do not establish a working exploit or increase severity automatically.", ""])
            for link in data["attack_chains"]:
                lines.extend(["- " + markdown(link["from"]) + " to " + markdown(link["to"]) + ": " + markdown(link["reason"]), ""])
        lines.extend(["## Coverage and next checks", "", "| Control | Surface | Environment | Actor | Progress | Outcome | Reason and next step |", "|---|---|---|---|---|---|---|"])
        for control in data["controls"]:
            lines.append("| " + " | ".join(markdown(value) for value in [control["title"], control["surface"], control["environment"], control["actor"] or "unknown", control["state"], control["outcome"], control["reason"] + " " + control["next_step"]]) + " |")
        lines.extend(["", "## Scope and limitations", ""] + ["- " + markdown(item) for item in data["limitations"]])
        name = "report-" + secrets.token_hex(16)
        payloads = {".json": canonical(data), ".md": ("\n".join(lines) + "\n").encode("utf-8")}
        require(all(len(content) <= 4 * 1024 * 1024 for content in payloads.values()), "rendered report exceeds its size limit")
        for suffix, content in payloads.items():
            with (self.store.root / (name + suffix)).open("xb") as stream: stream.write(content)
            import os
            if os.name != "nt": (self.store.root / (name + suffix)).chmod(0o600)
        return {"status": "report_created", "report": name, "security_verdict": "not_established"}
