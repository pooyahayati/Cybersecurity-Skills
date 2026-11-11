"""M3 source review and scoped remediation, bound to existing M1/M2 evidence."""

import copy
from pathlib import Path
import re
import secrets

from security_runtime.common import canonical, digest, fields, identifier, integer, parse, read_file, relpath, require, sha256, text
from security_runtime.controller import Controller, HEAD_RESOURCES, selected_tree, write_bundle
from .contracts import choice, items, version
from .redaction import markdown, redact
from .service import Assessment
from .source_rules import RULES
from . import specialists


DOMAINS = {"architecture", "application", "identity", "data", "business", "dependencies", "secrets"}
WORKER = "scripts/m3_worker.py"


def exact_version(ecosystem, value):
    """Recognize bounded concrete release identities, never tags or constraints.

    This is not a resolver, ordering algorithm or advisory range matcher.
    Unsupported spellings remain blocked instead of being guessed.
    """
    number = r"(?:0|[1-9][0-9]*)"
    pre = r"(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)"
    patterns = {
        "npm": rf"{number}\.{number}\.{number}(?:-{pre}(?:\.{pre})*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?",
        "pypi": r"(?:[0-9]+!)?[0-9]+(?:\.[0-9]+)*(?:(?:a|b|rc)[0-9]+)?(?:\.post[0-9]+)?(?:\.dev[0-9]+)?(?:\+[a-z0-9]+(?:[._-][a-z0-9]+)*)?",
        "composer": r"v?[0-9]+(?:\.[0-9]+){1,3}(?:-(?:alpha|beta|rc|patch|pl|p)[0-9]*)?",
    }
    require(isinstance(value, str) and len(value) <= 256 and re.fullmatch(patterns[ecosystem], value, re.I), "dependency requires a supported concrete release identity")


def behavior_contract(value):
    fields(value, {"entrypoint", "cases", "oracle_basis", "limitations"})
    require(relpath(value["entrypoint"]).endswith(".py"), "probe entrypoint must be Python")
    for field in ("oracle_basis", "limitations"): text(value[field], 4096)
    names, kinds, requests = set(), set(), set()
    for row in items(value["cases"], 24, 3):
        fields(row, {"id", "kind", "actor", "request", "state", "expected", "forbidden_response"})
        identifier(row["id"])
        require(row["id"] not in names, "duplicate behavior case")
        names.add(row["id"])
        choice(row["kind"], {"legitimate", "denied", "variant"})
        choice(row["actor"], {"anonymous", "owner", "non-owner", "cross-tenant", "low-privilege", "service"})
        kinds.add(row["kind"])
        fields(row["expected"], {"response", "state"})
        require(isinstance(row["state"], dict) and isinstance(row["expected"]["state"], dict), "protected state must be an object")
        request = canonical({"request": row["request"], "state": row["state"]})
        require(len(request) <= 3072 and len(canonical(row["expected"])) <= 16384, "behavior payload exceeds limit")
        if row["kind"] != "legitimate":
            require(canonical(row["state"]) == canonical(row["expected"]["state"]), "denied and variant cases must preserve protected state")
            require(row["forbidden_response"] is not None and canonical(row["forbidden_response"]) != canonical(row["expected"]["response"]), "denied cases need a distinct concrete prohibited response")
            require(digest(row["request"]) not in requests, "denied variants need distinct requests")
            requests.add(digest(row["request"]))
    require(kinds == {"legitimate", "denied", "variant"}, "all behavior families are required")


class SourceReview(Assessment):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.engine = digest([self.engine, selected_tree(self.package, ["scripts"])])

    def refresh(self, key, value):
        require(False, "M3 source and context are immutable; create a new case after changes")

    def _current(self, case):
        require(case["source"] is not None, "source access is required")
        source = case["source"]
        require({p: sha256(read_file(source["root"], p, 1024 * 1024)) for p in source["manifest"]} == source["manifest"], "source changed; create a new source review")

    def _ledger(self, tx, key):
        return tx.get("source-review", key, {"scans": {}, "traces": {}, "proposals": {}})

    def _producer(self, case, tx, operation_id, arguments, expected=None):
        operation = tx.get("operation", operation_id)
        require(operation is not None, "operation is unavailable")
        spec = {"operation": operation_id, "files": sorted(case["source"]["manifest"]), "observed_at": operation.get("finished_at")}
        producer = self._operation(case, {"surface": "source"}, spec, tx, expected)
        auth = tx.get("authorization", operation["authorization"])
        require(auth["manifest"] == case["source"]["manifest"], "operation must bind the complete selected source")
        run = tx.get("run", operation["run"])
        selected = operation["specification"]
        require(selected["interpreter"] == "python" and selected["entrypoint"] == WORKER and selected["arguments"] == arguments, "operation is not the requested M3 adapter")
        candidate = tx.get("candidate", run["bindings"][selected["component"]])
        require(candidate["kind"] == "tool" and candidate["manifest"] == selected_tree(self.package, ["scripts"]), "adapter resources do not match the current implementation")
        require(producer["exit_code"] == 0, "adapter failed; no behavioral observation is available")
        output = read_file(self.store.root, operation_id + ".output", min(4 * 1024 * 1024, selected["max_output_bytes"]))
        return producer, parse(output)

    def import_scan(self, key, value):
        fields(value, {"id", "operation"})
        identifier(value["id"])
        with self.store.transaction() as tx:
            case = self._case(tx, key)
            self._current(case)
            ledger = self._ledger(tx, key)
            require(value["id"] not in ledger["scans"] and len(ledger["scans"]) < 32, "scan ID reused or limit reached")
            producer, output = self._producer(case, tx, value["operation"], ["inspect"])
            fields(output, {"schema_version", "adapter", "files", "leads", "security_verdict", "limitations"})
            version(output["schema_version"])
            require(output["adapter"] == "builtin-source" and output["security_verdict"] == "not_established", "unsupported analyzer result")
            files = {}
            for row in items(output["files"], 256, 1):
                fields(row, {"path", "sha256", "language", "status"})
                require(row["path"] not in files, "duplicate file result")
                choice(row["status"], {"examined", "limited_lexical", "inconclusive", "unsupported"})
                require(row["language"] in {None, "python", "javascript", "typescript", "php"}, "unknown source language")
                files[row["path"]] = row["sha256"]
            require(files == case["source"]["manifest"], "analyzer omitted or changed selected source")
            names = set()
            for row in items(output["leads"], 2048):
                fields(row, {"id", "rule", "domain", "path", "line", "title", "fix", "disposition"})
                require(row["rule"] in RULES and row["path"] in files and row["disposition"] == "needs_validation", "invalid source lead")
                domain, title, fix = RULES[row["rule"]]
                integer(row["line"], 1, 1024 * 1024)
                require((row["domain"], row["title"], row["fix"]) == (domain, title, fix), "unrecognized analyzer guidance")
                require(row["id"] == "lead-" + digest([row["path"], row["line"], row["rule"]])[:24] and row["id"] not in names, "invalid lead identity")
                names.add(row["id"])
            for limit in items(output["limitations"], 8): text(limit, 2048)
            ledger["scans"][value["id"]] = {"producer": producer, "output": output}
            tx.put("source-review", key, ledger)
        return {"status": "recorded", "lead_count": len(output["leads"]), "security_verdict": "not_established"}

    def guidance(self, key, value):
        specialists.request(value)
        controller = Controller(self.store, self.package, clock=self.clock)
        run, _auth = controller.guard(value["run"])
        candidate_id = run["bindings"].get(specialists.COMPONENT)
        require(candidate_id is not None, "Cloudflare was not selected at preflight")
        # A new guidance request checks upstream anew; a retained packet is frozen
        # for its bounded run. Never hold a state transaction during network I/O.
        freshness = controller.check_current(candidate_id)
        with self.store.transaction() as tx:
            case = self._case(tx, key)
            self._current(case)
            ledger = self._ledger(tx, key)
            packets = ledger.setdefault("guidance", {})
            require(value["id"] not in packets and len(packets) < 32, "guidance ID reused or limit reached")
            result = specialists.packet(controller, tx, case, key, value, freshness)
            packets[value["id"]] = result
            tx.put("source-review", key, ledger)
        return specialists.expose(controller, result)

    def trace(self, key, value):
        fields(value, {"id", "run", "adapter", "domain", "actor", "assets", "locations", "entrypoint", "untrusted_input", "guard", "sink", "abuse_case", "counterevidence", "conclusion", "next_step", "dependency"}, {"guidance"})
        identifier(value["id"])
        choice(value["domain"], DOMAINS)
        choice(value["adapter"], {"builtin-review", "addy-hardening", specialists.COMPONENT})
        require(("guidance" in value) == (value["adapter"] == specialists.COMPONENT), "guidance is required only for Cloudflare traces")
        if "guidance" in value: identifier(value["guidance"])
        choice(value["conclusion"], {"supported_issue", "no_issue_observed", "inconclusive"})
        for field in ("entrypoint", "untrusted_input", "guard", "sink", "abuse_case", "counterevidence", "next_step"): text(value[field], 4096)
        controller = Controller(self.store, self.package)
        run, auth = controller.guard(value["run"])
        head = controller.candidate(run["bindings"]["head"])
        require(head["manifest"] == selected_tree(self.package, HEAD_RESOURCES), "head changed during review")
        if value["adapter"] == "addy-hardening":
            candidate_id = run["bindings"].get("addy-hardening")
            require(candidate_id is not None, "selected specialist was not preflighted")
            candidate = controller.candidate(candidate_id)
            source = controller.source("addy-hardening")
            require(candidate["kind"] == "skill" and source["repository"] == "addyosmani/agent-skills" and "skills/security-and-hardening/SKILL.md" in candidate["manifest"] and "LICENSE" in candidate["manifest"], "specialist identity or required resources differ")
        if value["domain"] == "dependencies":
            dependency = value["dependency"]
            fields(dependency, {"package", "ecosystem", "version", "lock_path", "advisory_component", "advisory_reference"})
            for field in ("package", "version", "advisory_reference"): text(dependency[field], 1024)
            choice(dependency["ecosystem"], {"npm", "pypi", "composer"})
            exact_version(dependency["ecosystem"], dependency["version"])
            feed = run["bindings"].get(dependency["advisory_component"])
            require(feed is not None and controller.candidate(feed)["kind"] == "data", "dependency review requires a current reviewed advisory component")
        else:
            require(value["dependency"] is None, "dependency evidence belongs to dependency review")
        with self.store.transaction() as tx:
            case = self._case(tx, key)
            self._current(case)
            require(auth["spec"]["root"] == case["source"]["root"] and auth["manifest"] == case["source"]["manifest"], "review authority does not cover the selected source")
            require(value["actor"] in {a["id"] for a in case["scope"]["model"]["actors"]}, "review actor is outside scope")
            require(set(items(value["assets"], 64, 1)) <= {a["id"] for a in case["scope"]["model"]["assets"]}, "review assets are outside scope")
            for row in items(value["locations"], 64, 1):
                fields(row, {"path", "line"})
                require(row["path"] in case["source"]["manifest"], "trace location is outside selected source")
                integer(row["line"], 1, len(read_file(case["source"]["root"], row["path"], 1024 * 1024).splitlines()))
            if value["dependency"] is not None:
                require(value["dependency"]["lock_path"] in {row["path"] for row in value["locations"]}, "dependency review must cite its selected lockfile")
                dependency = value["dependency"]
                supported = {"npm": {"package-lock.json"}, "composer": {"composer.lock"}, "pypi": {"uv.lock", "poetry.lock"}}
                require(Path(dependency["lock_path"]).name in supported[dependency["ecosystem"]], "unsupported lockfile format")
                require(any(f["kind"] == "package" and f["name"] == dependency["package"] and f["version"] == dependency["version"] and f["version_basis"] == "lockfile" and dependency["lock_path"] in f["paths"] for f in case["discovery"]["facts"]), "dependency is not an observed exact lockfile entry")
            ledger = self._ledger(tx, key)
            guidance_digest = None
            if value["adapter"] == specialists.COMPONENT:
                packet = ledger.get("guidance", {}).get(value["guidance"])
                require(packet is not None, "guidance packet is unavailable")
                specialists.validate(Controller(self.store, self.package, clock=self.clock), tx, case, key, packet, value["run"], value["domain"])
                guidance_digest = digest(packet)
            require(value["id"] not in ledger["traces"] and len(ledger["traces"]) < 128, "trace ID reused or limit reached")
            ledger["traces"][value["id"]] = {"spec": copy.deepcopy(value), "scope_sha256": case["scope_sha256"], "source_sha256": digest(case["source"]["manifest"]), "components": copy.deepcopy(run["bindings"]), "component_digests": {component: digest(tx.get("candidate", candidate)) for component, candidate in run["bindings"].items()}, "authorization": run["authorization"], "authority_sha256": digest(auth["spec"]), "observed_at": self.clock(), "expires_at": self.clock() + 31 * 86400, "origin": "operator_source_review"}
            if guidance_digest is not None:
                ledger["traces"][value["id"]]["guidance_sha256"] = guidance_digest
            tx.put("source-review", key, ledger)
        return {"status": "recorded", "origin": "operator_source_review", "security_verdict": "not_established"}

    def propose(self, key, value):
        fields(value, {"id", "finding", "rationale", "replacements", "behavior"})
        identifier(value["id"])
        text(value["rationale"], 4096)
        behavior_contract(value["behavior"])
        with self.store.transaction() as tx:
            case = self._case(tx, key)
            self._current(case)
            ledger = self._ledger(tx, key)
            require(value["id"] not in ledger["proposals"] and len(ledger["proposals"]) < 16, "proposal ID reused or limit reached")
            finding = case["findings"].get(value["finding"])
            require(finding is not None and finding["spec"]["disposition"] == "confirmed", "proposal requires a confirmed finding")
            require(self._finding_basis(case, finding["spec"], tx)["surface"] == "source", "proposal requires source evidence")
            contents = {p: read_file(self.store.root / "objects" / case["source"]["object"], p, 1024 * 1024) for p in case["source"]["manifest"]}
            require(value["behavior"]["entrypoint"] in contents, "probe entrypoint is not selected source")
            changed = set()
            for row in items(value["replacements"], 32, 1):
                fields(row, {"path", "before_sha256", "content"})
                path = relpath(row["path"])
                require(path in contents and path not in changed and sha256(contents[path]) == row["before_sha256"], "replacement does not bind an original selected file")
                require(isinstance(row["content"], str) and len(row["content"].encode("utf-8")) <= 1024 * 1024, "replacement exceeds limit")
                replacement = row["content"].encode("utf-8")
                require(replacement != contents[path], "replacement does not change source")
                contents[path] = replacement
                changed.add(path)
            require(sum(map(len, contents.values())) <= 16 * 1024 * 1024, "candidate exceeds limit")
            staged, manifest = write_bundle(self.store.root / "quarantine", contents)
            object_id = "patch-" + secrets.token_hex(16)
            staged.rename(self.store.root / "objects" / object_id)
            ledger["proposals"][value["id"]] = {"finding": value["finding"], "rationale": value["rationale"], "behavior": copy.deepcopy(value["behavior"]), "manifest": manifest, "original_manifest": copy.deepcopy(case["source"]["manifest"]), "scope_sha256": case["scope_sha256"], "object": object_id, "changed": sorted(changed), "tests": {}, "acceptance": None}
            tx.put("source-review", key, ledger)
        return {"status": "proposed", "changed_files": len(changed), "original_modified": False}

    def export(self, key, proposal_id, destination):
        destination = Path(destination).absolute()
        require(not destination.exists() and destination.parent == destination.parent.resolve(strict=True), "export requires a new directory under a canonical existing parent")
        with self.store.transaction() as tx:
            case = self._case(tx, key)
            self._current(case)
            proposal = self._ledger(tx, key)["proposals"][proposal_id]
            for other in (self.package, self.store.root, Path(case["source"]["root"])):
                require(not destination.is_relative_to(other) and not other.is_relative_to(destination), "candidate must be outside source, package and state")
            contents = {p: read_file(self.store.root / "objects" / proposal["object"], p, 1024 * 1024) for p in proposal["manifest"]}
            require({p: sha256(v) for p, v in contents.items()} == proposal["manifest"], "candidate integrity failed")
            staged, _ = write_bundle(destination.parent, contents)
            staged.rename(destination)
        return {"status": "exported", "original_modified": False}

    def _test(self, case, proposal, tx, record):
        require(proposal["scope_sha256"] == case["scope_sha256"] and proposal["original_manifest"] == case["source"]["manifest"], "proposal source or context changed")
        selected = next(row for row in proposal["behavior"]["cases"] if row["id"] == record["case"])
        target = copy.deepcopy(case)
        if record["variant"] == "candidate":
            target["source"]["root"] = record["root"]
            target["source"]["manifest"] = proposal["manifest"]
        arguments = ["probe", proposal["behavior"]["entrypoint"], canonical({"request": selected["request"], "state": selected["state"]}).decode("utf-8")]
        producer, result = self._producer(target, tx, record["operation"], arguments, record.get("producer"))
        fields(result, {"response", "state"})
        violation = selected["kind"] != "legitimate" and (
            canonical(result["state"]) != canonical(selected["state"])
            or canonical(result["response"]) == canonical(selected["forbidden_response"]))
        return {"producer": producer, "matches": canonical(result) == canonical(selected["expected"]), "violation_observed": violation}

    def test(self, key, value):
        fields(value, {"proposal", "case", "variant", "operation", "root"})
        choice(value["variant"], {"original", "candidate"})
        with self.store.transaction() as tx:
            case = self._case(tx, key)
            self._current(case)
            ledger = self._ledger(tx, key)
            proposal = ledger["proposals"][value["proposal"]]
            require(value["root"] is None if value["variant"] == "original" else isinstance(value["root"], str), "invalid candidate root")
            if value["variant"] == "candidate":
                root = Path(value["root"]).absolute()
                require(root == root.resolve(strict=True), "candidate root is not canonical")
                for other in (self.package, self.store.root, Path(case["source"]["root"])):
                    require(not root.is_relative_to(other) and not other.is_relative_to(root), "candidate root overlaps protected source or state")
            name = value["variant"] + ":" + value["case"]
            require(name not in proposal["tests"] and proposal["acceptance"] is None, "test records are immutable; create a new proposal for a new attempt")
            record = copy.deepcopy(value)
            record.update(self._test(case, proposal, tx, record))
            proposal["tests"][name] = record
            tx.put("source-review", key, ledger)
        return {"status": "recorded", "matches": record["matches"], "scope": "declared_serialized_model"}

    def _qualifies(self, case, proposal, tx):
        self._current(case)
        finding = case["findings"].get(proposal["finding"])
        require(finding is not None and finding["spec"]["disposition"] == "confirmed", "finding is no longer confirmed")
        self._finding_basis(case, finding["spec"], tx)
        baseline_failures = 0
        for scenario in proposal["behavior"]["cases"]:
            for variant in ("original", "candidate"):
                record = proposal["tests"].get(variant + ":" + scenario["id"])
                require(record is not None, "behavior cases are incomplete")
                current = self._test(case, proposal, tx, record)
                if variant == "candidate" or scenario["kind"] == "legitimate":
                    require(current["matches"], "required legitimate or candidate behavior failed")
                elif current["violation_observed"]:
                    baseline_failures += 1
        require(baseline_failures > 0, "original behavior did not reproduce the reported failure")

    def accept(self, key, value):
        fields(value, {"proposal", "reviewer", "reason", "oracle_review", "residual_risk"})
        for field in ("reviewer", "reason", "oracle_review", "residual_risk"): text(value[field], 4096)
        with self.store.transaction() as tx:
            case = self._case(tx, key)
            ledger = self._ledger(tx, key)
            proposal = ledger["proposals"][value["proposal"]]
            require(proposal["acceptance"] is None, "acceptance is immutable")
            self._qualifies(case, proposal, tx)
            proposal["acceptance"] = {**copy.deepcopy(value), "accepted_at": self.clock()}
            tx.put("source-review", key, ledger)
        return {"status": "accepted_for_declared_model", "security_verdict": "not_established", "production_verified": False}

    def source_report(self, key):
        with self.store.transaction() as tx:
            case = self._case(tx, key)
            ledger = self._ledger(tx, key)
            current = True
            try: self._current(case)
            except (OSError, ValueError): current = False
            scans, traces, proposals = [], [], []
            for name, scan in ledger["scans"].items():
                valid = current
                try: self._producer(case, tx, scan["producer"]["operation"], ["inspect"], scan["producer"])
                except (OSError, ValueError, KeyError, TypeError): valid = False
                operation = tx.get("operation", scan["producer"]["operation"])
                scans.append({"id": name, "valid": valid, "operation": scan["producer"]["operation"], "producer_sha256": scan["producer"]["record_sha256"], "observed_at": operation["finished_at"], "files": scan["output"]["files"], "leads": scan["output"]["leads"], "limitations": scan["output"]["limitations"]})
            for name, trace in ledger["traces"].items():
                valid = current and trace["scope_sha256"] == case["scope_sha256"] and trace["source_sha256"] == digest(case["source"]["manifest"])
                valid = valid and not any(tx.get("revocation", component, False) for component in trace["components"])
                authority = tx.get("authorization", trace["authorization"])
                valid = valid and authority is not None and not authority["revoked"] and digest(authority["spec"]) == trace["authority_sha256"] and self.clock() < trace["expires_at"]
                for component, candidate_id in trace["components"].items():
                    candidate = tx.get("candidate", candidate_id)
                    valid = valid and candidate is not None and candidate["component"] == component and digest(candidate) == trace["component_digests"][component]
                    if candidate is not None and candidate["kind"] == "data":
                        source = tx.get("source", component)
                        valid = valid and source is not None and self.clock() < candidate["resolved"]["identity"]["published_at"] + source["spec"]["data_max_age_seconds"]
                guidance = None
                if trace["spec"]["adapter"] == specialists.COMPONENT:
                    packet = ledger.get("guidance", {}).get(trace["spec"]["guidance"])
                    try:
                        require(packet is not None and digest(packet) == trace["guidance_sha256"], "guidance packet changed")
                        specialists.validate(Controller(self.store, self.package, clock=self.clock), tx, case, key, packet, trace["spec"]["run"], trace["spec"]["domain"])
                    except (OSError, ValueError, KeyError, TypeError): valid = False
                    if packet is not None:
                        guidance = {"packet_sha256": trace["guidance_sha256"], "mode": packet["mode"], "upstream": packet["upstream"], "resources": packet["resources"], "currentness_checked_at": packet["currentness_checked_at"], "freshness_basis": "checked_at_packet_creation; no upstream check while rendering", "validity_basis": "unchanged resources and reviews within the original active authorized run"}
                row = {"id": name, "valid": valid, "origin": trace["origin"], "run": trace["spec"]["run"], "authorization": trace["authorization"], "observed_at": trace["observed_at"], "source_manifest_sha256": trace["source_sha256"], "components": [{"component": component, "candidate": candidate} for component, candidate in trace["components"].items()], **{k: v for k, v in trace["spec"].items() if k not in ("run", "id")}}
                if guidance is not None: row["guidance_provenance"] = guidance
                traces.append(row)
            for name, proposal in ledger["proposals"].items():
                qualifies = False
                try:
                    self._qualifies(case, proposal, tx)
                    qualifies = True
                except (OSError, ValueError, KeyError, TypeError, StopIteration): pass
                proposals.append({"id": name, "finding": proposal["finding"], "changed": proposal["changed"], "rationale": proposal["rationale"], "eligible": qualifies,
                                  "accepted": qualifies and proposal["acceptance"] is not None,
                                  "scope": "declared_serialized_model", "production_verified": False,
                                  "original_manifest_sha256": digest(proposal["original_manifest"]), "candidate_manifest_sha256": digest(proposal["manifest"]), "behavior_sha256": digest(proposal["behavior"]),
                                  "acceptance": proposal["acceptance"],
                                  "tests": [{"case": r["case"], "variant": r["variant"], "recorded_match": r["matches"], "violation_observed": r["violation_observed"], "operation": r["operation"], "producer_sha256": r["producer"]["record_sha256"], "observed_at": tx.get("operation", r["operation"])["finished_at"]} for r in proposal["tests"].values()],
                                  "oracle_basis": proposal["behavior"]["oracle_basis"], "limitations": proposal["behavior"]["limitations"]})
            result = {"schema_version": 1, "assessment": key, "generated_at": self.clock(), "source_manifest_sha256": digest(case["source"]["manifest"]) if case["source"] else None, "declared_source_revision": case["source"]["declared_revision"] if case["source"] else None, "security_verdict": "not_established", "source_current": current, "scans": scans, "traces": traces, "proposals": proposals,
                      "unreviewed_domains": sorted(DOMAINS - {t["domain"] for t in traces if t["valid"]}),
                      "limitations": ["Static leads require validation; operator source reviews are attributed judgments.", "Behavior probes execute target Python only in M1 isolation. Their serialized response/state model can be falsified by malicious target code; oracle review is mandatory.", "No installed platform, live service, production data, full-project or overall security assurance is established."]}
            return redact(result, case["scope"]["redact_values"])

    def write_source_report(self, key):
        report = self.source_report(key)
        lines = ["# Source review and remediation", "", "Security verdict: not established.", ""]
        for field in ("assessment", "generated_at", "source_manifest_sha256", "declared_source_revision", "source_current"):
            lines += [field + ": " + markdown(report[field]), ""]
        for scan in report["scans"]:
            lines += ["## Static inspection", "", "Evidence valid: " + str(scan["valid"]), "", "Operation: " + markdown(scan["operation"]) + "; observed at: " + str(scan["observed_at"]), ""]
            for lead in scan["leads"]:
                lines += ["- " + markdown(lead["title"]) + " at " + markdown(lead["path"]) + ":" + str(lead["line"]) + ". " + markdown(lead["fix"])]
        for trace in report["traces"]:
            lines += ["", "## " + markdown(trace["domain"]) + " review", "", "Evidence valid: " + str(trace["valid"])]
            lines += ["- Location: " + markdown(row["path"]) + ":" + str(row["line"]) for row in trace["locations"]]
            for field in ("id", "origin", "run", "authorization", "observed_at", "source_manifest_sha256"):
                lines += ["- " + field + ": " + markdown(trace[field])]
            for field in ("actor", "entrypoint", "untrusted_input", "guard", "sink", "abuse_case", "counterevidence", "conclusion", "next_step"):
                lines.append("- " + field + ": " + markdown(trace[field]))
            lines += ["- Adapter: " + markdown(trace["adapter"])]
            if "guidance_provenance" in trace:
                guidance = trace["guidance_provenance"]
                for field in ("packet_sha256", "mode", "currentness_checked_at", "freshness_basis", "validity_basis"):
                    lines += ["- " + field + ": " + markdown(guidance[field])]
                lines += ["- Upstream: " + markdown(guidance["upstream"])]
                lines += ["- Resource: " + markdown(p) + "; SHA-256: " + markdown(h) for p, h in guidance["resources"].items()]
        for proposal in report["proposals"]:
            lines += ["", "## Patch proposal " + markdown(proposal["id"]), "", "Finding: " + markdown(proposal["finding"]), "", "Accepted for declared serialized model: " + str(proposal["accepted"]), "", markdown(proposal["rationale"]), "", "Changed files: " + markdown(", ".join(proposal["changed"])), "", "Oracle: " + markdown(proposal["oracle_basis"]), "", "Limit: " + markdown(proposal["limitations"])]
            for field in ("original_manifest_sha256", "candidate_manifest_sha256", "behavior_sha256"):
                lines += ["", field + ": " + markdown(proposal[field])]
            if proposal["acceptance"] is not None:
                for field in ("reviewer", "reason", "oracle_review", "residual_risk", "accepted_at"):
                    lines += ["", field + ": " + markdown(proposal["acceptance"][field])]
            for test in proposal["tests"]:
                lines.append("- " + markdown(test["variant"]) + " / " + markdown(test["case"]) + ": recorded match " + str(test["recorded_match"]) + "; prohibited effect observed " + str(test["violation_observed"]) + "; operation " + markdown(test["operation"]) + "; observed at " + str(test["observed_at"]) + "; producer " + markdown(test["producer_sha256"]))
        lines += ["", "Unreviewed domains: " + markdown(", ".join(report["unreviewed_domains"])), ""] + ["- " + markdown(x) for x in report["limitations"]]
        name = "m3-report-" + secrets.token_hex(12)
        (self.store.root / (name + ".json")).write_bytes(canonical(report) + b"\n")
        (self.store.root / (name + ".md")).write_text("\n".join(lines) + "\n", encoding="utf-8")
        return {"status": "written", "json": name + ".json", "markdown": name + ".md", "security_verdict": "not_established"}
