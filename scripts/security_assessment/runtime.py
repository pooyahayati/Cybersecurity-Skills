"""M4 observations: deployed reads, offline infrastructure leads and delivery identity."""

import copy
from pathlib import Path
import re
import secrets

from security_runtime.common import canonical, digest, fields, identifier, number, parse, read_file, require, sha256, text
from security_runtime.controller import HEAD_RESOURCES, selected_tree
from security_runtime.web import WebController
from . import contracts
from .infrastructure import container_summary
from .redaction import markdown, redact
from .remediation import SourceReview


class RuntimeReview(SourceReview):
    def __init__(self, *args, upstream=None, docker=None, **kwargs):
        super().__init__(*args, **kwargs)
        # Older entrypoints must not interpret a case whose evidence includes
        # producers they cannot revalidate. M3 methods remain available here.
        self.engine = digest([self.engine, "m4-runtime-review-v1"])
        self.web = WebController(self.store, self.package, upstream, self.clock)
        self.docker = docker

    def _runtime(self, tx, key):
        return tx.get("runtime-review", key, {"scans": {}, "comparisons": {}, "containers": {}, "releases": {}})

    def web_authorize(self, key, value):
        with self.store.transaction() as tx: case = self._case(tx, key)
        return self.web.authorize(case, value)

    def web_execute(self, key, authorization, route, credentials=None, ca=None):
        with self.store.transaction() as tx: case = self._case(tx, key)
        return self.web.execute(case, authorization, route, credentials, ca)

    def _scan_producer(self, case, tx, operation_id, adapter, expected=None):
        self._current(case)
        operation = tx.get("operation", operation_id)
        require(operation is not None, "scanner operation unavailable")
        producer = self._operation(case, {"surface": "source"}, {"operation": operation_id,
            "files": sorted(case["source"]["manifest"]), "observed_at": operation.get("finished_at")}, tx, expected)
        auth = tx.get("authorization", operation["authorization"])
        require(auth["manifest"] == case["source"]["manifest"] and self.clock() < auth["spec"]["limits"]["expires_at"], "scanner scope or expiry differs")
        selected = operation["specification"]
        require(selected["interpreter"] == "python" and selected["entrypoint"] == "scripts/m4_worker.py"
                and selected["arguments"] == [adapter], "not the selected M4 adapter")
        run = tx.get("run", operation["run"])
        worker = tx.get("candidate", run["bindings"][selected["component"]])
        require(worker["kind"] == "tool" and worker["manifest"] == selected_tree(self.package, ["scripts"]), "worker implementation differs")
        for component, candidate_id in run["bindings"].items():
            candidate = self.web.controller.candidate(candidate_id, tx)
            require(candidate is not None and candidate["component"] == component, "scanner producer absent")
            self.web.controller.reviewed(candidate_id, candidate, tx)
            if candidate["kind"] == "data":
                source = self.web.controller.source(component, tx)
                require(self.clock() < candidate["resolved"]["identity"]["published_at"] + source["data_max_age_seconds"], "scanner data expired")
        require(producer["exit_code"] == 0, "scanner failed")
        output = parse(read_file(self.store.root, operation_id + ".output", selected["max_output_bytes"]))
        fields(output, {"schema_version", "adapter", "tool_version", "files", "leads", "security_verdict"})
        require(output["schema_version"] == 1 and output["security_verdict"] == "not_established"
                and output["adapter"] == {"infra": "builtin-infrastructure", "trivy": "trivy-bundled"}[adapter], "unsupported scanner envelope")
        if adapter == "trivy":
            candidate_id = run["bindings"].get("trivy")
            scanner = tx.get("candidate", candidate_id) if candidate_id else None
            source = self.web.controller.source("trivy", tx)
            require(scanner is not None and scanner["kind"] == "tool" and source["repository"] == "aquasecurity/trivy"
                    and set(scanner["manifest"]) == {"trivy"} and source["asset"] is not None
                    and source["asset"]["name"] == "trivy_{version}_Linux-64bit.tar.gz", "unsupported scanner distribution")
            require(output["tool_version"] == scanner["resolved"]["identity"]["label"].removeprefix("v"), "actual scanner version differs")
        else: require(output["tool_version"] is None, "unexpected external scanner")
        observed = {}
        for row in contracts.items(output["files"], 256, 1):
            fields(row, {"path", "sha256", "status"})
            require(row["path"] not in observed and row["status"] in {"unsupported", "inconclusive", "limited_structured", "limited_lexical", "reported", "no_reported_result"}, "invalid coverage")
            observed[row["path"]] = row["sha256"]
        require(observed == case["source"]["manifest"], "scanner omitted selected inputs")
        for row in contracts.items(output["leads"], 2048):
            fields(row, {"id", "rule", "path", "line", "title", "fix", "disposition"})
            require(row["path"] in observed and row["disposition"] == "needs_validation" and type(row["line"]) is int and 1 <= row["line"] <= 1048576, "invalid scanner lead")
            for name in ("id", "rule", "title", "fix"): text(row[name], 2048)
        return producer, output

    def import_infrastructure(self, key, value):
        fields(value, {"id", "operation", "adapter"})
        identifier(value["id"])
        require(value["adapter"] in {"infra", "trivy"}, "unsupported scanner")
        with self.store.transaction() as tx:
            case, ledger = self._case(tx, key), self._runtime(tx, key)
            require(value["id"] not in ledger["scans"] and len(ledger["scans"]) < 32, "scan ID reused or limit reached")
            producer, output = self._scan_producer(case, tx, value["operation"], value["adapter"])
            ledger["scans"][value["id"]] = {"producer": producer, "adapter": value["adapter"], "output": output, "invalidated": False}
            tx.put("runtime-review", key, ledger)
        return {"status": "recorded", "lead_count": len(output["leads"]), "security_verdict": "not_established"}

    def inspect_container(self, key, value):
        fields(value, {"id", "deployment", "container_id", "expected_image", "expires_at"})
        identifier(value["id"])
        require(re.fullmatch(r"[0-9a-f]{64}", value["container_id"]) and re.fullmatch(r"sha256:[0-9a-f]{64}", value["expected_image"]), "immutable container and image required")
        number(value["expires_at"], self.clock() + 1, self.clock() + 3600)
        require(self.docker is not None, "local Docker adapter unavailable")
        with self.store.transaction() as tx:
            case, ledger = self._case(tx, key), self._runtime(tx, key)
            require(any(d["id"] == value["deployment"] for d in case["scope"]["deployments"]), "deployment unavailable")
            require(value["id"] not in ledger["containers"] and len(ledger["containers"]) < 32, "container observation ID reused or limit reached")
            # Reserve before daemon access; a controller interruption cannot replay this intent.
            ledger["containers"][value["id"]] = {"spec": value, "status": "unfinished", "invalidated": False}
            tx.put("runtime-review", key, ledger)
        head = self.web.fresh_head()
        prerequisite = self.docker.observe()
        rows = parse(self.docker.checked(["container", "inspect", value["container_id"]]))
        require(isinstance(rows, list) and len(rows) == 1 and rows[0].get("Id") == value["container_id"], "container differs")
        require(re.fullmatch(r"sha256:[0-9a-f]{64}", rows[0].get("Image", "")), "image identity unavailable")
        images = parse(self.docker.checked(["image", "inspect", rows[0]["Image"]]))
        require(isinstance(images, list) and len(images) == 1, "image observation unavailable")
        summary = container_summary(rows[0], images[0])
        record = {"spec": value, "status": "completed", "head": head, "observed_at": self.clock(),
            "collector": prerequisite, "executable": str(self.docker.executable), "scope_sha256": case["scope_sha256"],
            "output": summary, "matches_declared_image": value["expected_image"] in summary["repository_digests"] or value["expected_image"] == summary["image_id"], "invalidated": False}
        with self.store.transaction() as tx:
            case, ledger = self._case(tx, key), self._runtime(tx, key)
            require(case["scope_sha256"] == record["scope_sha256"], "scope changed during collection")
            ledger["containers"][value["id"]] = record
            tx.put("runtime-review", key, ledger)
        return {"status": "observed", "id": value["id"], "matches_declared_image": record["matches_declared_image"], "security_verdict": "not_established"}

    def _container(self, case, ledger, key, tx):
        record = ledger["containers"].get(key)
        require(record is not None and record["status"] == "completed" and not record["invalidated"]
                and self.clock() < record["spec"]["expires_at"] and record["scope_sha256"] == case["scope_sha256"], "container evidence unavailable")
        head = tx.get("candidate", record["head"]["candidate"])
        require(head is not None and digest(head) == record["head"]["record_sha256"]
                and selected_tree(self.package, HEAD_RESOURCES) == record["head"]["manifest"], "container producer changed")
        self.web.controller.reviewed(record["head"]["candidate"], head, tx)
        executable = Path(record["executable"])
        require(sha256(read_file(executable.parent, executable.name, 256 * 1024 * 1024)) == record["collector"]["executable_sha256"], "container collector executable changed")
        return record

    def _comparison(self, case, specification, tx):
        results, credentials, identities, resources = [], set(), set(), set()
        for row in specification["cases"]:
            record, auth, route = self.web.observation(case, row["operation"], tx)
            require(route["kind"] == "resource", "comparison needs resource predicates")
            require(auth["spec"]["deployment"] == specification["deployment"], "comparison environment differs")
            resources.add((route["url"], route["method"]))
            actor = next(a for a in case["scope"]["model"]["actors"] if a["id"] == route["actor"])
            if actor["kind"] != "anonymous":
                proof, proof_auth, proof_route = self.web.observation(case, row["identity_operation"], tx)
                require(proof["matched"] and proof_route["kind"] == "identity" and proof_route["id"] == route["identity"]
                        and proof_route["actor"] == route["actor"] and proof["authorization"] == record["authorization"]
                        and proof["credential_binding"] == record["credential_binding"]
                        and 0 <= record["started_at"] - proof["finished_at"] <= 300, "matching recent identity observation required")
                require(record["credential_binding"] not in credentials and proof_route["body_sha256"] not in identities, "compared actors need distinct credentials and identity predicates")
                credentials.add(record["credential_binding"])
                identities.add(proof_route["body_sha256"])
            else: require(row["identity_operation"] is None, "anonymous identity proof unsupported")
            if row["expectation"] == "allowed": require(route["statuses"] == [200], "positive control requires resource success predicate")
            else: require(set(route["statuses"]) <= {401, 403, 404}, "denial requires explicit denied response and body predicate")
            results.append({"operation": row["operation"], "actor": route["actor"], "expectation": row["expectation"],
                "matched": record["matched"], "response_predicate_matched": record["matched"],
                "producer_sha256": digest(record), "observed_at": record["finished_at"],
                "body_sha256": record["hops"][-1]["output"]["body_sha256"]})
        require(len(resources) == 1, "compared roles must request the same exact resource and method")
        require(len({r["actor"] for r in results}) == len(results), "duplicate compared actor")
        positive = next(r for r in results if r["expectation"] == "allowed")
        for row in results:
            row["same_body_as_positive"] = row["body_sha256"] == positive["body_sha256"]
            if row["expectation"] == "denied" and row["same_body_as_positive"]:
                row["matched"] = False
        return results

    def compare(self, key, value):
        fields(value, {"id", "deployment", "policy_basis", "identity_basis", "cases"})
        identifier(value["id"])
        for field in ("policy_basis", "identity_basis"): text(value[field], 4096)
        for row in contracts.items(value["cases"], 8, 2):
            fields(row, {"operation", "identity_operation", "expectation"})
            require(row["expectation"] in {"allowed", "denied"}, "unsupported comparison expectation")
        require(sum(r["expectation"] == "allowed" for r in value["cases"]) == 1, "one legitimate positive control required")
        with self.store.transaction() as tx:
            case, ledger = self._case(tx, key), self._runtime(tx, key)
            require(value["id"] not in ledger["comparisons"] and len(ledger["comparisons"]) < 32, "comparison ID reused or limit reached")
            results = self._comparison(case, value, tx)
            ledger["comparisons"][value["id"]] = {"spec": value, "results": results, "invalidated": False}
            tx.put("runtime-review", key, ledger)
        return {"status": "recorded", "expectations_satisfied": all(r["matched"] for r in results), "security_verdict": "not_established"}

    def _release(self, case, ledger, specification, tx):
        container = self._container(case, ledger, specification["container"], tx)
        require(container["spec"]["deployment"] == specification["deployment"] and container["spec"]["expected_image"] == specification["artifact"]
                and container["matches_declared_image"] and container["output"]["running"], "observed runtime artifact differs or is not running")
        deployment = next(d for d in case["scope"]["deployments"] if d["id"] == specification["deployment"])
        require(deployment["artifact"] == specification["artifact"], "declared deployment artifact differs")
        comparisons = []
        for name in specification["comparisons"]:
            record = ledger["comparisons"].get(name)
            require(record is not None and not record["invalidated"] and record["spec"]["deployment"] == specification["deployment"], "required comparison unavailable")
            result = self._comparison(case, record["spec"], tx)
            require(result == record["results"] and all(r["matched"] for r in result), "runtime comparison failed or changed")
            comparisons.append(digest(record))
        if case["source"] is not None: self._current(case)
        return {"container_sha256": digest(container), "comparison_sha256": comparisons,
                "captured_source_manifest_sha256": digest(case["source"]["manifest"]) if case["source"] else None,
                "source_to_image_provenance": "not_established", "url_to_container_routing": "not_established"}

    def release_check(self, key, value):
        fields(value, {"id", "deployment", "stage", "artifact", "container", "comparisons", "reviewer", "basis"})
        identifier(value["id"])
        require(value["stage"] in {"pre-release", "post-release"}, "unsupported release stage")
        contracts.ids(value["comparisons"], 16, 1)
        for field in ("reviewer", "basis"): text(value[field], 4096)
        with self.store.transaction() as tx:
            case, ledger = self._case(tx, key), self._runtime(tx, key)
            require(value["id"] not in ledger["releases"] and len(ledger["releases"]) < 32, "release check ID reused or limit reached")
            result = self._release(case, ledger, value, tx)
            ledger["releases"][value["id"]] = {"spec": value, "bindings": result, "invalidated": False}
            tx.put("runtime-review", key, ledger)
        return {"status": "recorded", "declared_correspondence": True, "deployment_approved": False, "security_verdict": "not_established"}

    def import_runtime_evidence(self, key, value):
        fields(value, {"observation", "operation"})
        spec = copy.deepcopy(value["observation"])
        contracts.observation(spec, self.clock())
        require(spec["method"] == "deployed_observation" and not spec["files"], "runtime evidence requires deployed observation")
        with self.store.transaction() as tx:
            case = self._case(tx, key)
            record, auth, route = self.web.observation(case, value["operation"], tx)
            control = case["controls"].get(spec["control"])
            require(control and spec["method"] in control["definition"]["methods"]
                    and control["surface"] == "deployment" and control["deployment"] == auth["spec"]["deployment"]
                    and (control["actor"] is None or control["actor"] == route["actor"])
                    and spec["observed_at"] == record["finished_at"] and spec["expires_at"] <= auth["spec"]["limits"]["expires_at"], "runtime control or timestamps differ")
            require(spec["id"] not in case["evidence"] and len(case["evidence"]) < 256, "evidence ID reused or limit reached")
            bindings = self._bindings(case, control, [], spec["actor"], spec["context_refs"])
            case["evidence"][spec["id"]] = {"spec": spec, "bindings": bindings, "origin": "m4_web",
                "producer": {"operation": value["operation"], "record_sha256": digest(record),
                    "output_sha256": digest(record["hops"]), "inputs_sha256": digest([case["scope_sha256"], route]),
                    "components": {"head": auth["head"]["record_sha256"]}, "exit_code": None},
                "recorded_at": self.clock(), "invalidated": False}
            tx.put("assessment", key, case)
        return {"status": "recorded", "origin": "m4_web"}

    def _supports_satisfied(self, case, item, tx):
        if item["origin"] == "m4_web":
            record, _auth, _route = self.web.observation(case, item["producer"]["operation"], tx)
            return record["matched"]
        return super()._supports_satisfied(case, item, tx)

    def _validity(self, case, item, tx, file_cache=None):
        valid, reason = super()._validity(case, item, tx, file_cache)
        if valid and item["origin"] == "m4_web":
            try:
                record, _auth, _route = self.web.observation(case, item["producer"]["operation"], tx)
                require(digest(record) == item["producer"]["record_sha256"], "runtime producer changed")
            except (ValueError, OSError, KeyError, TypeError): return False, "Runtime producer is unavailable, expired or changed."
        return valid, reason

    def invalidate_runtime(self, key, kind, name):
        require(kind in {"web", "scans", "comparisons", "containers", "releases"}, "unsupported evidence kind")
        if kind == "web":
            with self.store.transaction() as tx:
                case = self._case(tx, key)
                record = tx.get("web-operation", name)
                require(record is not None and tx.get("web-authority", record["authorization"])["assessment"] == key, "operation belongs to another assessment")
            return self.web.invalidate(name)
        with self.store.transaction() as tx:
            self._case(tx, key)
            ledger = self._runtime(tx, key)
            require(name in ledger[kind], "runtime evidence unavailable")
            ledger[kind][name]["invalidated"] = True
            tx.put("runtime-review", key, ledger)
        return {"status": "invalidated"}

    def runtime_report(self, key):
        with self.store.transaction() as tx:
            case, ledger = self._case(tx, key), self._runtime(tx, key)
            report = {"schema_version": 1, "assessment": key, "generated_at": self.clock(), "scope_sha256": case["scope_sha256"],
                "security_verdict": "not_established", "network": [], "scans": [], "containers": [], "comparisons": [], "releases": []}
            for name, operation in tx.list("web-operation").items():
                auth = tx.get("web-authority", operation["authorization"])
                if auth is None or auth["assessment"] != key: continue
                valid = True
                try: self.web.observation(case, name, tx)
                except (ValueError, OSError, KeyError, TypeError): valid = False
                report["network"].append({"operation": name, "authorization": operation["authorization"], "route": operation["route"],
                    "deployment": auth["spec"]["deployment"], "valid": valid, "status": operation["status"], "matched": operation.get("matched"),
                    "started_at": operation["started_at"], "finished_at": operation.get("finished_at"), "producer_sha256": digest(operation), "hops": operation["hops"]})
            for kind in ("scans", "containers", "comparisons", "releases"):
                for name, record in ledger[kind].items():
                    valid = not record["invalidated"]
                    try:
                        if kind == "scans": self._scan_producer(case, tx, record["producer"]["operation"], record["adapter"], record["producer"])
                        elif kind == "containers": self._container(case, ledger, name, tx)
                        elif kind == "comparisons": require(self._comparison(case, record["spec"], tx) == record["results"], "comparison changed")
                        else: require(self._release(case, ledger, record["spec"], tx) == record["bindings"], "delivery evidence changed")
                    except (ValueError, OSError, KeyError, TypeError, StopIteration): valid = False
                    visible = {k: v for k, v in record.items() if k not in {"head", "executable", "invalidated"}}
                    if kind == "scans":
                        visible["producer"] = {k: v for k, v in record["producer"].items() if k != "components"}
                        visible["producer"]["components"] = [{"component": component, "sha256": fingerprint}
                            for component, fingerprint in record["producer"]["components"].items()]
                    report[kind].append({"id": name, "valid": valid, **visible})
            report["gaps"] = ["General active scanning, mutation, load tests and remote host/cloud account inspection are not implemented.",
                "HTTP identity predicates are server responses, not independent identity attestation; complete exact bodies are required for role comparisons.",
                "Container observations cover one local container at one time. Source-to-image build provenance, URL routing and other replicas remain unverified.",
                "Bundled Trivy rules belong to the current reviewed tool release; external check feeds and vulnerability databases are not selected or silently substituted."]
            if case["source"] is None: report["gaps"].append("Source and infrastructure files unavailable; no source/configuration assessment.")
            if not case["scope"]["deployments"]: report["gaps"].append("No deployed target; no runtime observation.")
            return redact(report, case["scope"]["redact_values"])

    def write_runtime_report(self, key):
        report = self.runtime_report(key)
        lines = ["# Runtime, infrastructure and delivery review", "", "Security verdict: not established.", ""]
        for field in ("assessment", "generated_at", "scope_sha256"): lines += [field + ": " + markdown(report[field]), ""]
        def table(headers, rows):
            lines.extend(["| " + " | ".join(headers) + " |", "| " + " | ".join("---" for _ in headers) + " |"])
            for row in rows: lines.append("| " + " | ".join(markdown(v) for v in row) + " |")
            lines.append("")
        lines += ["## Network observations", "", "Valid evidence is a completed current observation, not a security verdict. A false predicate requires investigation.", ""]
        table(["Operation / authority", "Route / deployment", "Valid", "Status", "Predicate matched", "Observed at"],
              [[r["operation"] + " / " + r["authorization"], r["route"] + " / " + r["deployment"], r["valid"], r["status"], r["matched"], r["finished_at"]] for r in report["network"]])
        for row in report["network"]:
            lines += ["Observation " + markdown(row["operation"]) + "; producer digest: " + markdown(row["producer_sha256"]), ""]
            table(["Destination digest", "Hop state", "HTTP status", "Body bytes / digest"],
                  [[h["url_sha256"], h["status"], h.get("output", {}).get("status"),
                    str(h.get("output", {}).get("body_bytes")) + " / " + str(h.get("output", {}).get("body_sha256"))] for h in row["hops"]])
        lines += ["## Infrastructure leads", "", "Each lead needs source/context validation and a legitimate-behavior retest. No lead is automatically confirmed.", ""]
        for row in report["scans"]:
            lines += ["### " + markdown(row["id"]), "", "Adapter: " + markdown(row["adapter"]) + "; valid: " + markdown(row["valid"]), "",
                "Producer operation: " + markdown(row["producer"]["operation"]) + "; output digest: " + markdown(row["producer"]["output_sha256"]), ""]
            table(["Selected file", "Coverage"], [[f["path"], f["status"]] for f in row["output"]["files"]])
            table(["Lead / rule", "Location", "Why review", "Correction to evaluate"],
                  [[l["id"] + " / " + l["rule"], l["path"] + ":" + str(l["line"]), l["title"], l["fix"]] for l in row["output"]["leads"]])
        lines += ["## Local container observations", "", "Observations are time-limited snapshots. They do not establish URL routing or current state after collection.", ""]
        for row in report["containers"]:
            lines += ["### " + markdown(row["id"]), "", "Valid: " + markdown(row["valid"]) + "; state: " + markdown(row["status"]), ""]
            table(["Deployment", "Container", "Declared image", "Observed image", "Matches", "Observed at"],
                  [[row["spec"]["deployment"], row["spec"]["container_id"], row["spec"]["expected_image"], row.get("output", {}).get("image_id"), row.get("matches_declared_image"), row.get("observed_at")]])
            table(["Rule", "Why review", "Correction to evaluate"], [[l["rule"], l["title"], l["fix"]] for l in row.get("output", {}).get("leads", [])])
        lines += ["## Role comparisons", "", "Every actor must request the same resource. A denied response with the same complete body as the positive control fails regardless of its status or configured predicate.", ""]
        for row in report["comparisons"]:
            lines += ["### " + markdown(row["id"]), "", "Valid: " + markdown(row["valid"]), "", "Policy: " + markdown(row["spec"]["policy_basis"]), "",
                "Identity basis: " + markdown(row["spec"]["identity_basis"]), ""]
            table(["Actor", "Expected access", "Satisfied", "Same body as owner", "Operation"],
                  [[r["actor"], r["expectation"], r["matched"], r["same_body_as_positive"], r["operation"]] for r in row["results"]])
        lines += ["## Pre/post-release correspondence", "", "This check never approves a deployment. Source-to-image provenance and URL-to-container routing remain unestablished.", ""]
        table(["Check", "Valid", "Stage", "Deployment", "Artifact", "Container observation", "Role comparisons"],
              [[r["id"], r["valid"], r["spec"]["stage"], r["spec"]["deployment"], r["spec"]["artifact"], r["spec"]["container"], ", ".join(r["spec"]["comparisons"])] for r in report["releases"]])
        lines += ["## Next actions", "", "Investigate failed predicates and leads using their operation IDs and exact locations. Corroborate impact before confirming a finding. Prepare source/configuration corrections through M3 where supported, preserve legitimate access, and collect new authorized runtime evidence after a separately authorized deployment. Expired or invalid evidence must be renewed; old successful observations cannot close current gaps.", ""]
        lines += ["## Coverage gaps", ""] + ["- " + markdown(gap) for gap in report["gaps"]]
        name = "m4-report-" + secrets.token_hex(12)
        (self.store.root / (name + ".json")).write_bytes(canonical(report) + b"\n")
        (self.store.root / (name + ".md")).write_text("\n".join(lines) + "\n", encoding="utf-8")
        return {"status": "written", "json": name + ".json", "markdown": name + ".md", "security_verdict": "not_established"}
