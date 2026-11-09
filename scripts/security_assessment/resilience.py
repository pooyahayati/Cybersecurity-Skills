"""M5 bounded workload, artifact recovery and private incident observations."""

import copy
from pathlib import Path
import secrets

from security_runtime.common import canonical, digest, fields, identifier, integer, number, parse, read_file, require, sha256, text
from security_runtime.controller import HEAD_RESOURCES, selected_tree
from security_runtime.load import LoadController
from security_runtime.web_scope import url
from .redaction import markdown, redact
from .resilience_data import contract as data_contract
from .runtime import RuntimeReview


class ResilienceReview(RuntimeReview):
    def __init__(self, *args, upstream=None, **kwargs):
        super().__init__(*args, upstream=upstream, **kwargs)
        self.engine = digest([self.engine, "m5-resilience-v1", selected_tree(self.package, [
            "scripts/m5_review.py", "scripts/m5_worker.py", "scripts/security_assessment/resilience.py",
            "scripts/security_assessment/resilience_data.py", "scripts/security_runtime/load.py",
            "scripts/security_runtime/load_scope.py", "scripts/security_runtime/load_worker.py"])])
        self.load = LoadController(self.store, self.package, upstream, self.clock)

    def _resilience(self, tx, key):
        return tx.get("resilience", key, {"plans": {}, "artifacts": {}, "alerts": {}, "incidents": {}, "incident_reservations": {}})

    def load_authorize(self, key, value):
        with self.store.transaction() as tx: case = self._case(tx, key)
        return self.load.authorize(case, value)

    def load_execute(self, key, authorization, credentials=None, ca=None):
        with self.store.transaction() as tx: case = self._case(tx, key)
        return self.load.execute(case, authorization, credentials, ca)

    def recovery_plan(self, key, value):
        fields(value, {"id", "deployment", "ack_url"})
        identifier(value["id"])
        with self.store.transaction() as tx:
            case, ledger = self._case(tx, key), self._resilience(tx, key)
            self._current(case)
            require(case["source"] is not None and "m5-contract.json" in case["source"]["manifest"], "selected recovery contract required")
            deployment = next((d for d in case["scope"]["deployments"] if d["id"] == value["deployment"]), None)
            require(deployment is not None, "deployment unavailable")
            origin, target = url(deployment["url"]), url(value["ack_url"])
            require(origin[:3] == target[:3] and (origin[3] == "/" or target[3] == origin[3] or target[3].startswith(origin[3].rstrip("/") + "/")), "acknowledgment URL outside deployment")
            require(value["id"] not in ledger["plans"] and len(ledger["plans"]) < 32, "plan reused or limit reached")
            challenge = secrets.token_hex(24)
            body = {"exercise": value["id"], "challenge": challenge, "state": "delivered"}
            ledger["plans"][value["id"]] = {"spec": copy.deepcopy(value), "created_at": self.clock(), "challenge": challenge,
                "ack_body_sha256": digest(body), "source_sha256": digest(case["source"]["manifest"]), "used_by": None}
            tx.put("resilience", key, ledger)
        return {"status": "planned", "exercise": value["id"], "receiver_body": body, "receiver_body_sha256": digest(body),
                "next_step": "Run the offline restore, then trigger the authorized alert and collect this exact receiver acknowledgment using M4 authority."}

    def _artifact(self, case, tx, operation_id, expected=None):
        self._current(case)
        operation = tx.get("operation", operation_id)
        require(operation is not None and case["source"] is not None, "artifact producer unavailable")
        producer = self._operation(case, {"surface": "source"}, {"operation": operation_id,
            "files": sorted(case["source"]["manifest"]), "observed_at": operation.get("finished_at")}, tx, expected)
        auth = tx.get("authorization", operation["authorization"])
        require(auth["manifest"] == case["source"]["manifest"] and self.clock() < auth["spec"]["limits"]["expires_at"], "artifact authority differs or expired")
        selected, run = operation["specification"], tx.get("run", operation["run"])
        require(selected["interpreter"] == "python" and selected["entrypoint"] == "scripts/m5_worker.py" and selected["arguments"] == ["sqlite"], "not the M5 artifact worker")
        worker = tx.get("candidate", run["bindings"][selected["component"]])
        require(worker["kind"] == "tool" and worker["manifest"] == selected_tree(self.package, ["scripts"]), "worker implementation differs")
        for candidate in run["bindings"].values():
            record = self.web.controller.candidate(candidate, tx)
            self.web.controller.reviewed(candidate, record, tx)
        require(producer["exit_code"] == 0, "artifact worker did not finish")
        output = parse(read_file(self.store.root, operation_id + ".output", selected["max_output_bytes"]))
        fields(output, {"schema_version", "adapter", "mode", "contract_sha256", "restored", "rollback", "restore_seconds",
            "artifact_check_passed", "declared_loss_seconds", "declared_loss_within_budget", "capture_time_verified",
            "deployed_database_link_verified", "service_recovery_verified", "security_verdict", "files"})
        specification = parse(read_file(self.store.root / "objects" / case["source"]["object"], "m5-contract.json", 32768))
        data_contract(specification)
        require(output["schema_version"] == 1 and output["adapter"] == "sqlite-artifact" and output["mode"] == specification["mode"]
                and output["contract_sha256"] == digest(specification) and output["files"] == case["source"]["manifest"], "artifact output binding differs")
        require(output["security_verdict"] == "not_established" and all(output[k] is False for k in ("capture_time_verified", "deployed_database_link_verified", "service_recovery_verified")), "unsupported recovery claim")
        number(output["restore_seconds"], 0, selected["timeout_seconds"])
        for key, expected_spec in (("restored", {"database": specification["database"], "oracle": specification["oracle"]}), ("rollback", specification["rollback"])):
            result = output[key]
            if expected_spec is None:
                require(result is None, "unexpected rollback result")
                continue
            fields(result, {"snapshot_sha256", "readable", "passed", "tables"})
            require(result["snapshot_sha256"] == case["source"]["manifest"].get(expected_spec["database"]), "snapshot differs")
            require(type(result["readable"]) is bool and type(result["passed"]) is bool and isinstance(result["tables"], list), "invalid artifact result")
            if not result["readable"]:
                require(not result["passed"] and result["tables"] == [], "unreadable snapshot cannot pass")
                continue
            require(len(result["tables"]) == len(expected_spec["oracle"]), "incomplete table coverage")
            for table, oracle in zip(result["tables"], expected_spec["oracle"]):
                fields(table, {"table", "rows", "rows_sha256", "duplicates_or_null_keys", "matched"})
                integer(table["rows"], 0, 10000)
                require(table["table"] == oracle["table"] and type(table["duplicates_or_null_keys"]) is bool, "table differs")
                matched = table["rows"] == oracle["row_count"] and table["rows_sha256"] == oracle["rows_sha256"] and not table["duplicates_or_null_keys"]
                require(table["matched"] is matched, "table success inconsistent")
            require(result["passed"] is all(t["matched"] for t in result["tables"]), "artifact success inconsistent")
        objectives = specification["objectives"]
        passed = output["restored"]["passed"] and (output["rollback"] is None or output["rollback"]["passed"]) and (objectives is None or output["restore_seconds"] <= objectives["restore_seconds"])
        require(output["artifact_check_passed"] is passed, "recovery success inconsistent")
        return producer, output, specification

    def import_artifact(self, key, value):
        fields(value, {"id", "operation", "plan"})
        identifier(value["id"])
        with self.store.transaction() as tx:
            case, ledger = self._case(tx, key), self._resilience(tx, key)
            require(value["id"] not in ledger["artifacts"] and len(ledger["artifacts"]) < 32, "artifact ID reused or limit reached")
            producer, output, specification = self._artifact(case, tx, value["operation"])
            if output["mode"] == "recovery":
                plan = ledger["plans"].get(value["plan"])
                require(plan is not None and plan["used_by"] is None and plan["source_sha256"] == digest(case["source"]["manifest"]), "unused matching recovery plan required")
                operation = tx.get("operation", value["operation"])
                require(operation["started_at"] >= plan["created_at"], "recovery operation predates plan")
                plan["used_by"] = value["id"]
            else: require(value["plan"] is None, "integrity check has no recovery plan")
            ledger["artifacts"][value["id"]] = {"producer": producer, "output": output, "expected_contract": specification, "plan": value["plan"], "invalidated": False}
            tx.put("resilience", key, ledger)
        return {"status": "recorded", "artifact_check_passed": output["artifact_check_passed"], "security_verdict": "not_established"}

    def _alert(self, case, tx, ledger, recovery, operation):
        artifact = ledger["artifacts"].get(recovery)
        require(artifact is not None and not artifact["invalidated"] and artifact["plan"] is not None, "recovery evidence unavailable")
        self._artifact(case, tx, artifact["producer"]["operation"], artifact["producer"])
        plan = ledger["plans"][artifact["plan"]]
        observed, authority, route = self.web.observation(case, operation, tx)
        recovery_operation = tx.get("operation", artifact["producer"]["operation"])
        require(observed["started_at"] >= recovery_operation["finished_at"] and observed["matched"] and len(observed["hops"]) == 1,
                "fresh complete post-exercise acknowledgment required")
        require(authority["spec"]["deployment"] == plan["spec"]["deployment"] and route["url"] == plan["spec"]["ack_url"] and route["method"] == "GET"
                and observed["hops"][0]["output"]["status"] == 200 and observed["hops"][0]["output"]["body_sha256"] == plan["ack_body_sha256"], "acknowledgment is not for this exercise/receiver")
        return digest(observed)

    def acknowledge(self, key, value):
        fields(value, {"recovery", "operation"})
        with self.store.transaction() as tx:
            case, ledger = self._case(tx, key), self._resilience(tx, key)
            require(value["recovery"] not in ledger["alerts"] and all(r["operation"] != value["operation"] for r in ledger["alerts"].values()), "acknowledgment reused")
            binding = self._alert(case, tx, ledger, value["recovery"], value["operation"])
            ledger["alerts"][value["recovery"]] = {"operation": value["operation"], "producer_sha256": binding}
            tx.put("resilience", key, ledger)
        return {"status": "observed_acknowledgment", "service_recovery_verified": False}

    def incident(self, key, value):
        fields(value, {"id", "kind", "files", "note", "claimed_at"})
        identifier(value["id"])
        require(value["kind"] in {"observation", "hypothesis", "containment-proposal", "recovery-proposal"}, "unsupported triage event")
        text(value["note"], 4096)
        number(value["claimed_at"], 0, self.clock() + 1)
        require(isinstance(value["files"], list) and len(value["files"]) <= 16 and len(set(value["files"])) == len(value["files"]), "invalid evidence files")
        intent = "capture-" + secrets.token_hex(16)
        contents = []
        with self.store.transaction() as tx:
            case, ledger = self._case(tx, key), self._resilience(tx, key)
            records = ledger["incidents"].setdefault(value["id"], [])
            reservations = ledger["incident_reservations"]
            require(len(ledger["incidents"]) <= 16 and len(reservations) < 1024
                    and sum(r["incident"] == value["id"] for r in reservations.values()) < 64, "incident attempt limit reached")
            total = sum(r["bytes"] for r in reservations.values())
            if value["files"]:
                self._current(case)
                require(case["source"] is not None and set(value["files"]) <= set(case["source"]["manifest"]), "evidence leaves selected source")
            for path in value["files"]:
                raw = read_file(case["source"]["root"], path, 1024 * 1024)
                require(sha256(raw) == case["source"]["manifest"][path], "evidence differs from selected snapshot")
                total += len(raw)
                require(total <= 16 * 1024 * 1024, "incident evidence exceeds aggregate bound")
                token = "incident-" + secrets.token_hex(16) + ".bin"
                contents.append((path, raw, {"object": token, "source_path_sha256": sha256(path.encode()), "sha256": sha256(raw), "bytes": len(raw)}))
            # This commit precedes every object write. Failed/interrupted captures
            # retain their whole reservation and cannot leave uncharged objects.
            reservations[intent] = {"incident": value["id"], "bytes": sum(len(raw) for _, raw, _ in contents),
                "objects": [item for _, _, item in contents], "status": "unfinished", "created_at": self.clock()}
            tx.put("resilience", key, ledger)
        try:
            for path, raw, item in contents:
                with (self.store.root / item["object"]).open("xb") as stream: stream.write(raw)
                require(sha256(read_file(case["source"]["root"], path, 1024 * 1024)) == item["sha256"], "source changed during preservation")
            with self.store.transaction() as tx:
                self._case(tx, key)
                ledger = self._resilience(tx, key)
                records = ledger["incidents"][value["id"]]
                event = {"sequence": len(records) + 1, "previous": digest(records[-1]) if records else None, "kind": value["kind"],
                    "collected_at": self.clock(), "claimed_at": value["claimed_at"], "note": value["note"], "evidence": [item for _, _, item in contents]}
                records.append(event)
                ledger["incident_reservations"][intent]["status"] = "completed"
                tx.put("resilience", key, ledger)
        except BaseException:
            with self.store.transaction() as tx:
                ledger = self._resilience(tx, key)
                ledger["incident_reservations"][intent]["status"] = "failed"
                tx.put("resilience", key, ledger)
            raise
        return {"status": "preserved", "sequence": event["sequence"], "event_sha256": digest(event), "containment_performed": False}

    def invalidate_resilience(self, key, kind, name):
        require(kind in {"load", "artifact"}, "unsupported invalidation")
        with self.store.transaction() as tx:
            self._case(tx, key)
            if kind == "load":
                record = tx.get("load-operation", name)
                require(record is not None and tx.get("load-authority", record["authorization"])["assessment"] == key, "operation belongs to another assessment")
                record["invalidated"] = True
                tx.put("load-operation", name, record)
            else:
                ledger = self._resilience(tx, key)
                require(name in ledger["artifacts"], "artifact unavailable")
                ledger["artifacts"][name]["invalidated"] = True
                tx.put("resilience", key, ledger)
        return {"status": "invalidated"}

    def resilience_report(self, key):
        with self.store.transaction() as tx:
            case, ledger = self._case(tx, key), self._resilience(tx, key)
            report = {"schema_version": 1, "assessment": key, "generated_at": self.clock(), "security_verdict": "not_established", "loads": [], "artifacts": [], "incidents": []}
            for name, record in tx.list("load-operation").items():
                auth = tx.get("load-authority", record["authorization"])
                if auth["assessment"] != key: continue
                spec = auth["spec"]
                route = spec["web"]["routes"][0]
                deployment = next(d for d in case["scope"]["deployments"] if d["id"] == spec["web"]["deployment"])
                valid = True
                try: self.load.observation(case, name, tx)
                except (ValueError, OSError, KeyError, TypeError): valid = False
                report["loads"].append({"operation": name, "valid": valid, "status": record["status"], "scenario": auth["spec"]["scenario"],
                    "context": {"deployment": deployment["id"], "environment": deployment["environment"], "declared_artifact": deployment["artifact"],
                        "route": route["id"], "actor": route["actor"], "method": route["method"], "url_sha256": sha256(route["url"].encode()),
                        "purpose": spec["purpose"], "workload": spec["workload"], "dataset": spec["dataset"], "phases": spec["phases"],
                        "acceptance": spec["acceptance"], "abort": spec["abort"], "limits": spec["web"]["limits"]},
                    "started_at": record["started_at"], "finished_at": record.get("finished_at"),
                    "producer": {"operation_sha256": digest(record), "output_sha256": record.get("output_sha256"),
                        "head_candidate": auth["head"]["candidate"], "head_record_sha256": auth["head"]["record_sha256"], "k6": auth["tool"]},
                    "workload_sha256": digest(auth["spec"]), "result": record.get("output"), "accepted": valid and record.get("output", {}).get("workload_passed", False),
                    "next_step": "Inspect errors, bottlenecks and generator gaps; repeat only with new bounded authority after the cause is resolved. Verify persisted state independently."})
            for name, record in ledger["artifacts"].items():
                valid = not record["invalidated"]
                try: self._artifact(case, tx, record["producer"]["operation"], record["producer"])
                except (ValueError, OSError, KeyError, TypeError): valid = False
                ack = ledger["alerts"].get(name)
                alert_valid = False
                if ack and valid:
                    try: alert_valid = self._alert(case, tx, ledger, name, ack["operation"]) == ack["producer_sha256"]
                    except (ValueError, OSError, KeyError, TypeError): pass
                visible = {k: v for k, v in record["output"].items() if k != "files"}
                visible["files"] = [{"path": path, "sha256": fingerprint} for path, fingerprint in record["output"]["files"].items()]
                producer = {k: v for k, v in record["producer"].items() if k != "components"}
                producer["components"] = [{"id": k, "record_sha256": v} for k, v in record["producer"]["components"].items()]
                operation = tx.get("operation", record["producer"]["operation"])
                authority = tx.get("authorization", operation["authorization"]) if operation else None
                # Preserve the validated import-time contract, including after
                # source retraction. Never display a newly tampered source file.
                expected = record["expected_contract"]
                plan = ledger["plans"].get(record["plan"])
                plan_context = {"id": record["plan"], "deployment": plan["spec"]["deployment"], "ack_url_sha256": sha256(plan["spec"]["ack_url"].encode()),
                    "ack_body_sha256": plan["ack_body_sha256"], "created_at": plan["created_at"]} if plan else None
                report["artifacts"].append({"id": name, "valid": valid, "result": visible, "observed_alert_acknowledgment": alert_valid,
                    "producer": producer, "expected_contract": expected, "recovery_plan": plan_context, "acknowledgment": ack,
                    "started_at": operation.get("started_at") if operation else None, "finished_at": operation.get("finished_at") if operation else None,
                    "expires_at": authority["spec"]["limits"]["expires_at"] if authority else None,
                    "accepted_artifact_check": valid and record["output"]["artifact_check_passed"], "service_recovery_verified": False,
                    "next_step": "Investigate unreadable backups, missing/duplicate transactions or changed state. Repair backup creation and retest a new disposable restore; independently verify capture time, service recovery and alert transport."})
            for name, events in ledger["incidents"].items():
                intact, previous, visible = True, None, []
                for index, event in enumerate(events, 1):
                    intact &= event["sequence"] == index and event["previous"] == previous
                    for artifact in event["evidence"]:
                        try: intact &= sha256(read_file(self.store.root, artifact["object"], 1024 * 1024)) == artifact["sha256"]
                        except (OSError, ValueError): intact = False
                    previous = digest(event)
                    visible.append({"sequence": index, "kind": event["kind"], "collected_at": event["collected_at"], "claimed_at": event["claimed_at"],
                        "note_sha256": sha256(event["note"].encode()), "event_sha256": previous,
                        "evidence": [{k: v for k, v in r.items() if k != "object"} for r in event["evidence"]]})
                attempts = [(k, r) for k, r in ledger["incident_reservations"].items() if r["incident"] == name]
                incomplete = [{"intent": k, "status": r["status"], "reserved_bytes": r["bytes"]} for k, r in attempts if r["status"] != "completed"]
                report["incidents"].append({"id": name, "custody_intact": bool(intact), "capture_complete": not incomplete,
                    "reserved_bytes": sum(r["bytes"] for _, r in attempts), "incomplete_captures": incomplete, "events": visible,
                    "next_step": "Preserve originals and restrict access; validate observations separately from hypotheses. Scope containment with the owner, retain recovery evidence and document decisions before any destructive cleanup."})
            report["gaps"] = ["A workload result covers measured read conditions only; target CPU/memory/queue saturation and persisted writes are not observed by the broker.",
                "SQLite checks concern selected standalone artifacts. Declared timestamps do not prove RPO; disposable restore time does not prove service RTO or deployment rollback.",
                "Alert evidence is a fresh exact receiver assertion; it does not independently attest the whole notification delivery chain.",
                "Incident custody assumes the control account and authenticated store remain trusted; whole-store rollback or host compromise is not prevented. No containment, notification or recurring monitoring is performed."]
        return redact(report, case["scope"]["redact_values"])

    def write_resilience_report(self, key):
        report = self.resilience_report(key)
        lines = ["# Capacity, recovery and incident observations", "", "Assessment: " + markdown(report["assessment"]), "",
            "Generated Unix time: " + markdown(report["generated_at"]), "", "No whole-system security or production approval is established.", ""]

        def table(headers, rows):
            lines.append("| " + " | ".join(headers) + " |")
            lines.append("| " + " | ".join("---" for _ in headers) + " |")
            lines.extend("| " + " | ".join(markdown(v) for v in row) + " |" for row in rows)
            lines.append("")

        lines += ["## Sampled read workloads", ""]
        for row in report["loads"]:
            result = row["result"] or {}
            lines += ["### " + markdown(row["operation"]), ""]
            context = row["context"]
            table(["Deployment", "Environment", "Declared artifact", "Route / actor / method", "URL digest"],
                [[context["deployment"], context["environment"], context["declared_artifact"], " / ".join(str(context[k]) for k in ("route", "actor", "method")), context["url_sha256"]]])
            table(["Purpose", "Declared workload", "Declared dataset"], [[context[k] for k in ("purpose", "workload", "dataset")]])
            table(["Authorized phase", "Request ceiling", "Concurrency ceiling", "Admission RPS ceiling", "Duration ceiling seconds"],
                [[p[k] for k in ("id", "requests", "concurrency", "rps", "seconds")] for p in context["phases"]])
            table(["p95 ceiling ms", "Error ratio ceiling", "Minimum successful RPS", "Abort errors / latency ms"],
                [[context["acceptance"]["p95_ms"], context["acceptance"]["error_rate"], context["acceptance"]["minimum_success_rps"],
                  str(context["abort"]["errors"]) + " / " + str(context["abort"]["latency_ms"])]])
            table(["Started Unix time", "Finished Unix time", "Authority expiry", "Request / seconds / body-byte ceilings"],
                [[row["started_at"], row["finished_at"], context["limits"]["expires_at"], " / ".join(str(context["limits"][k]) for k in ("requests", "seconds", "body_bytes"))]])
            table(["Head candidate", "k6 candidate / version", "k6 binary digest", "Operation / output digest"],
                [[row["producer"]["head_candidate"], row["producer"]["k6"]["candidate"] + " / " + row["producer"]["k6"]["version"], row["producer"]["k6"]["binary_sha256"],
                  str(row["producer"]["operation_sha256"]) + " / " + str(row["producer"]["output_sha256"])]])
            table(["Valid evidence", "Operation state", "Sample criteria met", "Stop reason"],
                [[row["valid"], row["status"], row["accepted"], result.get("stop_reason")]])
            table(["Planned", "Offered", "Admitted", "Completed", "Successful", "Errors", "Unfinished"],
                [[result.get(k) for k in ("planned", "offered", "admitted", "completed", "successful", "errors", "unfinished")]])
            table(["Successful RPS", "p50 ms", "p95 ms", "p99 ms", "Elapsed seconds"],
                [[result.get(k) for k in ("successful_rps", "p50_ms", "p95_ms", "p99_ms", "elapsed_seconds")]])
            table(["Phase", "Planned / completed", "Peak in flight", "Generator exit", "Rejected tickets"],
                [[p["id"], str(p["planned"]) + " / " + str(p["completed"]), p["peak_in_flight"], p["generator_exit"], p["rejected_tickets"]] for p in result.get("phases", [])])
            lines += [markdown(row["next_step"]), ""]
        lines += ["## Persisted artifacts and disposable recovery", ""]
        for row in report["artifacts"]:
            result = row["result"]
            lines += ["### " + markdown(row["id"]), ""]
            table(["M1 operation", "Input / output digest", "Started / finished Unix time", "Authority expiry"],
                [[row["producer"]["operation"], row["producer"]["inputs_sha256"] + " / " + row["producer"]["output_sha256"],
                  str(row["started_at"]) + " / " + str(row["finished_at"]), row["expires_at"]]])
            table(["Producer component", "Record digest"], [[c["id"], c["record_sha256"]] for c in row["producer"]["components"]])
            expected = row["expected_contract"]
            if expected:
                for kind, specification in (("Restoration", expected), ("Rollback", expected["rollback"])):
                    if specification is not None:
                        table(["Expected artifact", "Table", "Columns", "Expected rows / digest", "Unique keys"],
                            [[kind + " / " + str(specification["database"]), o["table"], ", ".join(o["columns"]), str(o["row_count"]) + " / " + o["rows_sha256"],
                              "; ".join(", ".join(k) for k in o["unique"])] for o in specification["oracle"]])
                if expected["objectives"]:
                    objective = expected["objectives"]
                    table(["Restore ceiling seconds", "Allowed declared loss seconds", "Declared snapshot / reference time"],
                        [[objective["restore_seconds"], objective["allowed_loss_seconds"], str(objective["declared_snapshot_at"]) + " / " + str(objective["declared_reference_at"])]])
            if row["recovery_plan"]:
                plan = row["recovery_plan"]
                table(["Recovery plan / deployment", "Receiver URL / body digest", "Acknowledgment operation"],
                    [[str(plan["id"]) + " / " + str(plan["deployment"]), str(plan["ack_url_sha256"]) + " / " + str(plan["ack_body_sha256"]),
                      row["acknowledgment"]["operation"] if row["acknowledgment"] else "missing"]])
            table(["Valid evidence", "Artifact criteria met", "Receiver acknowledgment", "Service recovery verified"],
                [[row["valid"], row["accepted_artifact_check"], row["observed_alert_acknowledgment"], False]])
            table(["Artifact", "Readable", "State matched", "Snapshot digest"],
                [[kind, result[kind]["readable"], result[kind]["passed"], result[kind]["snapshot_sha256"]] for kind in ("restored", "rollback") if result[kind] is not None])
            table(["Table", "Rows", "Duplicate/null keys", "Expected state matched"],
                [[t["table"], t["rows"], t["duplicates_or_null_keys"], t["matched"]] for t in result["restored"]["tables"]])
            table(["Disposable restore seconds", "Declared loss seconds", "Declared loss within budget", "Capture time verified"],
                [[result["restore_seconds"], result["declared_loss_seconds"], result["declared_loss_within_budget"], False]])
            lines += [markdown(row["next_step"]), ""]
        lines += ["## Preserved incident evidence", ""]
        for row in report["incidents"]:
            lines += ["### " + markdown(row["id"]), "", "Custody intact: " + markdown(row["custody_intact"]) + "; all captures complete: " + markdown(row["capture_complete"]) + "; incomplete attempts: " + str(len(row["incomplete_captures"])), ""]
            table(["Sequence", "Kind", "Collected Unix time", "Claimed Unix time", "Preserved files", "Event digest"],
                [[e["sequence"], e["kind"], e["collected_at"], e["claimed_at"], len(e["evidence"]), e["event_sha256"]] for e in row["events"]])
            lines += [markdown(row["next_step"]), ""]
        lines += ["## Limits and next checks", ""] + ["- " + markdown(gap) for gap in report["gaps"]]
        name = "m5-report-" + secrets.token_hex(12)
        (self.store.root / (name + ".json")).write_bytes(canonical(report) + b"\n")
        (self.store.root / (name + ".md")).write_text("\n".join(lines) + "\n", encoding="utf-8")
        return {"status": "written", "json": name + ".json", "markdown": name + ".md", "security_verdict": "not_established"}
