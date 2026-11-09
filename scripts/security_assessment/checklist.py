"""Offline checklist planning. Capability descriptions never qualify a target."""

import copy
from pathlib import Path

from security_runtime.common import digest, fields, parse, read_file, relpath, require, text


GROUPS = ("architecture", "identity", "authorization", "data", "application", "business",
          "integrations", "supply-chain", "infrastructure", "detection", "recovery", "verification")
CATALOG = "config/security-checklist.json"
SOURCE = "https://pooyahayati.com/services/software-audit-security/checklist/"
PHASES = {"C1", "C2", "C3", "C4", "C5", "C6"}


def _text(value, limit):
    text(value, limit)
    require(value.strip(), "checklist text must contain non-whitespace content")


def _strings(values, maximum=16):
    require(isinstance(values, list) and 1 <= len(values) <= maximum, "nonempty bounded text list required")
    for value in values:
        _text(value, 2048)
    require(len(set(values)) == len(values), "duplicate text item")


def validate_catalog(value, modules, legacy_controls):
    fields(value, {"schema_version", "profile", "catalog_version", "purpose", "source",
                   "assessment_default", "groups", "capabilities", "controls"})
    require(type(value["schema_version"]) is int and value["schema_version"] == 1,
            "unsupported checklist schema")
    require(value["profile"] == "service-security-audit" and value["catalog_version"] == "1.0",
            "unsupported checklist profile")
    require(value["assessment_default"] == "unverified", "a planning catalog cannot claim an assessment outcome")
    _text(value["purpose"], 2048)
    source = value["source"]
    fields(source, {"url", "section", "reviewed_on", "expected_groups", "expected_controls", "interpretation"})
    require(source["url"] == SOURCE and source["section"] == "Security Audit", "unexpected checklist source")
    require(type(source["expected_groups"]) is int and source["expected_groups"] == 12
            and type(source["expected_controls"]) is int and source["expected_controls"] == 36,
            "the complete source profile requires 12 groups and 36 controls")
    from datetime import date
    require(isinstance(source["reviewed_on"], str)
            and date.fromisoformat(source["reviewed_on"]).isoformat() == source["reviewed_on"], "invalid review date")
    _text(source["interpretation"], 2048)
    require(isinstance(value["groups"], list) and len(value["groups"]) == 12, "missing checklist groups")
    groups = {}
    for group in value["groups"]:
        fields(group, {"id", "title", "module", "legacy_control"})
        require(isinstance(group["id"], str) and group["id"] in GROUPS
                and group["id"] not in groups, "unknown or duplicate checklist group")
        require(group["module"] in modules and group["legacy_control"] in legacy_controls,
                "checklist module or legacy control unavailable")
        _text(group["title"], 256)
        groups[group["id"]] = group
    require(set(groups) == set(GROUPS), "incomplete checklist group inventory")
    require(isinstance(value["capabilities"], list) and 1 <= len(value["capabilities"]) <= 32,
            "invalid capability inventory")
    capabilities = {}
    for capability in value["capabilities"]:
        fields(capability, {"id", "state", "paths", "limit"})
        _text(capability["id"], 64)
        require(capability["id"] not in capabilities and capability["state"] in {"guidance", "bounded"},
                "duplicate capability or unsupported qualification claim")
        _strings(capability["paths"])
        for path in capability["paths"]:
            relpath(path)
            require(path.startswith(("scripts/", "docs/", "references/")), "unsupported capability reference")
        _text(capability["limit"], 2048)
        capabilities[capability["id"]] = capability
    require(isinstance(value["controls"], list) and len(value["controls"]) == 36, "all 36 checklist controls are required")
    ids, source_items = set(), set()
    for control in value["controls"]:
        fields(control, {"id", "group", "source_item", "title", "capabilities", "required_evidence",
                         "acceptance", "legitimate_test", "prohibited_test", "remaining_gap", "phase"})
        require(isinstance(control["group"], str) and control["group"] in groups, "unknown control group")
        item = control["source_item"]
        require(type(item) is int and 1 <= item <= 3, "invalid source item")
        expected = "audit-" + str(GROUPS.index(control["group"]) * 3 + item).zfill(2)
        require(control["id"] == expected and expected not in ids, "duplicate or remapped checklist identity")
        ids.add(expected)
        source_items.add((control["group"], item))
        _strings(control["capabilities"])
        require(set(control["capabilities"]) <= set(capabilities), "unknown linked capability")
        _strings(control["required_evidence"])
        for name in ("title", "acceptance", "legitimate_test", "prohibited_test", "remaining_gap"):
            _text(control[name], 2048)
        require(control["phase"] in PHASES, "unknown implementation phase")
    require(source_items == {(group, item) for group in GROUPS for item in (1, 2, 3)},
            "source checklist coverage is incomplete")
    return value


def load_catalog(package):
    package = Path(package)
    from .service import load_catalog as load_legacy
    modules = parse(read_file(package, "config/modules.json", 1024 * 1024))
    legacy = load_legacy(package)
    value = validate_catalog(parse(read_file(package, CATALOG, 1024 * 1024)),
                             {m["id"] for m in modules["modules"]}, {c["id"] for c in legacy["controls"]})
    # Verify references in both a checkout and an installed package. Do not import
    # referenced code or follow remote links. Tests are intentionally not required
    # resources in the installable skill payload.
    for capability in value["capabilities"]:
        for path in capability["paths"]:
            read_file(package, path, 1024 * 1024)
    return value


def plan(catalog):
    """An unbound planning template, never a completed evidence record."""
    groups = {group["id"]: group for group in catalog["groups"]}
    capabilities = {item["id"]: item for item in catalog["capabilities"]}
    controls = []
    for item in sorted(catalog["controls"], key=lambda c: c["id"]):
        row = copy.deepcopy(item)
        row.update({"module": groups[item["group"]]["module"],
                    "legacy_control_template": groups[item["group"]]["legacy_control"],
                    "capability_limits": [copy.deepcopy(capabilities[key]) for key in item["capabilities"]],
                    "applicability": "unknown", "scope": None, "progress": "not_started",
                    "outcome": "unverified", "evidence": [], "reviewer": None,
                    "observed_at": None, "expires_at": None, "rationale": None})
        controls.append(row)
    return {"schema_version": 1, "type": "security_checklist_plan", "profile": catalog["profile"],
            "catalog_sha256": digest(catalog), "source": copy.deepcopy(catalog["source"]),
            "assessment_performed": False, "security_verdict": "not_established",
            "tool_activation": "none", "controls": controls,
            "limitations": ["This is an unbound planning template, not an assessment or execution receipt.",
                            "Capability availability, target applicability and target outcome are independent.",
                            "Use the M2 evidence ledger and applicable M1-M5 methods for actual observations.",
                            "One broad legacy control or chapter reference cannot close its finer checklist items.",
                            "Other service sections, active penetration tests and recurring operations need separate scope."]}


def markdown_plan(value):
    from .redaction import markdown
    lines = ["# Security checklist assessment plan", "", "Assessment performed: **no**.",
             "Security verdict: **not established**. Tool activation: **none**.", "",
             "Profile: " + markdown(value["profile"]) + ". Catalog SHA-256: " + markdown(value["catalog_sha256"]) + ".", "",
             "Source: " + markdown(value["source"]["url"]), "",
             "Section: " + markdown(value["source"]["section"]) + ". Source reviewed: " + markdown(value["source"]["reviewed_on"]) + ".", "",
             "All 36 outcomes start unverified. This document contains proposed checks, not test results.", ""]
    for row in value["controls"]:
        lines.extend(["## " + markdown(row["id"]) + " - " + markdown(row["title"]), "",
                      "Progress: not_started. Applicability: unknown. Outcome: unverified.", "",
                      "Source group: " + markdown(row["group"]) + ". Item: " + str(row["source_item"]) + ". Next implementation phase: " + markdown(row["phase"]) + ".", "",
                      "Module: " + markdown(row["module"]) + ". Legacy routing template: " + markdown(row["legacy_control_template"]) + ".", "",
                      "Linked capabilities: " + markdown(", ".join(row["capabilities"])) + ".", "",
                      "Scope, actor, environment and exact revision: not supplied.", "",
                      "Required evidence: " + markdown(" ".join(row["required_evidence"])), "",
                      "Acceptance: " + markdown(row["acceptance"]), "",
                      "Proposed legitimate case: " + markdown(row["legitimate_test"]), "",
                      "Proposed prohibited-effect case: " + markdown(row["prohibited_test"]), "",
                      "Existing capability limits: " + markdown(" ".join(c["limit"] for c in row["capability_limits"])), "",
                      "Remaining gap: " + markdown(row["remaining_gap"]), "",
                      "Evidence, reviewer, observation/expiry times and outcome rationale: not supplied.", ""])
    lines.extend(["## Limits", ""] + ["- " + markdown(item) for item in value["limitations"]])
    return "\n".join(lines) + "\n"
