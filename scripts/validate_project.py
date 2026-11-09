#!/usr/bin/env python3
"""Validate this skill package, without executing or fetching resources.

This intentionally narrow validator is not a security scanner, freshness verifier,
general schema validator, or a defense against concurrent filesystem replacement.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import posixpath
import re
import sys
from pathlib import Path, PurePosixPath
from urllib.parse import unquote, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent))
from security_runtime.common import Blocked
from security_runtime.package_version import channel, skill_header


MAX_FILE_BYTES = 1_048_576
MAX_TOTAL_BYTES = 8_388_608
MAX_FILES = 512
ID = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*")
REPOSITORY = re.compile(r"https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
LINK = re.compile(r"\[[^\]\r\n]*\]\(([^\s)]+)\)")
REQUIRED_FILES = (
    "README.md", "AGENTS.md", "ROADMAP.md", "STATUS.md", "CHANGELOG.md",
    "CONTRIBUTING.md", "SECURITY.md", "THIRD_PARTY_NOTICES.md", "LICENSE",
    "agents/openai.yaml", "docs/ARCHITECTURE.md", "docs/EVALUATION.md",
    "docs/SOURCE_REVIEW.md", "references/freshness.md",
    "references/module-contract.md", "references/scope-and-safety.md",
    "references/evidence.md", "templates/assessment-report.md",
    "templates/assessment-scope.md", "docs/M1-CONTROL-PLANE.md", "docs/M1-OPERATIONS.md",
    "docs/M2-DISCOVERY-EVIDENCE.md", "docs/M2-OPERATIONS.md", "config/assessment-controls.json",
    "docs/M3-SOURCE-REMEDIATION.md", "docs/M3-OPERATIONS.md", "scripts/m3_review.py", "scripts/m3_worker.py",
    "docs/M5-RESILIENCE.md", "docs/M5-OPERATIONS.md", "scripts/m5_review.py", "scripts/m5_worker.py",
    "docs/M4-RUNTIME-SECURITY.md", "docs/M4-OPERATIONS.md", "scripts/m4_review.py", "scripts/m4_worker.py",
    "docs/M6-QUALIFICATION.md", "templates/qualification-record.md", "scripts/m6_package.py",
    "docs/RELEASE-READINESS.md", "scripts/security_runtime/package_version.py",
    "scripts/security_runtime/package_diagnostics.py",
    "config/security-checklist.json", "scripts/security_checklist.py",
    "scripts/security_assessment/checklist.py",
    "docs/CHECKLIST-COVERAGE.md", "docs/CHECKLIST-ROADMAP.md",
)


class ValidationError(ValueError):
    """A bounded, non-sensitive validation failure."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValidationError(message)


def shape(value: object, keys: set[str], label: str) -> None:
    require(isinstance(value, dict) and set(value) == keys,
            f"{label}: missing or unknown fields")


def nonempty(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def text_list(value: object) -> bool:
    return isinstance(value, list) and bool(value) and all(nonempty(x) for x in value)


def unique_object(pairs: list[tuple[str, object]]) -> dict:
    result: dict = {}
    for key, value in pairs:
        require(key not in result, "JSON: duplicate object key")
        result[key] = value
    return result


def reject_constant(_value: str) -> None:
    raise ValidationError("JSON: non-finite number")


class Reader:
    def __init__(self, root: Path):
        self.root = root.resolve(strict=True)
        require(self.root.is_dir(), "project root must be a directory")
        self.contents: dict[str, bytes] = {}
        self.total = 0

    def path(self, relative: str) -> Path:
        require(isinstance(relative, str) and bool(relative), "invalid file reference")
        parts = PurePosixPath(relative)
        require(not parts.is_absolute() and ".." not in parts.parts
                and not any(c in relative for c in ("\\", ":", "\x00")),
                "file reference must be a contained relative path")
        try:
            resolved = (self.root / relative).resolve(strict=True)
        except (OSError, RuntimeError, ValueError) as exc:
            raise ValidationError("referenced file is missing or unreadable") from exc
        require(resolved.is_relative_to(self.root), "file reference escapes project root")
        require(resolved.is_file(), "file reference must name a regular file")
        return resolved

    def read(self, relative: str) -> str:
        require(isinstance(relative, str) and bool(relative), "invalid file reference")
        if relative not in self.contents:
            require(len(self.contents) < MAX_FILES, "file count limit exceeded")
            path = self.path(relative)
            with path.open("rb") as handle:
                data = handle.read(MAX_FILE_BYTES + 1)
            require(len(data) <= MAX_FILE_BYTES, "file size limit exceeded")
            require(self.total + len(data) <= MAX_TOTAL_BYTES, "total input limit exceeded")
            self.contents[relative] = data
            self.total += len(data)
        return self.contents[relative].decode("utf-8")

    def json(self, relative: str) -> object:
        return json.loads(self.read(relative), object_pairs_hook=unique_object,
                          parse_constant=reject_constant)

    def fingerprint(self) -> str:
        digest = hashlib.sha256()
        for name, content in sorted(self.contents.items()):
            digest.update(name.encode("utf-8") + b"\x00")
            digest.update(hashlib.sha256(content).digest())
        return digest.hexdigest()


def validate(root: Path) -> dict:
    reader = Reader(root)
    project = reader.json("config/project.json")
    shape(project, {"schema_version", "name", "version", "maturity", "operational",
                    "entrypoint", "modules_catalog", "sources_catalog"}, "project")
    require(type(project["schema_version"]) is int and project["schema_version"] == 1,
            "unsupported project schema")
    require(project["name"] == "cybersecurity-skills", "unexpected skill identity")
    try:
        channel(project["version"])
    except Blocked as exc:
        raise ValidationError("unsupported package version") from exc
    require(project["maturity"] == "bounded-qualification" and project["operational"] is False,
            "bounded qualification cannot declare general operational assessment readiness")
    require(project["entrypoint"] == "SKILL.md"
            and project["modules_catalog"] == "config/modules.json"
            and project["sources_catalog"] == "config/sources.json",
            "unexpected package entrypoints")

    skill = reader.read(project["entrypoint"])
    try:
        header = skill_header(skill)
    except Blocked as exc:
        raise ValidationError(str(exc)) from exc
    require(header["name"] == "cybersecurity-skills" and header["description"],
            "skill name or description is missing")
    require(header["metadata"]["version"] == project["version"], "skill and project versions differ")

    catalog = reader.json(project["modules_catalog"])
    shape(catalog, {"schema_version", "modules"}, "module catalog")
    require(type(catalog["schema_version"]) is int and catalog["schema_version"] == 1,
            "unsupported module schema")
    require(isinstance(catalog["modules"], list) and bool(catalog["modules"]),
            "module catalog must be nonempty")
    identifiers: set[str] = set()
    for module in catalog["modules"]:
        shape(module, {"id", "title", "entrypoint", "state", "activation", "inputs", "outputs"},
              "module")
        identifier = module["id"]
        require(isinstance(identifier, str) and ID.fullmatch(identifier) is not None
                and identifier not in identifiers, "invalid or duplicate module ID")
        identifiers.add(identifier)
        require(module["state"] == "guidance", "foundation modules must remain guidance")
        require(nonempty(module["title"]) and nonempty(module["activation"])
                and text_list(module["inputs"]) and text_list(module["outputs"]),
                "module contract is incomplete")
        # Resolve before enforcing the layout so traversal and symlink escapes fail.
        reader.read(module["entrypoint"])
        require(module["entrypoint"] == f"references/modules/{identifier}.md",
                "module entrypoint does not match its ID")

    sources = reader.json(project["sources_catalog"])
    shape(sources, {"schema_version", "policy", "sources"}, "source catalog")
    require(type(sources["schema_version"]) is int and sources["schema_version"] == 1,
            "unsupported source schema")
    require(sources["policy"] == {"strategy": "latest-stable-or-default-branch",
                                  "silent_stale_fallback": False,
                                  "activation": "reviewed-adapter-required"}
            and sources["policy"].get("silent_stale_fallback") is False,
            "freshness policy was weakened or changed")
    require(isinstance(sources["sources"], list), "sources must be an array")
    source_ids: set[str] = set()
    for source in sources["sources"]:
        shape(source, {"id", "kind", "repository", "status", "enabled", "purpose"}, "source")
        require(isinstance(source["id"], str) and ID.fullmatch(source["id"]) is not None
                and source["id"] not in source_ids, "invalid or duplicate source ID")
        source_ids.add(source["id"])
        require(source["kind"] in ("skill", "tool"), "unsupported source kind")
        require(source["status"] in ("candidate", "deprecated") and source["enabled"] is False,
                "foundation sources cannot be activated")
        require(isinstance(source["repository"], str)
                and REPOSITORY.fullmatch(source["repository"]) is not None,
                "source must use a canonical GitHub HTTPS repository URL")
        require(nonempty(source["purpose"]), "source purpose is missing")

    for name in REQUIRED_FILES:
        reader.read(name)
    # Follow simple inline file links used by this package; no network requests.
    checked: set[str] = set()
    while True:
        pending = [name for name in reader.contents if name.endswith(".md") and name not in checked]
        if not pending:
            break
        for name in pending:
            checked.add(name)
            for link in LINK.findall(reader.read(name)):
                parsed = urlsplit(link)
                if parsed.scheme in ("http", "https"):
                    continue
                require(not parsed.scheme and not parsed.netloc,
                        "unsupported documentation link scheme")
                if parsed.path:
                    relative = posixpath.normpath(str(PurePosixPath(name).parent / unquote(parsed.path)))
                    reader.read(relative)

    from security_runtime.controller import HEAD_RESOURCES
    from security_runtime.sources import source_spec
    head = source_spec(reader.json("config/head-source.json"))
    require(head["id"] == "head" and head["kind"] == "head"
            and sorted(head["include"]) == sorted(HEAD_RESOURCES), "invalid head resource contract")
    from security_assessment.service import load_catalog
    try:
        controls = load_catalog(reader.root)
    except (ValueError, KeyError, TypeError) as exc:
        raise ValidationError("invalid assessment control catalog") from exc

    from security_assessment.checklist import validate_catalog as validate_checklist
    try:
        checklist = validate_checklist(reader.json("config/security-checklist.json"), identifiers,
                                       {item["id"] for item in controls["controls"]})
        for capability in checklist["capabilities"]:
            for path in capability["paths"]:
                reader.read(path)
    except (ValueError, KeyError, TypeError) as exc:
        raise ValidationError("invalid security checklist catalog") from exc

    return {"result": "structure_valid", "scope": "repository_structure_only",
            "operational_assessment": False, "freshness_verified": False,
            "version": project["version"], "modules": len(identifiers),
            "candidate_sources": sum(item["status"] == "candidate" for item in sources["sources"]),
            "deprecated_sources": sum(item["status"] == "deprecated" for item in sources["sources"]),
            "files_checked": len(reader.contents),
            "assessment_control_templates": len(controls["controls"]),
            "security_checklist_items": len(checklist["controls"]),
            "inputs_sha256": reader.fingerprint()}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    try:
        result = validate(args.root)
    except (ValidationError, OSError, UnicodeError, json.JSONDecodeError,
            RecursionError, ValueError) as exc:
        # Do not echo arbitrary JSON values or file content into public CI logs.
        message = str(exc) if isinstance(exc, ValidationError) else "unreadable or malformed input"
        print(json.dumps({"result": "invalid_structure", "error": message,
                          "operational_assessment": False}))
        return 1
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
