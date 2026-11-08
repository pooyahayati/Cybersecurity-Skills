"""Versioned M2 input contracts. Caller assertions never set provenance."""

from pathlib import Path
import re
from urllib.parse import urlsplit, urlunsplit

from security_runtime.common import fields, identifier, integer, number, relpath, require, text


FEATURES = {"authentication", "sensitive_data", "transactions", "ai", "infrastructure", "delivery", "resilience"}
METHODS = {"design_review", "source_reasoning", "configuration_inspection", "deployed_observation", "controlled_reproduction"}
SEVERITIES = {"critical", "high", "medium", "low", "informational"}
PROGRESS = {"not_started", "in_progress", "reviewed", "blocked", "not_applicable"}
OUTCOMES = {"unverified", "satisfied", "failed", "inconclusive", "not_applicable"}


def choice(value, options):
    require(isinstance(value, str) and value in options, "unsupported enum value")
    return value


def items(value, maximum, minimum=0):
    require(isinstance(value, list) and minimum <= len(value) <= maximum, "array outside allowed bounds")
    return value


def ids(value, maximum=64, minimum=0):
    for item in items(value, maximum, minimum):
        identifier(item)
    require(len(set(value)) == len(value), "duplicate identifier")
    return value


def version(value):
    require(type(value) is int and value == 1, "unsupported assessment schema version")


def declared_revision(value):
    if value is not None:
        require(isinstance(value, str) and re.fullmatch(r"(?:[0-9a-f]{40}|(?:sha256:)?[0-9a-f]{64})", value),
                "revision must be an immutable digest or null")


def passive_url(value):
    text(value, 2048)
    require(not any(c.isspace() or ord(c) < 32 for c in value) and "\\" not in value,
            "invalid scoped URL")
    try:
        parsed = urlsplit(value)
        host, port = parsed.hostname, parsed.port
        require(parsed.scheme in {"https", "http"} and host and parsed.username is None
                and parsed.password is None and not parsed.query and not parsed.fragment,
                "URL must have a host and no credentials, query or fragment")
        host = host.encode("idna").decode("ascii").lower()
        require(bool(re.fullmatch(r"[a-z0-9.:-]+", host)) and (port is None or 1 <= port <= 65535),
                "invalid scoped host or port")
        netloc = ("[" + host + "]" if ":" in host else host) + (":" + str(port) if port else "")
        return urlunsplit((parsed.scheme, netloc, parsed.path or "/", "", ""))
    except (ValueError, UnicodeError) as exc:
        raise ValueError("invalid scoped URL") from exc


def source(value):
    if value is None:
        return
    fields(value, {"root", "files", "revision"})
    text(value["root"], 4096)
    require(Path(value["root"]).is_absolute(), "source root must be absolute")
    for path in items(value["files"], 256, 1):
        relpath(path)
    require(len({p.casefold() for p in value["files"]}) == len(value["files"]), "duplicate source path")
    declared_revision(value["revision"])


def model(value):
    fields(value, {"actors", "assets", "flows", "capabilities"})
    actors, assets, flows = {}, {}, set()
    for row in items(value["actors"], 64):
        fields(row, {"id", "kind", "trust"})
        identifier(row["id"])
        require(row["id"] not in actors, "duplicate actor")
        choice(row["kind"], {"anonymous", "user", "administrator", "service", "unknown"})
        choice(row["trust"], {"external", "internal", "unknown"})
        actors[row["id"]] = row
    for row in items(value["assets"], 64):
        fields(row, {"id", "kind", "classification"}, {"revision"})
        identifier(row["id"])
        require(row["id"] not in assets, "duplicate asset")
        choice(row["kind"], {"database", "file", "service", "queue", "credential", "dataset", "unknown"})
        choice(row["classification"], {"public", "internal", "personal", "sensitive", "secret", "unknown"})
        declared_revision(row.get("revision"))
        assets[row["id"]] = row
    for row in items(value["flows"], 128):
        fields(row, {"id", "actor", "asset", "direction", "boundary"})
        identifier(row["id"])
        require(row["id"] not in flows and row["actor"] in actors and row["asset"] in assets,
                "invalid or duplicate flow reference")
        choice(row["direction"], {"read", "write", "exchange", "unknown"})
        text(row["boundary"], 512)
        flows.add(row["id"])
    fields(value["capabilities"], FEATURES)
    for row in value["capabilities"].values():
        fields(row, {"state", "basis"})
        choice(row["state"], {"present", "absent", "unknown"})
        text(row["basis"], 1024)


def deployments(value):
    found = set()
    for row in items(value, 16):
        fields(row, {"id", "environment", "url", "artifact"})
        identifier(row["id"])
        require(row["id"] not in found, "duplicate deployment")
        choice(row["environment"], {"local", "staging", "production", "unknown"})
        row["url"] = passive_url(row["url"])
        declared_revision(row["artifact"])
        found.add(row["id"])


def scope(value):
    fields(value, {"schema_version", "id", "source", "deployments", "model", "redact_values"})
    version(value["schema_version"])
    identifier(value["id"])
    source(value["source"])
    deployments(value["deployments"])
    require(value["source"] is not None or value["deployments"], "source or URL scope is required")
    model(value["model"])
    for item in items(value["redact_values"], 128):
        text(item, 4096)
        require(len(item) >= 3, "sensitive literal must contain at least three characters")


def observation(value, now, controller=False):
    required = {"schema_version", "id", "control", "method", "actor", "files", "context_refs", "summary", "observed_at", "expires_at"}
    fields(value, required | ({"operation"} if controller else set()))
    version(value["schema_version"])
    identifier(value["id"])
    text(value["control"], 128)
    choice(value["method"], METHODS)
    require((value["method"] == "controlled_reproduction") is controller,
            "controlled evidence requires an authenticated M1 operation")
    if value["actor"] is not None:
        identifier(value["actor"])
    for path in items(value["files"], 256):
        relpath(path)
    require(len(set(value["files"])) == len(value["files"]), "duplicate evidence path")
    for ref in items(value["context_refs"], 128):
        require(isinstance(ref, str) and re.fullmatch(r"(?:asset|flow):[a-z][a-z0-9-]{0,63}", ref), "invalid context reference")
    require(len(set(value["context_refs"])) == len(value["context_refs"]), "duplicate context reference")
    text(value["summary"], 4096)
    number(value["observed_at"], 0, now + 60)
    number(value["expires_at"], value["observed_at"], value["observed_at"] + 31 * 86400)
    require(value["expires_at"] > now, "new evidence is already expired")
    if controller:
        require(isinstance(value["operation"], str) and re.fullmatch(r"op-[0-9a-f]{32}", value["operation"]),
                "invalid controller operation reference")


def finding(value):
    fields(value, {"schema_version", "id", "root_cause", "control", "title", "category", "location",
                   "actor", "prerequisites", "trust_boundary", "impact", "severity", "severity_reason",
                   "confidence", "confidence_reason", "evidence", "counterevidence", "disposition",
                   "fix", "preserve", "retest", "uncertainty"})
    version(value["schema_version"])
    for key in ("id", "root_cause"):
        identifier(value[key])
    text(value["control"], 128)
    if value["actor"] is not None:
        identifier(value["actor"])
    choice(value["category"], {"vulnerability", "hardening", "operational"})
    choice(value["severity"], SEVERITIES)
    choice(value["confidence"], {"high", "medium", "low"})
    choice(value["disposition"], {"confirmed", "needs_validation", "rejected"})
    for key in ("title", "location", "prerequisites", "trust_boundary", "impact", "severity_reason",
                "confidence_reason", "fix", "preserve", "retest", "uncertainty"):
        text(value[key], 4096)
    ids(value["evidence"])
    ids(value["counterevidence"])
    require(not set(value["evidence"]) & set(value["counterevidence"]), "evidence cannot refute itself")
