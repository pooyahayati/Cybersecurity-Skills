"""Conservative outward projection; never serialize raw private records."""

import re


PATTERNS = [
    (re.compile(r"-----BEGIN [^-\r\n]*PRIVATE KEY-----.*?-----END [^-\r\n]*PRIVATE KEY-----", re.S), "[PRIVATE KEY REDACTED]"),
    (re.compile(r"(?i)\b(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]+"), "[AUTHORIZATION REDACTED]"),
    (re.compile(r"(?i)[\"']?\b(?:password|passwd|secret|token|client[_-]?secret|access[_-]?token|refresh[_-]?token|private[_-]?key|api[_-]?key|authorization|cookie|session[_-]?id)\b[\"']?\s*[:=]\s*(?:\"(?:\\.|[^\"\\\r\n])*\"|'(?:\\.|[^'\\\r\n])*'|[^\s,;]+)"), "[SECRET REDACTED]"),
    (re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9_]{12,}|github_pat_[A-Za-z0-9_]+|AKIA[A-Z0-9]{16}|sk-[A-Za-z0-9_-]{12,}|eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)\b"), "[TOKEN REDACTED]"),
    (re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b"), "[EMAIL REDACTED]"),
    (re.compile(r"(?<!\w)(?:\+?\d[\d .()-]{8,}\d)(?!\w)"), "[NUMBER REDACTED]"),
    (re.compile(r"(?i)https?://[^\s<>\"']+"), "[URL WITHHELD]"),
    (re.compile(r"(?i)\b[A-Z]:[\\/][^\r\n\t]+"), "[LOCAL PATH WITHHELD]"),
]


# These are validated/public protocol tokens, not private display text. Masking
# them can turn a rejected finding into an actionable one or falsify an outcome.
# The same words in a summary, identifier or credential are still redacted.
PUBLIC_TOKENS = {
    "result": {"assessment_record"}, "security_verdict": {"not_established"},
    "disposition": {"confirmed", "needs_validation", "rejected"},
    "recorded_disposition": {"confirmed", "needs_validation", "rejected"},
    "remediation_state": {"not_verified"},
    "severity": {"critical", "high", "medium", "low", "informational"},
    "confidence": {"high", "medium", "low"},
    "category": {"vulnerability", "hardening", "operational"},
    "state": {"not_started", "in_progress", "reviewed", "blocked", "not_applicable", "present", "absent", "unknown"},
    "outcome": {"unverified", "satisfied", "failed", "inconclusive", "not_applicable"},
    "method": {"design_review", "source_reasoning", "configuration_inspection", "deployed_observation", "controlled_reproduction"},
    "origin": {"operator_observation", "m1_controller", "operator_source_review"},
    "domain": {"architecture", "application", "identity", "data", "business", "dependencies", "secrets"},
    "conclusion": {"supported_issue", "no_issue_observed", "inconclusive"},
    "scope": {"declared_serialized_model"}, "variant": {"original", "candidate"},
    "adapter": {"builtin-source", "builtin-review", "addy-hardening"},
    "status": {"examined", "limited_lexical", "inconclusive", "unsupported"},
    "language": {"python", "javascript", "typescript", "php"},
    "ecosystem": {"npm", "pypi", "composer"},
    "surface": {"source", "deployment", "context"}, "mode": {"source_only", "url_only", "combined"},
    "environment": {"local", "staging", "production", "unknown", "selected_source"},
    "relevance": {"relevant", "needs_confirmation", "exclusion_needs_evidence", "unknown"},
    "execution": {"not_activated"}, "declared_capability": {"present", "absent", "unknown"},
    "kind": {"anonymous", "user", "administrator", "service", "unknown", "database", "file", "queue", "credential", "dataset", "package", "language", "platform-marker"},
    "trust": {"external", "internal", "unknown"}, "direction": {"read", "write", "exchange", "unknown"},
    "classification": {"public", "internal", "personal", "sensitive", "secret", "unknown"},
    "version_basis": {"lockfile", "declared-constraint", "source-assignment", "selected-file-extensions"},
    "model_provenance": {"operator_declared"}, "revision_provenance": {"operator_declared; not deployed identity"},
}


def redact(value, literals, field=None):
    if isinstance(value, str):
        if value in PUBLIC_TOKENS.get(field, set()):
            return value
        for literal in sorted(set(literals), key=len, reverse=True):
            value = value.replace(literal, "[REDACTED]")
        for pattern, replacement in PATTERNS:
            value = pattern.sub(replacement, value)
        # Neutralize terminal controls and bidi overrides before rendering.
        return "".join(c if c in "\n\t" or ord(c) >= 32 and c not in "\x7f\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069" else " " for c in value)
    if isinstance(value, list):
        return [redact(item, literals, "disposition" if field == "dispositions" else None) for item in value]
    if isinstance(value, dict):
        # Only a closed outward projection may reach this function. Protocol
        # keys are public constants; caller-controlled identifiers are values.
        # Rewriting keys corrupts the contract and can silently merge records.
        return {key: redact(item, literals, key) for key, item in value.items()}
    return value


def markdown(value):
    value = str(value).replace("\n", " ").replace("\r", " ")
    for char in "\\`*_{}[]()<>!|#":
        value = value.replace(char, "\\" + char)
    return value
