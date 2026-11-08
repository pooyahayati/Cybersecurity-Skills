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


def redact(value, literals):
    if isinstance(value, str):
        for literal in sorted(set(literals), key=len, reverse=True):
            value = value.replace(literal, "[REDACTED]")
        for pattern, replacement in PATTERNS:
            value = pattern.sub(replacement, value)
        # Neutralize terminal controls and bidi overrides before rendering.
        return "".join(c if c in "\n\t" or ord(c) >= 32 and c not in "\x7f\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069" else " " for c in value)
    if isinstance(value, list):
        return [redact(item, literals) for item in value]
    if isinstance(value, dict):
        # Only a closed outward projection may reach this function. Protocol
        # keys are public constants; caller-controlled identifiers are values.
        # Rewriting keys corrupts the contract and can silently merge records.
        return {key: redact(item, literals) for key, item in value.items()}
    return value


def markdown(value):
    value = str(value).replace("\n", " ").replace("\r", " ")
    for char in "\\`*_{}[]()<>!|#":
        value = value.replace(char, "\\" + char)
    return value
