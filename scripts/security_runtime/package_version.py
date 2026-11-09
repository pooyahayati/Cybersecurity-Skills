"""Canonical release labels; a label grants no trust, freshness or authority."""

import re

from .common import require


def skill_header(text):
    """Parse this skill's canonical plain-scalar YAML subset, not arbitrary YAML.

    Duplicate keys, alternate YAML constructs and ambiguous scalar syntax are
    rejected instead of relying on a host parser's first/last-key behavior.
    """
    require(isinstance(text, str) and text.startswith("---\n") and "\n---\n" in text[4:],
            "missing skill frontmatter")
    lines = text.split("\n---\n", 1)[0].split("\n")[1:]
    root, metadata = {}, {}
    nested = False
    for line in lines:
        require(line and not any(ord(c) < 32 or 0x7f <= ord(c) <= 0x9f
                or c in "\u2028\u2029\ufffe\uffff" for c in line), "unsupported skill frontmatter syntax")
        if line == "metadata:":
            require("metadata" not in root, "duplicate skill frontmatter key")
            root["metadata"] = metadata
            nested = True
            continue
        if line.startswith("  "):
            require(nested and not line.startswith("   "), "unsupported skill metadata indentation")
            fields, allowed, value_line = metadata, {"author", "version"}, line[2:]
        else:
            nested = False
            fields, allowed, value_line = root, {"name", "description", "license"}, line
        key, separator, value = value_line.partition(": ")
        require(separator and key in allowed and key not in fields,
                "unknown or duplicate skill frontmatter key")
        require(value and value == value.strip() and ": " not in value and not value.endswith(":") and " #" not in value
                and value[0] not in "!&*{}[]|>'\"%@`#?-",
                "unsupported skill frontmatter scalar")
        fields[key] = value
    require(set(root) == {"name", "description", "license", "metadata"}
            and set(metadata) == {"author", "version"}, "incomplete skill frontmatter")
    return root


def channel(version):
    require(isinstance(version, str) and len(version) <= 64, "unsupported package version")
    number = r"(?:0|[1-9][0-9]*)"
    if re.fullmatch(r"0\." + number + r"\." + number + r"-dev", version):
        return "development"
    if re.fullmatch(r"[1-9][0-9]*\." + number + r"\." + number + r"-rc\.[1-9][0-9]*", version):
        return "release-candidate"
    if re.fullmatch(r"[1-9][0-9]*\." + number + r"\." + number, version):
        return "stable"
    require(False, "unsupported package version")
