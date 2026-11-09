"""Canonical release labels; a label grants no trust, freshness or authority."""

import re

from .common import require


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
