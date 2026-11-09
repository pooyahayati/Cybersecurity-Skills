"""Exact, bounded npm lock inventory. No reachability or installed-state claim."""

import re
from urllib.parse import quote

from security_runtime.common import digest, fields, parse, require, sha256, text


def inventory(raw, path="package-lock.json"):
    lock = parse(raw, 4 * 1024**2)
    require(lock.get("lockfileVersion") in (2, 3) and isinstance(lock.get("packages"), dict), "unsupported npm lock format")
    require(len(lock["packages"]) <= 10000, "inventory exceeds limit")
    components, gaps = [], []
    for location, item in lock["packages"].items():
        if location == "": continue
        require(isinstance(item, dict), "invalid package entry")
        if not re.fullmatch(r"(?:node_modules/(?:@[a-z0-9._-]+/)?[a-z0-9._-]+/)*node_modules/(?:@[a-z0-9._-]+/)?[a-z0-9._-]+", location):
            gaps.append({"path": location, "reason": "unsupported workspace or package location"})
            continue
        name = location.rsplit("node_modules/", 1)[-1]
        version = item.get("version")
        if item.get("link") or not isinstance(version, str) or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?", version):
            gaps.append({"path": location, "reason": "unresolved, linked or unsupported exact version"})
            continue
        identity = {"lockfile": path, "location": location, "name": name, "version": version}
        components.append({**identity, "id": digest(identity), "purl": "pkg:npm/" + quote(name, safe="/") + "@" + quote(version, safe="")})
    require(components or gaps, "empty dependency inventory does not establish coverage")
    return {"profile": "npm-lock-v2-v3", "boundary": "lockfile-declared-not-installed", "input_sha256": sha256(raw),
            "components": components, "gaps": gaps, "completeness": "partial" if gaps else "selected-lockfile-entries"}


def normalize(report, selected, tool_version, metadata):
    require(report.get("SchemaVersion") == 2 and isinstance(report.get("Results"), list), "unsupported scanner output")
    expected = {(c["name"], c["version"]) for c in selected["components"]}
    observed, findings = set(), []
    require(len(report["Results"]) <= 16, "unexpected scan scope")
    for row in report["Results"]:
        require(row.get("Type") == "npm" and row.get("Target") == "package-lock.json", "scanner target differs from selected lockfile")
        packages = row.get("Packages")
        require(isinstance(packages, list) and len(packages) <= 10000, "scanner inventory unavailable")
        for package in packages:
            pair = (package.get("Name"), package.get("Version"))
            require(pair in expected, "scanner component differs from exact inventory")
            observed.add(pair)
        for finding in row.get("Vulnerabilities") or []:
            pair = (finding.get("PkgName"), finding.get("InstalledVersion"))
            require(pair in expected, "vulnerability lacks an exact selected component")
            for c in selected["components"]:
                if (c["name"], c["version"]) != pair: continue
                findings.append({"component_id": c["id"], "location": c["location"], "name": c["name"], "version": c["version"],
                    "advisory": text(finding.get("VulnerabilityID"), 256), "severity": text(finding.get("Severity"), 32),
                    "fixed_versions": str(finding.get("FixedVersion", ""))[:512]})
    require(observed == expected, "scanner did not account for every selected component")
    sbom = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
        "metadata": {"properties": [{"name": "cybersecurity-skills:boundary", "value": selected["boundary"]},
            {"name": "cybersecurity-skills:completeness", "value": selected["completeness"]}]},
        "components": [{"type": "library", "bom-ref": c["id"], "name": c["name"], "version": c["version"], "purl": c["purl"],
            "properties": [{"name": "cybersecurity-skills:lock-location", "value": c["location"]}]} for c in selected["components"]]}
    return {"schema_version": 1, "adapter": "c2-trivy-npm", "tool_version": text(tool_version, 128), "data_metadata": metadata,
            "inventory": selected, "sbom": sbom, "findings": findings,
            "outcome": "unverified" if selected["gaps"] else "failed" if findings else "satisfied",
            "claim": "Selected known-advisory lookup only; installed identity, reachability, malware and other ecosystems are unverified."}
