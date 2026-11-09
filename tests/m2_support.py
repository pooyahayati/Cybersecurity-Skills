"""Synthetic M2 fixtures shared by behavioral and CLI checks."""

import copy
import os
from pathlib import Path
import shutil
import sys
import tempfile
import time

from workflow_package import ROOT
from security_assessment.contracts import FEATURES
from security_assessment.service import Assessment
from security_runtime.store import Store


def model():
    return {"actors": [{"id": "visitor", "kind": "anonymous", "trust": "external"},
                       {"id": "owner", "kind": "user", "trust": "external"}],
            "assets": [{"id": "records", "kind": "database", "classification": "sensitive"}],
            "flows": [{"id": "read-record", "actor": "owner", "asset": "records", "direction": "read", "boundary": "client to service"}],
            "capabilities": {key: {"state": "unknown", "basis": "Not established by available context."} for key in FEATURES}}


class World:
    def __init__(self, source=True, urls=True):
        self.root = Path(tempfile.mkdtemp(prefix="cyber-m2-test-")).resolve()
        self.target = self.root / "target"
        self.target.mkdir()
        (self.target / "app.py").write_text("# A synthetic application; never execute during discovery.\n", encoding="utf-8")
        (self.target / "other.py").write_text("# Unrelated source fixture.\n", encoding="utf-8")
        self.state = Store(self.root / "private", ROOT, initialize=True)
        self.now = [time.time()]
        self.control = Assessment(self.state, ROOT, lambda: self.now[0])
        self.spec = {"schema_version": 1, "id": "demo",
                     "source": {"root": str(self.target), "files": ["app.py", "other.py"], "revision": "a" * 40} if source else None,
                     "deployments": [{"id": "staging", "environment": "staging", "url": "https://example.invalid/", "artifact": "b" * 64}] if urls else [],
                     "model": model(), "redact_values": []}

    def create(self):
        return self.control.create(copy.deepcopy(self.spec))

    def control_id(self, catalog_id="application", surface="source", actor=None, deployment=None):
        report = self.control.report(self.spec["id"])
        return next(c["id"] for c in report["controls"] if c["catalog_id"] == catalog_id and c["surface"] == surface
                    and c["actor"] == actor and (deployment is None or c["deployment"] == deployment))

    def observation(self, name="trace", control=None, surface="source", actor=None, files=None, method=None, context_refs=None):
        return {"schema_version": 1, "id": name, "control": control or self.control_id(surface=surface),
                "method": method or ("source_reasoning" if surface == "source" else "deployed_observation"),
                "actor": actor, "files": files if files is not None else ["app.py"] if surface == "source" else [],
                "context_refs": context_refs or [], "summary": "Inspected the selected synthetic boundary; result requires reviewer interpretation.",
                "observed_at": self.now[0], "expires_at": self.now[0] + 3600}

    def finding(self, name="finding", control=None, evidence=None, disposition="confirmed", counter=None):
        return {"schema_version": 1, "id": name, "root_cause": "owner-check", "control": control or self.control_id(),
                "title": "Missing ownership check", "category": "vulnerability", "location": "app.py:1",
                "actor": None, "prerequisites": "An authenticated non-owner can name a record.",
                "trust_boundary": "Caller identity to protected record", "impact": "Another customer's record could be disclosed.",
                "severity": "high", "severity_reason": "Sensitive cross-owner disclosure.", "confidence": "medium",
                "confidence_reason": "Source trace needs an authorized runtime counterpart.", "evidence": ["trace"] if evidence is None else evidence,
                "counterevidence": counter or [], "disposition": disposition,
                "fix": "Check record ownership before reading its sensitive contents.", "preserve": "The owner can still read their record.",
                "retest": "Exercise owner and non-owner requests and check actual returned fields.",
                "uncertainty": "The deployed version and role identity have not been independently observed."}

    def close(self):
        assert self.root.name.startswith("cyber-m2-test-") and self.root == self.root.resolve()
        for current, dirs, files in os.walk(self.root, followlinks=False):
            for name in dirs + files:
                path = Path(current) / name
                if not path.is_symlink(): path.chmod(0o700)
        shutil.rmtree(self.root)
