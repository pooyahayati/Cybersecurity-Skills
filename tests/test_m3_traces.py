import copy
import unittest

from m3_support import ReviewWorld
from runtime_support import source, acceptance
from security_runtime.common import digest


class TraceTests(unittest.TestCase):
    def setUp(self): self.w = ReviewWorld()
    def tearDown(self): self.w.close()

    def trace(self, domain="identity", components=None):
        op = self.w.execute(["inspect"], {}, components=components)
        run = self.w.state.get("operation", op)["run"]
        return {"id": "review-" + domain, "run": run, "adapter": "builtin-review", "domain": domain, "actor": "owner", "assets": ["records"], "locations": [{"path": "app.py", "line": 1}], "entrypoint": "Selected synthetic function", "untrusted_input": "Caller-controlled record identifier", "guard": "Inspect owner and tenant guard before the effect", "sink": "Protected synthetic record", "abuse_case": "Cross-owner access", "counterevidence": "No separate middleware in this selected fixture", "conclusion": "inconclusive", "next_step": "Compare owner and non-owner behavior", "dependency": None}

    def component(self, name, kind, contents, repository="fixture/project"):
        spec = source(name, kind, list(contents))
        spec["repository"] = repository
        self.w.publisher.contents[name] = contents
        self.w.runtime.enroll(spec)
        candidate = self.w.runtime.prepare(name)["candidate"]
        self.w.runtime.review(acceptance(candidate))
        self.w.runtime.activate(candidate)

    def test_each_nondependency_domain_is_attributed_and_scoped(self):
        for domain in ("architecture", "application", "identity", "data", "business", "secrets"):
            result = self.w.control.trace("demo", self.trace(domain))
            self.assertEqual(result["origin"], "operator_source_review")
        report = self.w.control.source_report("demo")
        self.assertEqual(report["unreviewed_domains"], ["dependencies"])
        self.assertEqual(report["security_verdict"], "not_established")

    def test_unknown_actor_path_line_and_out_of_scope_run_fail(self):
        base = self.trace()
        for updates in ({"actor": "intruder"}, {"locations": [{"path": "../app.py", "line": 1}]}, {"locations": [{"path": "app.py", "line": 9999}]}, {"assets": ["missing"]}):
            with self.subTest(updates=updates), self.assertRaises(ValueError): self.w.control.trace("demo", dict(base, **updates))
        op = self.w.execute(["inspect"], {}, inputs=["app.py"])
        base["run"] = self.w.state.get("operation", op)["run"]
        with self.assertRaises(ValueError): self.w.control.trace("demo", base)

    def test_refresh_rejected_without_mutation_and_authority_revoked(self):
        self.w.control.trace("demo", self.trace())
        before = digest(self.w.state.get("assessment", "demo"))
        spec = copy.deepcopy(self.w.spec)
        spec["model"]["actors"][1]["kind"] = "admin"
        with self.assertRaises(ValueError): self.w.control.refresh("demo", spec)
        self.assertEqual(digest(self.w.state.get("assessment", "demo")), before)
        self.w.runtime.revoke(authorization="check-1")
        self.assertFalse(self.w.control.source_report("demo")["traces"][0]["valid"])

    def test_optional_skill_needs_current_selected_resources(self):
        base = self.trace()
        base["adapter"] = "addy-hardening"
        with self.assertRaises(ValueError): self.w.control.trace("demo", base)
        self.component("addy-hardening", "skill", {"LICENSE": b"synthetic license", "skills/security-and-hardening/SKILL.md": b"synthetic reviewed instructions"}, "addyosmani/agent-skills")
        base = self.trace(components=["m3", "addy-hardening"])
        base["adapter"] = "addy-hardening"
        self.w.control.trace("demo", base)
        self.assertTrue(self.w.control.source_report("demo")["traces"][0]["valid"])
        self.w.runtime.revoke(component="addy-hardening")
        self.assertFalse(self.w.control.source_report("demo")["traces"][0]["valid"])

    def test_dependencies_bind_lock_and_fresh_data(self):
        self.component("advisories", "data", {"advisories.json": b'{"synthetic":true}'})
        (self.w.target / "uv.lock").write_bytes(b'[[package]]\nname = "fixture-package"\nversion = "1.2.3"\n')
        self.w.spec["id"] = "dependencies"
        self.w.spec["source"]["files"].append("uv.lock")
        self.w.create()
        base = self.trace("dependencies", ["m3", "advisories"])
        base["locations"].append({"path": "uv.lock", "line": 1})
        base["dependency"] = {"package": "fixture-package", "version": "1.2.3", "ecosystem": "pypi", "lock_path": "uv.lock", "advisory_component": "advisories", "advisory_reference": "Synthetic advisory reviewed against the exact locked package"}
        for wrong in ("^1.2", "7.8.9"):
            altered = copy.deepcopy(base)
            altered["dependency"]["version"] = wrong
            with self.assertRaises(ValueError): self.w.control.trace("dependencies", altered)
        self.w.control.trace("dependencies", base)
        self.assertTrue(self.w.control.source_report("dependencies")["traces"][0]["valid"])
        self.w.now[0] += 3601
        self.assertFalse(self.w.control.source_report("dependencies")["traces"][0]["valid"])
        candidate_id = self.w.state.get("active", "advisories")
        # Simulate a missing authenticated producer record, not a forged pass.
        with self.w.state.transaction() as tx:
            tx.connection.execute("DELETE FROM records WHERE kind = ? AND id = ?", ("candidate", candidate_id))
        self.assertFalse(self.w.control.source_report("dependencies")["traces"][0]["valid"])


if __name__ == "__main__": unittest.main()
