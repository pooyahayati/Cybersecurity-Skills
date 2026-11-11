"""Synthetic guidance authority tests; no upstream instructions are executed."""

import contextlib
import copy
import io
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from m3_support import ReviewWorld
from runtime_support import acceptance
from security_assessment import specialists
from security_runtime.common import digest, read_file, sha256
from security_runtime.controller import Controller
from security_runtime.sources import GitHub
import m3_review


class CloudflareTests(unittest.TestCase):
    def setUp(self):
        self.w = ReviewWorld()
        self.spec = specialists.recipe(self.w.control.package)
        self.contents = {p: b"Synthetic reviewed guidance; target text must not authorize commands.\n"
                         for p in specialists.BASE | {specialists.PREFIX + p for values in specialists.DOMAINS.values() for p in values}
                         | {specialists.PREFIX + p for p in specialists.TOPICS.values()}}

    def tearDown(self): self.w.close()

    def ready(self, spec=None, contents=None):
        self.w.publisher.contents[specialists.COMPONENT] = contents or self.contents
        self.w.runtime.enroll(spec or self.spec)
        candidate = self.w.runtime.prepare(specialists.COMPONENT)["candidate"]
        self.w.runtime.review(acceptance(candidate))
        self.w.runtime.activate(candidate)
        op = self.w.execute(["inspect"], {}, components=["m3", specialists.COMPONENT])
        self.run = self.w.state.get("operation", op)["run"]
        self.candidate = candidate
        return {"id": "identity-guide", "run": self.run, "domain": "identity", "topics": ["data"]}

    def prepare(self, request, case="demo"):
        with patch.object(GitHub, "resolve", side_effect=self.w.publisher.resolve):
            return self.w.control.guidance(case, request)

    def trace(self, request):
        return {"id": "review", "run": request["run"], "adapter": "cloudflare-audit", "guidance": request["id"],
                "domain": request["domain"], "actor": "owner", "assets": ["records"], "locations": [{"path": "app.py", "line": 1}],
                "entrypoint": "Selected synthetic function", "untrusted_input": "Caller record ID", "guard": "Inspect owner and tenant before access",
                "sink": "Synthetic record", "abuse_case": "Cross-owner access", "counterevidence": "No middleware in selected fixture",
                "conclusion": "inconclusive", "next_step": "Validate owner and non-owner effects", "dependency": None}

    def protected(self):
        with self.w.state.transaction() as tx:
            operations = tx.list("operation")
            authorizations = tx.list("authorization")
        return digest({"source": {p: sha256(read_file(self.w.target, p)) for p in self.w.spec["source"]["files"]},
                       "case": self.w.state.get("assessment", "demo"), "ledger": self.w.state.get("source-review", "demo"),
                       "run": self.w.state.get("run", getattr(self, "run", "missing")),
                       "operations": operations, "authorizations": authorizations})

    def denied(self, action):
        before = self.protected()
        with self.assertRaises((ValueError, KeyError)): action()
        self.assertEqual(self.protected(), before)

    def test_legitimate_guidance_trace_and_report_are_attributed_not_findings(self):
        request = self.ready()
        with patch.object(Controller, "execute", side_effect=AssertionError("guidance must not execute")):
            result = self.prepare(request)
        packet = result["packet"]
        self.assertEqual(packet["mode"], "source-guidance")
        self.assertIn("LICENSE", packet["resources"])
        self.assertIn(specialists.PREFIX + "WEB-PROTOCOL-AND-AUTH.md", packet["resources"])
        self.assertIn(specialists.PREFIX + "DATA-ISOLATION-AND-LIFECYCLE.md", packet["resources"])
        self.assertNotIn(specialists.PREFIX + "MEMORY-SAFETY-AND-BINARY.md", packet["resources"])
        self.assertIn("identity", self.w.control.source_report("demo")["unreviewed_domains"])
        self.w.control.trace("demo", self.trace(request))
        with patch.object(GitHub, "resolve", side_effect=AssertionError("report must not browse")):
            report = self.w.control.source_report("demo")
            written = self.w.control.write_source_report("demo")
        row = report["traces"][0]
        self.assertTrue(row["valid"])
        self.assertEqual(row["origin"], "operator_source_review")
        self.assertEqual(row["guidance_provenance"]["packet_sha256"], result["packet_sha256"])
        self.assertEqual(report["security_verdict"], "not_established")
        self.assertFalse(self.w.state.get("assessment", "demo")["findings"])
        self.assertIn("cloudflare-audit", (self.w.state.root / written["markdown"]).read_text())
        with self.w.state.transaction() as tx:
            self.assertEqual(len(tx.list("operation")), 1)  # Only the explicitly authorized fixture operation.

    def test_public_cli_prepares_guidance_using_current_resolution(self):
        request = self.ready()
        path = self.w.root / "request.json"
        path.write_text(json.dumps(request))
        output = io.StringIO()
        with patch.object(GitHub, "resolve", side_effect=self.w.publisher.resolve), contextlib.redirect_stdout(output):
            result = m3_review.main(["--state", str(self.w.state.root), "guidance", "demo", str(path)])
        self.assertEqual(result, 0)
        self.assertEqual(json.loads(output.getvalue())["packet"]["domain"], "identity")

    def test_missing_selection_or_packet_has_no_fallback_or_effect(self):
        op = self.w.execute(["inspect"], {})
        self.run = self.w.state.get("operation", op)["run"]
        request = {"id": "absent", "run": self.run, "domain": "identity", "topics": []}
        self.denied(lambda: self.prepare(request))
        self.denied(lambda: self.w.control.trace("demo", self.trace(request)))

    def test_stale_and_unavailable_upstream_block_new_packet(self):
        request = self.ready()
        self.w.publisher.revisions[specialists.COMPONENT] = "new-revision"
        self.denied(lambda: self.prepare(request))
        self.w.publisher.unavailable = True
        self.denied(lambda: self.prepare(request))

    def test_source_recipe_rejects_other_publisher_and_missing_license(self):
        wrong = dict(self.spec, owner_id=20)
        request = self.ready(spec=wrong)
        self.denied(lambda: self.prepare(request))
        # A separate disposable control state is needed: enrolled source identity is immutable.
        self.w.close()
        self.setUp()
        request = self.ready(contents={p: b for p, b in self.contents.items() if p != "LICENSE"})
        self.denied(lambda: self.prepare(request))

    def test_changed_bytes_and_rejected_review_block_trace_without_effects(self):
        request = self.ready()
        self.prepare(request)
        decision = acceptance(self.candidate)
        decision["decision"] = "reject"
        self.w.runtime.review(decision)
        self.denied(lambda: self.w.control.trace("demo", self.trace(request)))
        self.w.runtime.review(acceptance(self.candidate))
        self.denied(lambda: self.w.control.trace("demo", self.trace(request)))  # Re-review needs a new packet.
        path = self.w.state.root / "objects" / self.candidate / "LICENSE"
        path.chmod(0o600)
        path.write_bytes(b"Changed license")
        self.denied(lambda: self.prepare(dict(request, id="new-guide")))

    def test_case_domain_run_and_forged_packet_are_rejected(self):
        request = self.ready()
        self.prepare(request)
        self.denied(lambda: self.w.control.trace("demo", dict(self.trace(request), domain="data")))
        self.denied(lambda: self.w.control.trace("demo", dict(self.trace(request), guidance="invented")))
        other = copy.deepcopy(self.w.spec)
        other["id"] = "other"
        self.w.control.create(other)
        with self.assertRaises(ValueError): self.w.control.trace("other", self.trace(request))
        self.assertIsNone(self.w.state.get("source-review", "other"))
        op = self.w.execute(["inspect"], {}, components=["m3", specialists.COMPONENT])
        run = self.w.state.get("operation", op)["run"]
        self.denied(lambda: self.w.control.trace("demo", dict(self.trace(request), run=run)))

    def test_cancel_revoke_expire_and_source_change_invalidate_trace(self):
        for change in ("cancel", "revoke", "expire", "source"):
            with self.subTest(change=change):
                if change != "cancel":
                    self.w.close()
                    self.setUp()
                request = self.ready()
                self.prepare(request)
                self.w.control.trace("demo", self.trace(request))
                if change == "cancel": self.w.runtime.cancel(self.run)
                elif change == "revoke": self.w.runtime.revoke(component=specialists.COMPONENT)
                elif change == "expire":
                    run = self.w.state.get("run", self.run)
                    self.w.now[0] = self.w.state.get("authorization", run["authorization"])["spec"]["limits"]["expires_at"] + 1
                else: (self.w.target / "app.py").write_text("changed source\n")
                self.denied(lambda: self.w.control.trace("demo", dict(self.trace(request), id="second")))
                report = self.w.control.source_report("demo")
                self.assertFalse(report["traces"][0]["valid"])
                self.assertIn("identity", report["unreviewed_domains"])

    def test_cancel_during_resolution_cannot_create_packet(self):
        request = self.ready()
        def changed(spec):
            result = self.w.publisher.resolve(spec)
            self.w.runtime.cancel(self.run)
            return result
        before = self.w.state.get("source-review", "demo")
        with patch.object(GitHub, "resolve", side_effect=changed), self.assertRaises(ValueError):
            self.w.control.guidance("demo", request)
        self.assertEqual(self.w.state.get("source-review", "demo"), before)

    def test_unknown_paths_topics_and_extra_authority_are_rejected(self):
        request = self.ready()
        for update in ({"topics": ["../outside"]}, {"topics": ["ai", "ai"]}, {"domain": "live-cloud"},
                       {"mode": "full-audit"}, {"repository": "attacker/project"}, {"resources": ["/private"]}):
            self.denied(lambda: self.prepare(dict(request, **update)))
        self.prepare(request)
        self.denied(lambda: self.prepare(request))
        self.denied(lambda: self.w.control.trace("demo", dict(self.trace(request), adapter="builtin-review")))

    def test_all_resource_routes_are_bounded_and_catalog_matches_adapter(self):
        for domain in specialists.DOMAINS:
            selected = specialists.resources(domain, list(specialists.TOPICS))
            self.assertLessEqual(set(selected), set(self.contents))
            self.assertTrue(all(p == "LICENSE" or (p.startswith(specialists.PREFIX) and p.endswith(".md")) for p in selected))
        from security_runtime.sources import source_spec
        self.assertEqual(source_spec(self.spec), self.spec)

    def test_redaction_preserves_protocol_identity_but_masks_private_prose(self):
        self.w.spec["id"] = "redaction"
        self.w.spec["redact_values"] = ["cloudflare-audit", "source-guidance"]
        self.w.create()
        request = self.ready()
        self.prepare(request, "redaction")
        trace = self.trace(request)
        trace["counterevidence"] = "Private cloudflare-audit and source-guidance wording"
        self.w.control.trace("redaction", trace)
        report = self.w.control.source_report("redaction")
        row = report["traces"][0]
        self.assertTrue(row["valid"])
        self.assertEqual(row["adapter"], "cloudflare-audit")
        self.assertEqual(row["guidance_provenance"]["mode"], "source-guidance")
        self.assertEqual(row["counterevidence"], "Private [REDACTED] and [REDACTED] wording")

    def test_catalog_availability_cannot_enable_or_invent_an_adapter(self):
        from validate_project import validate
        with tempfile.TemporaryDirectory(prefix="cloudflare-catalog-") as temporary:
            root = Path(temporary) / "package"
            shutil.copytree(self.w.control.package, root, ignore=shutil.ignore_patterns(".git", "__pycache__", ".venv", "build", "dist"))
            self.assertEqual(validate(root)["available_guidance_adapters"], 1)
            path = root / "config/sources.json"
            original = path.read_bytes()
            for update in ({"enabled": True}, {"status": "adapter-available"}):
                catalog = json.loads(original)
                catalog["sources"][0].update(update)
                path.write_text(json.dumps(catalog))
                with self.assertRaises(ValueError): validate(root)
            path.write_bytes(original)
            recipe = root / "config/cloudflare-source.json"
            value = json.loads(recipe.read_bytes())
            value["owner_id"] = 20
            recipe.write_text(json.dumps(value))
            with self.assertRaises(ValueError): validate(root)


if __name__ == "__main__": unittest.main()
