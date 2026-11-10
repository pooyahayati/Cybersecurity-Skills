import copy
import json
import os
import subprocess
import sys
import threading
import time
import unittest
from unittest.mock import patch

from m4_support import ROOT, RuntimeWorld, Server, compare_roles, role_plan, roles
from security_runtime.common import Blocked, canonical, sha256
from security_runtime.private import private_directory
from security_runtime.web_scope import address, url
from security_runtime.web_worker import collect


class WebTests(unittest.TestCase):
    def setUp(self):
        self.server = Server()
        self.world = RuntimeWorld(self.server)

    def tearDown(self):
        self.server.close()
        self.world.close()

    def test_exact_allowed_route_no_ambient_credentials_and_single_intent(self):
        self.world.authorize()
        with patch.dict(os.environ, {"HTTP_PROXY": "http://127.0.0.1:9", "AUTHORIZATION": "Bearer not-authorized"}):
            result = self.world.execute()
        self.assertTrue(result["expectation_matched"])
        self.assertEqual(self.server.calls, [{"path": "/", "authorization": None, "cookie": None}])
        with self.assertRaises(Blocked): self.world.execute()
        self.assertEqual(len(self.server.calls), 1)

    def test_cli_credentials_outside_private_state_never_send_or_consume_intent(self):
        self.world.authorize(self.world.authorization([self.world.route(actor="owner", credential="account")]))
        credentials = {"account": {"header": "Authorization", "value": "Bearer fixture-private-location"}}
        outside = private_directory(self.world.target / "credentials", create=True) / "account.json"
        outside.write_bytes(canonical(credentials))
        def request(path):
            return subprocess.run([sys.executable, "-I", "-B", str(ROOT / "scripts/m4_review.py"), "--state", str(self.world.state.root),
                "request", "demo", "web-audit", "read", "--credentials", str(path)], capture_output=True, timeout=15)
        denied = request(outside)
        self.assertEqual(denied.returncode, 1)
        self.assertEqual(self.server.calls, [])
        self.assertEqual(self.world.state.get("web-authority", "web-audit")["intents"], {})
        permitted = self.world.state.root / "account.json"
        permitted.write_bytes(canonical(credentials))
        result = request(permitted)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertTrue(json.loads(result.stdout)["expectation_matched"])
        self.assertEqual(len(self.server.calls), 1)
        self.assertEqual(self.server.calls[0]["authorization"], credentials["account"]["value"])
        self.assertNotIn(b"fixture-private-location", denied.stdout + result.stdout)

    def test_scoped_redirect_works_cross_target_never_contacted(self):
        other = Server()
        try:
            self.server.handler = lambda path, token: (302, {"Location": "/final"}, b"") if path == "/start" else (200, {}, b"safe")
            # This case tests redirect scope; hard-deadline regressions are separate.
            self.world.authorize(self.world.authorization([self.world.route(path="start", redirects=["final"])], timeout_seconds=5))
            self.assertTrue(self.world.execute()["expectation_matched"])
            self.assertEqual([c["path"] for c in self.server.calls], ["/start", "/final"])
            self.assertEqual(self.world.state.get("web-authority", "web-audit")["seconds_used"], 10)
            self.server.handler = lambda path, token: (302, {"Location": other.url}, b"")
            self.world.authorize(self.world.authorization(name="escape", timeout_seconds=5))
            with self.assertRaises(Blocked): self.world.execute(authorization="escape")
            self.assertEqual(other.calls, [])
            self.assertEqual(self.world.state.get("web-authority", "escape")["requests_used"], 1)
            self.assertEqual(self.world.state.get("web-authority", "escape")["seconds_used"], 5)
        finally: other.close()

    def test_unapproved_path_never_contacted_and_budget_cannot_reset(self):
        self.server.handler = lambda path, token: (302, {"Location": "/other"}, b"")
        self.world.authorize(self.world.authorization(requests=1))
        with self.assertRaises(Blocked): self.world.execute()
        self.assertEqual([c["path"] for c in self.server.calls], ["/"])
        with self.assertRaises(Blocked): self.world.execute()
        with self.assertRaises(Blocked): self.world.authorize()
        self.assertEqual(len(self.server.calls), 1)

    def test_redirect_reserves_full_aggregate_body_and_time_budget(self):
        self.server.handler = lambda path, token: (302, {"Location": "/final"}, b"")
        self.world.authorize(self.world.authorization([self.world.route(redirects=["final"])], body_bytes=1024))
        with self.assertRaises(Blocked): self.world.execute()
        self.assertEqual(len(self.server.calls), 1)
        self.assertEqual(self.world.state.get("web-authority", "web-audit")["body_bytes_reserved"], 1024)

    def test_credential_bound_to_exact_actor_and_not_reported(self):
        self.server.handler = roles()
        comparison, result = compare_roles(self.world)
        self.assertTrue(result["expectations_satisfied"])
        report = self.world.control.runtime_report("demo")
        self.assertNotIn("fixture-owner", str(report))
        self.assertNotIn("synthetic-protected-record", str(report))
        self.assertIsNone(self.server.calls[-1]["authorization"])
        self.world.control.invalidate_runtime("demo", "web", comparison["cases"][0]["identity_operation"])
        self.assertFalse(self.world.control.runtime_report("demo")["comparisons"][0]["valid"])

    def test_vulnerable_roles_are_observed_failed_without_confirmed_verdict(self):
        self.server.handler = roles(vulnerable=True)
        _comparison, result = compare_roles(self.world)
        self.assertFalse(result["expectations_satisfied"])
        report = self.world.control.runtime_report("demo")
        self.assertEqual(report["security_verdict"], "not_established")
        self.assertTrue(all(r["same_body_as_positive"] for r in report["comparisons"][0]["results"]))

    def test_missing_identity_or_reused_credentials_cannot_compare_roles(self):
        self.server.handler = roles()
        spec, credentials = role_plan(self.world)
        self.world.authorize(spec)
        owner = self.world.execute("owner-read", credentials=credentials)["operation"]
        outsider = self.world.execute("outsider-read", credentials=credentials)["operation"]
        comparison = {"id": "bad", "deployment": "local", "policy_basis": "Synthetic owner policy", "identity_basis": "No identity observation", "cases": [
            {"operation": owner, "identity_operation": "absent", "expectation": "allowed"},
            {"operation": outsider, "identity_operation": "absent", "expectation": "denied"}]}
        with self.assertRaises(Blocked): self.world.control.compare("demo", comparison)

    def role_observations(self, spec, credentials):
        self.world.authorize(spec)
        cases = []
        for actor in ("owner", "outsider"):
            proof = self.world.execute(actor + "-identity", credentials=credentials)["operation"]
            record = self.world.execute(actor + "-read", credentials=credentials)["operation"]
            cases.append({"operation": record, "identity_operation": proof, "expectation": "allowed" if actor == "owner" else "denied"})
        return {"id": "comparison", "deployment": "local", "policy_basis": "Owner alone may read this exact record.",
                "identity_basis": "Distinct complete synthetic identity predicates.", "cases": cases}

    def test_denied_predicate_cannot_bless_the_protected_positive_body(self):
        legitimate = roles()
        self.server.handler = lambda path, token: (403, {}, b"synthetic-protected-record") if path == "/record" and token != "Bearer fixture-owner" else legitimate(path, token)
        spec, credentials = role_plan(self.world)
        next(r for r in spec["routes"] if r["id"] == "outsider-read")["body_sha256"] = sha256(b"synthetic-protected-record")
        result = self.world.control.compare("demo", self.role_observations(spec, credentials))
        self.assertFalse(result["expectations_satisfied"])
        denied = self.world.control.runtime_report("demo")["comparisons"][0]["results"][1]
        self.assertTrue(denied["response_predicate_matched"])
        self.assertTrue(denied["same_body_as_positive"])
        self.assertFalse(denied["matched"])

    def test_unrelated_denied_resource_cannot_qualify_as_role_comparison(self):
        legitimate = roles()
        self.server.handler = lambda path, token: (403, {}, b"denied") if path == "/unrelated" else legitimate(path, token)
        spec, credentials = role_plan(self.world)
        next(r for r in spec["routes"] if r["id"] == "outsider-read")["url"] = self.server.url + "unrelated"
        comparison = self.role_observations(spec, credentials)
        with self.assertRaises(Blocked): self.world.control.compare("demo", comparison)
        self.assertEqual(len(self.server.calls), 4)

    def test_reused_actor_credential_cannot_qualify_even_with_distinct_identity_bodies(self):
        counter = [0]
        def handler(path, _token):
            if path == "/identity":
                counter[0] += 1
                return 200, {}, b'{"user":"owner","tenant":"one"}' if counter[0] == 1 else b'{"user":"outsider","tenant":"one"}'
            return (200, {}, b"synthetic-protected-record") if counter[0] == 1 else (403, {}, b"denied")
        self.server.handler = handler
        spec, credentials = role_plan(self.world)
        credentials["outsider"] = copy.deepcopy(credentials["owner"])
        comparison = self.role_observations(spec, credentials)
        with self.assertRaises(Blocked): self.world.control.compare("demo", comparison)

    def test_inflight_cancellation_stops_waiting_and_consumes_intent(self):
        entered, finish = threading.Event(), threading.Event()
        def handler(_path, _token):
            entered.set(); finish.wait(5)
            return 200, {}, b"safe"
        self.server.handler = handler
        self.world.authorize(self.world.authorization(timeout_seconds=5))
        errors = []
        def execute():
            try: self.world.execute()
            except Blocked as error: errors.append(error)
        thread = threading.Thread(target=execute)
        thread.start()
        try:
            self.assertTrue(entered.wait(5))
            self.world.control.web.cancel("web-audit")
            thread.join(3)
            self.assertFalse(thread.is_alive())
            self.assertEqual(len(errors), 1)
            with self.assertRaises(Blocked): self.world.execute()
            self.assertEqual(len(self.server.calls), 1)
        finally:
            finish.set(); thread.join(6)

    def test_concurrent_distinct_intents_cannot_exceed_persistent_budget(self):
        self.world.authorize(self.world.authorization([self.world.route("one"), self.world.route("two")], requests=1))
        barrier, outcomes = threading.Barrier(2), []
        def execute(route):
            barrier.wait()
            try: outcomes.append(self.world.execute(route)["status"])
            except Blocked: outcomes.append("blocked")
        threads = [threading.Thread(target=execute, args=(name,)) for name in ("one", "two")]
        for thread in threads: thread.start()
        for thread in threads: thread.join(10)
        self.assertEqual(sorted(outcomes), ["blocked", "observed"])
        self.assertEqual(len(self.server.calls), 1)
        self.assertEqual(self.world.state.get("web-authority", "web-audit")["requests_used"], 1)

    def test_oversize_compression_and_truncation_never_match(self):
        for name, headers, body in [("oversize", {}, b"x" * 1025), ("compressed", {"Content-Encoding": "gzip"}, b"data"), ("truncated", {"Content-Length": "17", "Connection": "close"}, b"data")]:
            with self.subTest(name=name):
                self.server.handler = lambda path, token, h=headers, b=body: (200, h, b)
                self.world.authorize(self.world.authorization(name=name))
                with self.assertRaises(Blocked): self.world.execute(authorization=name)
        self.assertTrue(all(r["status"] == "uncertain" and not r["valid"] for r in self.world.control.runtime_report("demo")["network"]))

    def test_slow_response_cancel_and_expiry_preserve_consumed_intent(self):
        entered = threading.Event()
        def slow(_path, _token):
            entered.set()
            time.sleep(2)
            return 200, {}, b"safe"
        self.server.handler = slow
        self.world.authorize(self.world.authorization(timeout_seconds=1))
        started = time.monotonic()
        with self.assertRaises(Blocked): self.world.execute()
        self.assertLess(time.monotonic() - started, 4)
        self.assertTrue(entered.is_set())
        with self.assertRaises(Blocked): self.world.execute()
        self.world.control.web.cancel("web-audit")
        self.assertFalse(self.world.control.runtime_report("demo")["network"][0]["valid"])

    def test_unknown_and_stale_head_prevents_all_wire_effects(self):
        self.world.publisher.unavailable = True
        with self.assertRaises(Blocked): self.world.authorize()
        self.world.publisher.unavailable = False
        self.world.authorize()
        self.world.now[0] += 601
        with self.assertRaises(Blocked): self.world.execute()
        self.assertEqual(self.server.calls, [])

    def test_destination_classes_and_ambiguous_urls(self):
        self.assertEqual(str(address("::1", "loopback")), "::1")
        for ip, network in [("169.254.169.254", "private"), ("127.0.0.1", "public"), ("::ffff:127.0.0.1", "loopback"), ("0.0.0.0", "private")]:
            with self.subTest(ip=ip), self.assertRaises(Blocked): address(ip, network)
        for target in ["https://user@example.com/", "https://example.com/a/../b", "https://example.com/%2e%2e/x", "https://example.com/%252e/x", "https://example.com//x", "https://example.com/?token=x"]:
            with self.subTest(target=target), self.assertRaises(Blocked): url(target)

    def test_all_dns_answers_checked_before_socket(self):
        value = {"url": "http://fixture.invalid/", "method": "GET", "addresses": ["127.0.0.1"], "network": "loopback", "timeout": 1, "limit": 1024, "credential": None, "ca": None}
        with patch("socket.getaddrinfo", return_value=[(2, 1, 6, "", ("127.0.0.1", 80)), (2, 1, 6, "", ("127.0.0.2", 80))]), patch("socket.socket") as socket:
            with self.assertRaises(Blocked): collect(value)
            socket.assert_not_called()


if __name__ == "__main__": unittest.main()
