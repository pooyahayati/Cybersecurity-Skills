from copy import deepcopy
import os
from pathlib import Path
import sqlite3
import shutil
import sys
import threading
import tempfile
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from security_runtime.common import Blocked, parse, read_file, relpath
from security_runtime.controller import HEAD_RESOURCES
from security_runtime.store import Store
from runtime_support import Fixture, acceptance, source


class ControlTests(unittest.TestCase):
    def setUp(self):
        self.f = Fixture()
        self.addCleanup(self.f.close)
        self.c, self.s = self.f.controller, self.f.store

    def test_private_state_outside_package_and_target(self):
        with self.assertRaises(Blocked):
            Store(self.f.package / "state", self.f.package, initialize=True)
        value = self.f.authorization(root=str(self.f.base))
        with self.assertRaises(Blocked):
            self.c.authorize(value)

    def test_tampered_record_and_cross_kind_replay_fail(self):
        with self.s.transaction() as tx:
            tx.put("run", "one", {"cancelled": True})
        db = sqlite3.connect(self.s.root / "control.sqlite3")
        db.execute("UPDATE records SET kind='authorization' WHERE kind='run'")
        db.commit()
        with self.assertRaises(Blocked):
            self.s.get("authorization", "one")
        db.execute("UPDATE records SET kind='run', payload=? WHERE id='one'", (b'{"cancelled":false}',))
        db.commit()
        db.close()
        with self.assertRaises(Blocked):
            self.s.get("run", "one")

    def test_source_identity_cannot_be_reenrolled_or_head_underselected(self):
        with self.assertRaises(Blocked):
            self.c.enroll(source())
        with self.assertRaises(Blocked):
            self.c.enroll(source("different-head", "head", HEAD_RESOURCES))

    def test_activation_needs_review_and_compatibility(self):
        candidate = self.c.prepare("analyzer")["candidate"]
        with self.assertRaises(Blocked):
            self.c.activate(candidate)
        decision = acceptance(candidate)
        decision["checks"]["compatibility"]["result"] = "fail"
        with self.assertRaises(Blocked):
            self.c.review(decision)
        self.assertIsNone(self.s.get("active", "analyzer"))

    def test_failed_update_preserves_last_pointer_without_stale_success(self):
        accepted = self.f.activate("analyzer")
        self.f.publisher.revisions["analyzer"] = "updated"
        candidate = self.c.prepare("analyzer")["candidate"]
        self.c.review(acceptance(candidate))
        self.f.publisher.unavailable = True
        with self.assertRaises(Blocked):
            self.c.activate(candidate)
        self.assertEqual(self.s.get("active", "analyzer"), accepted)
        with self.assertRaises(Blocked):
            self.c.check_current(accepted)

    def test_candidate_tampering_blocks_activation(self):
        candidate = self.c.prepare("analyzer")["candidate"]
        self.c.review(acceptance(candidate))
        path = self.s.root / "objects" / candidate / "check.py"
        path.chmod(0o600)
        path.write_bytes(b"changed")
        with self.assertRaises(Blocked):
            self.c.activate(candidate)
        self.assertIsNone(self.s.get("active", "analyzer"))

    def test_head_required_and_actual_reload_verified(self):
        self.f.activate("runtime")
        self.f.activate("analyzer")
        self.c.authorize(self.f.authorization())
        with self.assertRaises(Blocked):
            self.c.begin("audit")
        self.f.activate("head")
        (self.f.package / "SKILL.md").write_bytes(b"modified")
        with self.assertRaisesRegex(Blocked, "reload_required"):
            self.c.begin("audit")

    def test_accepted_head_can_reload_into_disjoint_package(self):
        self.f.ready()
        self.f.publisher.contents["head"]["SKILL.md"] = b"updated instructions\n"
        self.f.publisher.revisions["head"] = "new-head"
        candidate = self.f.activate("head")
        self.c.authorize(self.f.authorization())
        with self.assertRaisesRegex(Blocked, "reload_required"):
            self.c.begin("audit")
        loaded = self.f.base / "reloaded-package"
        shutil.copytree(self.s.root / "objects" / candidate, loaded)
        from security_runtime.controller import Controller
        reloaded = Controller(Store(self.s.root, loaded), loaded, self.f.publisher, self.f.docker)
        self.assertEqual(reloaded.begin("audit")["status"], "ready")

    def test_symlink_root_cannot_redirect_input_capture(self):
        alias = self.f.base / "alias"
        try:
            alias.symlink_to(self.f.target, target_is_directory=True)
        except OSError as exc:
            if os.name != "nt":
                raise
            self.skipTest("Windows host cannot create this symlink fixture")
        with self.assertRaises(Blocked):
            read_file(alias, "customer.txt")

    def test_failed_resume_invalidates_previous_run(self):
        self.f.ready()
        run = self.f.begin()
        self.f.publisher.unavailable = True
        with self.assertRaises(Blocked):
            self.c.begin("audit")
        with self.assertRaises(Blocked):
            self.c.execute(run, "check")
        self.assertEqual(self.f.docker.calls, [])
        self.assertTrue(self.s.get("run", run)["cancelled"])

    def test_frozen_bytes_survive_unrelated_activation_until_resume(self):
        self.f.ready()
        run = self.f.begin()
        old = self.s.get("run", run)["bindings"]["analyzer"]
        self.f.publisher.revisions["analyzer"] = "updated"
        new = self.f.activate("analyzer")
        self.assertNotEqual(old, new)
        self.assertEqual(self.c.execute(run, "check")["result"]["exit_code"], 0)
        self.assertEqual(self.s.get("run", run)["bindings"]["analyzer"], old)
        resumed = self.c.begin("audit")["run"]
        self.assertEqual(self.s.get("run", resumed)["bindings"]["analyzer"], new)

    def test_data_age_separate_from_binary_and_expires_mid_run(self):
        self.f.publisher.contents["rules"] = {"rules.json": b"{}"}
        self.c.enroll(source("rules", "data", ["rules.json"]))
        self.f.activate("rules")
        self.f.ready()
        run = self.f.begin(self.f.authorization(components=["analyzer", "rules"]))
        self.c.clock = lambda: time.time() + 3601
        # Keep authorization valid to isolate the data-age rejection.
        with self.s.transaction() as tx:
            auth = tx.get("authorization", "audit")
            auth["spec"]["limits"]["expires_at"] += 7200
            tx.put("authorization", "audit", auth)
        with self.assertRaisesRegex(Blocked, "data expired"):
            self.c.execute(run, "check")

    def test_changed_original_requires_new_authorization_but_execution_uses_snapshot(self):
        self.f.ready()
        run = self.f.begin()
        (self.f.target / "customer.txt").write_bytes(b"changed by owner")
        self.assertEqual(self.c.execute(run, "check")["result"]["exit_code"], 0)
        with self.assertRaisesRegex(Blocked, "target bytes changed"):
            self.c.begin("audit")
        self.assertEqual((self.f.target / "customer.txt").read_bytes(), b"changed by owner")

    def test_permission_escalation_and_unsupported_network_rejected(self):
        for change in ({"network": "internet"}, {"verified": True}, {"inputs": ["../outside"]},
                       {"components": ["head"]}):
            with self.subTest(change=change), self.assertRaises(Blocked):
                self.c.authorize(self.f.authorization(**change))

    def test_exact_operations_and_shared_budget_across_resume(self):
        self.f.ready()
        value = self.f.authorization()
        value["limits"].update(calls=1, seconds=5)
        run = self.f.begin(value)
        with self.assertRaises(Blocked):
            self.c.execute(run, "unapproved")
        self.assertEqual(self.c.execute(run, "check")["result"]["exit_code"], 0)
        resumed = self.c.begin("audit")["run"]
        with self.assertRaisesRegex(Blocked, "budget exhausted"):
            self.c.execute(resumed, "check")
        self.assertEqual(len(self.f.docker.calls), 1)

    def test_cancel_and_revoke_interrupt_guard_and_consume_budget(self):
        self.f.ready()
        run = self.f.begin()
        self.f.docker.callback = lambda: self.c.revoke(component="analyzer")
        with self.assertRaises(Blocked):
            self.c.execute(run, "check")
        self.assertEqual(self.s.get("authorization", "audit")["calls_used"], 1)
        self.assertIsNone(self.s.get("authorization", "audit")["operation"])
        self.c.cancel(run)
        with self.assertRaises(Blocked):
            self.c.guard(run)

    def test_concurrent_operation_cannot_double_spend(self):
        self.f.ready()
        run = self.f.begin()
        reached, release = threading.Event(), threading.Event()
        errors = []
        self.f.docker.callback = lambda: (reached.set(), release.wait(10))

        def first():
            try:
                self.c.execute(run, "check")
            except Exception as exc:
                errors.append(exc)

        thread = threading.Thread(target=first)
        thread.start()
        self.assertTrue(reached.wait(10))
        try:
            with self.assertRaises(Blocked):
                self.c.execute(run, "check")
        finally:
            release.set()
            thread.join(10)
        self.assertFalse(errors)
        self.assertEqual(self.s.get("authorization", "audit")["calls_used"], 1)

    def test_cleanup_failure_locks_and_recovery_invalidates(self):
        self.f.ready()
        run = self.f.begin()
        self.f.docker.callback = lambda: self.c.cancel(run)
        self.f.docker.cleanup_failure = True
        with self.assertRaisesRegex(Blocked, "cleanup unverified"):
            self.c.execute(run, "check")
        self.assertIsNotNone(self.s.get("authorization", "audit")["operation"])
        with self.assertRaises(Blocked):
            self.c.begin("audit")
        self.f.docker.cleanup_failure = False
        self.assertEqual(len(self.c.recover()["operations"]), 1)
        self.assertIsNone(self.s.get("authorization", "audit")["operation"])
        self.assertTrue(self.s.get("run", run)["cancelled"])

    def test_hard_link_inputs_are_rejected(self):
        os.link(self.f.target / "customer.txt", self.f.target / "alias.txt")
        with self.assertRaises(Blocked):
            self.c.authorize(self.f.authorization())


class ParsingTests(unittest.TestCase):
    def test_repeated_capture_keeps_fresh_bytes_and_bounded_pointer_metadata(self):
        import ctypes
        import hashlib

        with tempfile.TemporaryDirectory(prefix="cyber-repeated-capture-") as directory:
            root = Path(directory).resolve()
            sample = root / "sample"
            sample.write_bytes(b"warm-up")
            self.assertEqual(read_file(root, "sample"), b"warm-up")
            pointer_cache = getattr(ctypes, "_pointer_type_cache", None)
            # The retained-allocation counter applies to the legacy Windows
            # dictionary cache; newer CPython exposes an opaque private object.
            # Fresh-file and handle-lifetime assertions run on every runtime.
            if os.name != "nt" or not isinstance(pointer_cache, dict):
                pointer_cache = None
            before = len(pointer_cache) if pointer_cache is not None else None
            for index in range(128):
                content = ("fresh capture " + str(index)).encode("ascii")
                # Every rewrite must succeed: captures cannot retain restrictive
                # file handles or reuse bytes from a preceding observation.
                sample.write_bytes(content)
                self.assertEqual(read_file(root, "sample"), content)
                self.assertEqual(read_file(root, "sample", hash_only=True),
                                 hashlib.sha256(content).hexdigest())
            if pointer_cache is not None:
                self.assertLessEqual(len(pointer_cache), before,
                                     "file captures retained new ctypes pointer types")
            sample.unlink()
            with self.assertRaises(FileNotFoundError):
                read_file(root, "sample")

    def test_file_size_ceiling_and_empty_file_capture(self):
        with tempfile.TemporaryDirectory(prefix="cyber-file-bound-") as directory:
            root = Path(directory).resolve()
            (root / "sample").write_bytes(b"exact bytes")
            self.assertEqual(read_file(root, "sample", 512 * 1024 * 1024), b"exact bytes")
            with self.assertRaises(Blocked):
                read_file(root, "sample", 10)
            (root / "empty").write_bytes(b"")
            self.assertEqual(read_file(root, "empty", 0), b"")

    def test_duplicate_nonfinite_and_unknown_json_do_not_grant_authority(self):
        for value in ('{"a":1,"a":2}', '{"value":NaN}', '{"value":Infinity}'):
            with self.subTest(value=value), self.assertRaises(Blocked):
                parse(value)

    def test_unsafe_portable_paths(self):
        for path in ("", ".", "../file", "a/../file", "/root", "C:/root", "a\\b", "a//b",
                     "nul.txt", "x.", "x ", "a:b", "a?b", "x\nfile"):
            with self.subTest(path=path), self.assertRaises(Blocked):
                relpath(path)


if __name__ == "__main__":
    unittest.main()
