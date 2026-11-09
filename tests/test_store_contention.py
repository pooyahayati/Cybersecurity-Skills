"""Real control-database contention must not weaken admission or replay bounds."""

from contextlib import closing
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from m4_support import ROOT, RuntimeWorld, Server
from security_runtime.common import Blocked
from security_runtime.store import Store


def rows(store):
    with closing(sqlite3.connect(store.root / "control.sqlite3")) as connection:
        return connection.execute("SELECT * FROM records ORDER BY kind,id").fetchall()


class StoreContentionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="cyber-store-lock-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.store = Store(self.root / "private", ROOT, initialize=True)
        with self.store.transaction() as tx:
            tx.put("owned", "first", {"value": "original"})
            tx.put("owned", "second", {"value": "original"})
        self.before = rows(self.store)

    def connection(self):
        connection = sqlite3.connect(self.store.root / "control.sqlite3")
        self.addCleanup(connection.close)
        return connection

    def test_real_writer_lock_blocks_before_transaction_and_recovers(self):
        writer = self.connection()
        writer.execute("BEGIN IMMEDIATE")
        entered = []
        with self.assertRaisesRegex(Blocked, "control state is busy"):
            with self.store.transaction() as tx:
                entered.append(True)
                tx.put("owned", "forbidden", {"value": "unexpected"})
        self.assertEqual(entered, [])
        writer.rollback()
        self.assertEqual(rows(self.store), self.before)
        with self.store.transaction() as tx:
            tx.put("owned", "allowed", {"value": "committed"})
        self.assertEqual(self.store.get("owned", "allowed"), {"value": "committed"})

    def test_real_reader_lock_at_commit_rolls_back_every_write(self):
        reader = self.connection()
        reader.execute("BEGIN")
        reader.execute("SELECT * FROM records").fetchall()
        with self.assertRaisesRegex(Blocked, "control state is busy"):
            with self.store.transaction() as tx:
                tx.put("owned", "first", {"value": "uncommitted"})
                tx.put("owned", "forbidden", {"value": "uncommitted"})
        reader.rollback()
        self.assertEqual(rows(self.store), self.before)
        with self.store.transaction() as tx:
            tx.put("owned", "first", {"value": "recovered"})
        self.assertEqual(self.store.get("owned", "first"), {"value": "recovered"})

    def test_real_locked_table_is_blocked_without_dropping_state(self):
        with self.assertRaisesRegex(Blocked, "control state is busy"):
            with self.store.transaction() as tx:
                with closing(tx.connection.execute("SELECT * FROM records")) as cursor:
                    self.assertIsNotNone(cursor.fetchone())
                    tx.connection.execute("DROP TABLE records")
        self.assertEqual(rows(self.store), self.before)
        self.assertEqual(self.store.get("owned", "first"), {"value": "original"})

    def test_unrelated_and_uncoded_errors_are_not_reclassified(self):
        with self.assertRaises(sqlite3.OperationalError) as actual:
            with self.store.transaction() as tx:
                tx.put("owned", "first", {"value": "uncommitted"})
                tx.connection.execute("SELECT * FROM missing_owned_table")
        self.assertEqual(actual.exception.sqlite_errorcode, sqlite3.SQLITE_ERROR)
        self.assertEqual(rows(self.store), self.before)
        for code in (None, "5", True, sqlite3.SQLITE_IOERR):
            error = sqlite3.OperationalError("database is locked: synthetic private detail")
            error.sqlite_errorcode = code
            with self.assertRaises(sqlite3.OperationalError) as result:
                with self.store.transaction() as tx:
                    tx.put("owned", "first", {"value": "uncommitted"})
                    raise error
            self.assertIs(result.exception, error)
            self.assertEqual(rows(self.store), self.before)

    def test_extended_contention_codes_are_sanitized_and_rolled_back(self):
        for code in (sqlite3.SQLITE_BUSY | (2 << 8), sqlite3.SQLITE_LOCKED | (1 << 8)):
            error = sqlite3.OperationalError("synthetic private connection detail")
            error.sqlite_errorcode = code
            with self.assertRaises(Blocked) as result:
                with self.store.transaction() as tx:
                    tx.put("owned", "first", {"value": "uncommitted"})
                    raise error
            self.assertNotIn("synthetic private", str(result.exception))
            self.assertTrue(result.exception.__suppress_context__)
            self.assertEqual(rows(self.store), self.before)


class WebContentionTests(unittest.TestCase):
    def setUp(self):
        self.server = Server()
        self.addCleanup(self.server.close)
        self.world = RuntimeWorld(self.server)
        self.addCleanup(self.world.close)
        self.world.authorize(self.world.authorization(requests=1))

    def test_real_admission_lock_has_no_effect_then_same_authority_works(self):
        before = rows(self.world.state)
        with closing(sqlite3.connect(self.world.state.root / "control.sqlite3")) as writer:
            writer.execute("BEGIN IMMEDIATE")
            with self.assertRaises(Blocked):
                self.world.execute()
            self.assertEqual(self.server.calls, [])
            writer.rollback()
        self.assertEqual(rows(self.world.state), before)
        self.assertEqual(self.world.execute()["status"], "observed")
        self.assertEqual(len(self.server.calls), 1)
        self.assertEqual(self.world.state.get("web-authority", "web-audit")["requests_used"], 1)

    def test_commit_lock_after_request_cannot_refund_or_replay_intent(self):
        reader = sqlite3.connect(self.world.state.root / "control.sqlite3")
        self.addCleanup(reader.close)
        original = self.world.control.web._request

        def capture_then_lock(*args, **kwargs):
            result = original(*args, **kwargs)
            reader.execute("BEGIN")
            reader.execute("SELECT * FROM records").fetchall()
            return result

        try:
            with patch.object(self.world.control.web, "_request", capture_then_lock):
                with self.assertRaises(Blocked):
                    self.world.execute()
        finally:
            reader.rollback()
        self.assertEqual(len(self.server.calls), 1)
        authority = self.world.state.get("web-authority", "web-audit")
        self.assertEqual(authority["requests_used"], 1)
        self.assertEqual(len(authority["intents"]), 1)
        operation = next(iter(authority["intents"].values()))
        self.assertNotEqual(self.world.state.get("web-operation", operation)["status"], "completed")
        with self.assertRaises(Blocked):
            self.world.execute()
        self.assertEqual(len(self.server.calls), 1)


if __name__ == "__main__":
    unittest.main()
