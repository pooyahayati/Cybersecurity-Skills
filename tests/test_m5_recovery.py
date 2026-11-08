import copy
from pathlib import Path
import tempfile
import sqlite3
import unittest

from m5_support import artifact_contract, make_database, oracle
from security_assessment.resilience_data import contract, exercise
from security_runtime.common import Blocked, sha256


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix="m5-sqlite-");self.addCleanup(self.temp.cleanup)
        # Windows runners may expose TEMP through an 8.3 alias. The owned fixture
        # must use its canonical path, just like authorized M1 input roots.
        self.root=Path(self.temp.name).resolve(strict=True);self.rows=[("one",100),("two",200)]
        make_database(self.root/"backup.sqlite3",self.rows)
        make_database(self.root/"rollback.sqlite3",self.rows)

    def run_check(self,value=None):return exercise(self.root,self.root/"disposable",value or artifact_contract(self.rows,True))

    def test_actual_restore_and_rollback_preserve_originals(self):
        before={p.name:sha256(p.read_bytes()) for p in self.root.iterdir()}
        result=self.run_check()
        self.assertTrue(result["artifact_check_passed"])
        self.assertTrue(result["rollback"]["passed"])
        self.assertGreater(result["restore_seconds"],0)
        self.assertFalse(result["service_recovery_verified"] or result["capture_time_verified"])
        self.assertEqual(before,{p.name:sha256(p.read_bytes()) for p in self.root.iterdir() if p.is_file()})

    def test_existing_unrestorable_backup_fails(self):
        (self.root/"backup.sqlite3").write_bytes(b"not a database")
        result=self.run_check()
        self.assertFalse(result["artifact_check_passed"])
        self.assertFalse(result["restored"]["readable"])

    def test_duplicate_transaction_even_with_matching_digest_fails(self):
        (self.root/"backup.sqlite3").unlink()
        duplicates=[("one",100),("one",200)]
        make_database(self.root/"backup.sqlite3",duplicates)
        result=self.run_check(artifact_contract(duplicates))
        self.assertTrue(result["restored"]["tables"][0]["duplicates_or_null_keys"])
        self.assertFalse(result["artifact_check_passed"])

    def test_altered_amount_and_wrong_rollback_fail(self):
        (self.root/"rollback.sqlite3").unlink();make_database(self.root/"rollback.sqlite3",[("one",999),("two",200)])
        result=self.run_check()
        self.assertTrue(result["restored"]["passed"])
        self.assertFalse(result["rollback"]["passed"] or result["artifact_check_passed"])

    def test_wal_and_executable_sql_views_rejected(self):
        (self.root/"backup.sqlite3-wal").write_bytes(b"pending")
        with self.assertRaises(Blocked):self.run_check()
        (self.root/"backup.sqlite3-wal").unlink()
        (self.root/"backup.sqlite3").unlink();make_database(self.root/"backup.sqlite3",self.rows,view=True)
        value=artifact_contract(self.rows);value["oracle"][0]["table"]="projected"
        result=exercise(self.root,self.root/"second",value)
        self.assertFalse(result["artifact_check_passed"])
        value["oracle"][0]["table"]="records; DROP TABLE records"
        with self.assertRaises(Blocked):contract(value)

    def test_null_unique_keys_and_type_changes_are_not_safe(self):
        (self.root/"backup.sqlite3").unlink();make_database(self.root/"backup.sqlite3",[(None,100),("two",200)])
        result=self.run_check(artifact_contract([(None,100),("two",200)]))
        self.assertFalse(result["artifact_check_passed"])
        self.assertNotEqual(oracle([("one",100)]),oracle([("one","100")]))

    def test_sqlite_numeric_equality_and_column_collation_define_duplicates(self):
        cases = [("", [(1, 100), (1.0, 200)], True),
                 ("TEXT COLLATE NOCASE", [("One", 100), ("one", 200)], True),
                 ("TEXT COLLATE BINARY", [("One", 100), ("one", 200)], False)]
        for index, (definition, rows, duplicated) in enumerate(cases):
            path = self.root / ("case" + str(index) + ".sqlite3")
            db = sqlite3.connect(path)
            try:
                db.execute("CREATE TABLE records (transaction_id " + definition + ", amount INTEGER)")
                db.executemany("INSERT INTO records VALUES (?,?)", rows); db.commit()
            finally: db.close()
            spec = artifact_contract(rows); spec["database"] = path.name
            result = exercise(self.root, self.root / ("work" + str(index)), spec)
            self.assertEqual(result["restored"]["tables"][0]["duplicates_or_null_keys"], duplicated)
            self.assertEqual(result["artifact_check_passed"], not duplicated)

    def test_missing_column_cannot_be_treated_as_string_constant(self):
        spec = artifact_contract(self.rows)
        spec["oracle"][0]["columns"] = ["missing", "amount"]
        spec["oracle"][0]["unique"] = [["missing"]]
        result = self.run_check(spec)
        self.assertFalse(result["artifact_check_passed"])
        self.assertFalse(result["restored"]["readable"])


if __name__=="__main__":unittest.main()
