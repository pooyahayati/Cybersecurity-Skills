"""Finite SQLite artifact oracles. Execute database parsing only inside M1."""

import math
from pathlib import Path
import re
import sqlite3
import time

from security_runtime.common import canonical, digest, fields, integer, number, read_file, require, sha256
from security_runtime.web_scope import fingerprint


def name(value):
    require(isinstance(value, str) and re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,63}", value), "simple SQLite identifier required")
    return '"' + value + '"'


def oracle_contract(rows):
    require(isinstance(rows, list) and 1 <= len(rows) <= 8, "bounded table oracles required")
    tables = set()
    for row in rows:
        fields(row, {"table", "columns", "row_count", "rows_sha256", "unique"})
        name(row["table"])
        require(row["table"] not in tables, "duplicate table")
        tables.add(row["table"])
        require(isinstance(row["columns"], list) and 1 <= len(row["columns"]) <= 16 and len(set(row["columns"])) == len(row["columns"]), "invalid projection")
        for column in row["columns"]: name(column)
        integer(row["row_count"], 0, 10000)
        fingerprint(row["rows_sha256"])
        require(isinstance(row["unique"], list) and 1 <= len(row["unique"]) <= 4, "explicit unique/idempotency keys required")
        for unique in row["unique"]:
            require(isinstance(unique, list) and 0 < len(unique) <= len(row["columns"]) and len(set(unique)) == len(unique)
                    and set(unique) <= set(row["columns"]), "invalid unique projection")


def contract(value):
    fields(value, {"schema_version", "mode", "database", "oracle", "rollback", "objectives"})
    require(value["schema_version"] == 1 and value["mode"] in {"integrity", "recovery"}, "unsupported artifact check")
    from security_runtime.common import relpath
    relpath(value["database"])
    oracle_contract(value["oracle"])
    if value["mode"] == "integrity":
        require(value["rollback"] is None and value["objectives"] is None, "integrity check has no recovery contract")
    else:
        fields(value["rollback"], {"database", "oracle"})
        relpath(value["rollback"]["database"])
        require(value["database"] != value["rollback"]["database"], "independent rollback snapshot required")
        oracle_contract(value["rollback"]["oracle"])
        fields(value["objectives"], {"restore_seconds", "declared_snapshot_at", "declared_reference_at", "allowed_loss_seconds"})
        number(value["objectives"]["restore_seconds"], .001, 60)
        number(value["objectives"]["allowed_loss_seconds"], 0, 86400 * 365)
        for key in ("declared_snapshot_at", "declared_reference_at"): number(value["objectives"][key], 0, 4102444800)
        require(value["objectives"]["declared_snapshot_at"] <= value["objectives"]["declared_reference_at"], "snapshot is after reference")


def cell(value):
    if value is None: return ["null", None]
    if type(value) is int: return ["integer", value]
    if type(value) is float:
        require(math.isfinite(value), "nonfinite SQLite value")
        return ["real", value]
    if isinstance(value, str): return ["text", value]
    if isinstance(value, bytes): return ["blob-sha256", sha256(value)]
    raise ValueError("unsupported SQLite value")


def inspect(database, oracles):
    results = []
    connection = sqlite3.connect(database.as_uri() + "?mode=ro&immutable=1", uri=True)
    deadline = time.monotonic() + 10
    try:
        connection.enable_load_extension(False)
        connection.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, 1024 * 1024)
        connection.setlimit(sqlite3.SQLITE_LIMIT_SQL_LENGTH, 8192)
        connection.set_progress_handler(lambda: int(time.monotonic() > deadline), 1000)
        connection.execute("PRAGMA query_only=ON")
        connection.execute("PRAGMA trusted_schema=OFF")
        require(connection.execute("PRAGMA integrity_check(1)").fetchall() == [("ok",)], "database integrity check failed")
        for row in oracles:
            definition = connection.execute("SELECT type,sql FROM sqlite_schema WHERE name=?", (row["table"],)).fetchone()
            require(definition and definition[0] == "table" and definition[1].lstrip().upper().startswith("CREATE TABLE"), "only real ordinary tables are supported")
            columns = {r[1] for r in connection.execute("PRAGMA table_xinfo(" + name(row["table"]) + ")") if r[6] == 0}
            require(set(row["columns"]) <= columns, "ordinary stored columns required")
            values = connection.execute("SELECT " + ",".join(name(c) for c in row["columns"]) + " FROM " + name(row["table"]) + " LIMIT 10001").fetchall()
            require(len(values) <= 10000, "row limit exceeded")
            encoded = sorted([list(map(cell, r)) for r in values], key=canonical)
            require(len(canonical(encoded)) <= 4 * 1024 * 1024, "projected data exceeds limit")
            duplicates = []
            for unique in row["unique"]:
                indices = [row["columns"].index(c) for c in unique]
                # SQLite numeric equality and declared column collations define
                # keys. Typed serialization remains only the whole-state oracle.
                duplicate = connection.execute("SELECT 1 FROM " + name(row["table"]) + " GROUP BY " +
                    ",".join(name(c) for c in unique) + " HAVING COUNT(*) > 1 LIMIT 1").fetchone() is not None
                duplicates.append(duplicate or any(r[i] is None for r in values for i in indices))
            actual = digest(encoded)
            results.append({"table": row["table"], "rows": len(values), "rows_sha256": actual, "duplicates_or_null_keys": any(duplicates),
                "matched": len(values) == row["row_count"] and actual == row["rows_sha256"] and not any(duplicates)})
        return {"readable": True, "passed": all(r["matched"] for r in results), "tables": results}
    finally:
        connection.close()


def exercise(root, workspace, value):
    contract(value)
    root, workspace = Path(root), Path(workspace)
    workspace.mkdir(mode=0o700, exist_ok=False)
    # perf_counter is monotonic and high-resolution on every supported Python.
    # Older Windows monotonic clocks can round a short real restore to zero.
    started = time.perf_counter()

    def restore(path, target, oracles):
        # A backup is a standalone SQLite snapshot, not an open database with WAL.
        require(not (root / (path + "-wal")).exists() and not (root / (path + "-shm")).exists(), "live WAL snapshots unsupported")
        raw = read_file(root, path, 16 * 1024 * 1024)
        destination = workspace / target
        destination.write_bytes(raw)
        try:
            result = inspect(destination, oracles)
        except (sqlite3.Error, ValueError, OSError):
            result = {"readable": False, "passed": False, "tables": []}
        require(sha256(read_file(root, path, 16 * 1024 * 1024)) == sha256(raw), "original input changed")
        return {"snapshot_sha256": sha256(raw), **result}

    restored = restore(value["database"], "restored.sqlite3", value["oracle"])
    elapsed = time.perf_counter() - started
    rollback = restore(value["rollback"]["database"], "rolled-back.sqlite3", value["rollback"]["oracle"]) if value["rollback"] else None
    objectives = value["objectives"]
    return {"schema_version": 1, "adapter": "sqlite-artifact", "mode": value["mode"], "contract_sha256": digest(value),
        "restored": restored, "rollback": rollback, "restore_seconds": elapsed,
        "artifact_check_passed": restored["passed"] and (rollback is None or rollback["passed"]) and (objectives is None or elapsed <= objectives["restore_seconds"]),
        "declared_loss_seconds": None if objectives is None else objectives["declared_reference_at"] - objectives["declared_snapshot_at"],
        "declared_loss_within_budget": None if objectives is None else objectives["declared_reference_at"] - objectives["declared_snapshot_at"] <= objectives["allowed_loss_seconds"],
        "capture_time_verified": False, "deployed_database_link_verified": False, "service_recovery_verified": False,
        "security_verdict": "not_established"}
