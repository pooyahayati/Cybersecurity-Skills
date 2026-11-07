"""Atomic signed control records outside source and target repositories."""

from __future__ import annotations

from contextlib import contextmanager
import hashlib
import hmac
import os
from pathlib import Path
import secrets
import sqlite3

from .common import Blocked, canonical, fields, parse, read_file, require, text
from .private import private_directory


class Store:
    def __init__(self, root, package_root, initialize=False):
        self.root = Path(root).absolute()
        package_root = Path(package_root).resolve()
        require(not self.root.is_relative_to(package_root)
                and not package_root.is_relative_to(self.root), "control state must be outside the package")
        private_directory(self.root, create=initialize)
        if initialize:
            with (self.root / "key").open("xb") as stream:
                stream.write(secrets.token_bytes(32))
            if os.name != "nt":
                (self.root / "key").chmod(0o600)
            for name in ("objects", "quarantine", "inputs", "docker-config"):
                (self.root / name).mkdir(mode=0o700)
            (self.root / "docker-config/config.json").write_bytes(b"{}\n")
            connection = sqlite3.connect(self.root / "control.sqlite3")
            try:
                connection.execute("CREATE TABLE records (kind TEXT, id TEXT, revision INTEGER, "
                                   "payload BLOB, mac TEXT, PRIMARY KEY(kind,id))")
                connection.commit()
            finally:
                connection.close()
            if os.name != "nt":
                (self.root / "control.sqlite3").chmod(0o600)
        self.key = read_file(self.root, "key", 32)
        require(len(self.key) == 32, "controller key is invalid")
        # Refuse database path substitution before sqlite can open it.
        from .common import regular
        regular(self.root / "control.sqlite3")
        if os.name != "nt":
            require((self.root / "key").stat().st_mode & 0o077 == 0
                    and (self.root / "control.sqlite3").stat().st_mode & 0o077 == 0,
                    "controller key and database must remain private")

    @contextmanager
    def transaction(self):
        connection = sqlite3.connect(self.root / "control.sqlite3", timeout=2)
        connection.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, 4 * 1024 * 1024)
        try:
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute("BEGIN IMMEDIATE")
            yield Transaction(self, connection)
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def get(self, kind, key, default=None):
        with self.transaction() as tx:
            return tx.get(kind, key, default)

    def sign(self, kind, key, revision, data):
        message = canonical({"kind": kind, "id": key, "revision": revision, "data": data})
        return hmac.new(self.key, message, hashlib.sha256).hexdigest()


class Transaction:
    def __init__(self, store, connection):
        self.store, self.connection = store, connection

    def get(self, kind, key, default=None):
        row = self.connection.execute(
            "SELECT revision,payload,mac FROM records WHERE kind=? AND id=?", (kind, key)).fetchone()
        if row is None:
            return default
        revision, encoded, signature = row
        require(type(revision) is int and revision > 0 and isinstance(signature, str),
                "invalid control record")
        data = parse(encoded)
        require(hmac.compare_digest(self.store.sign(kind, key, revision, data), signature),
                "control record authentication failed")
        return data

    def put(self, kind, key, data):
        text(kind, 64)
        text(key, 128)
        self.get(kind, key)  # Never overwrite an unauthenticated prior record.
        row = self.connection.execute("SELECT revision FROM records WHERE kind=? AND id=?",
                                      (kind, key)).fetchone()
        revision = row[0] + 1 if row else 1
        encoded = canonical(data)
        require(len(encoded) <= 4 * 1024 * 1024, "control record exceeds its size limit")
        signature = self.store.sign(kind, key, revision, data)
        self.connection.execute("INSERT OR REPLACE INTO records VALUES (?,?,?,?,?)",
                                (kind, key, revision, encoded, signature))

    def list(self, kind):
        keys = self.connection.execute("SELECT id FROM records WHERE kind=? ORDER BY id", (kind,)).fetchall()
        require(len(keys) <= 4096, "control record count exceeds its limit")
        return {key: self.get(kind, key) for (key,) in keys}
