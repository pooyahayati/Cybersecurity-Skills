"""One-skill, explicit-root installation with private recovery records.

The account and filesystem must be trusted against concurrent outside writers.
The lock serializes this manager; hashes/markers do not authenticate a publisher
or protect against an actor who can replace the private state and skill files.
"""

from contextlib import contextmanager
import os
from pathlib import Path
import re
import uuid

from .common import Blocked, canonical, fields, parse, read_file, regular, require, sha256
from .package import (MANIFEST, MAX_ARCHIVE, MAX_FILE, MAX_FILES, NAME, directory,
                      hash_text, read_archive, verify, write_new)
from .private import private_directory


RECEIPT = ".managed-package.json"


class Manager:
    def __init__(self, state, skills_root, create=False):
        self.root = directory(skills_root)
        self.state = Path(state).absolute()
        directory(self.state.parent)
        require(not self.state.is_relative_to(self.root) and not self.root.is_relative_to(self.state),
                "management state and skills root must be separate")
        require(not self.state.is_relative_to(Path(__file__).resolve().parents[2]),
                "management state must stay outside the skill source")
        if not self.state.exists():
            require(create, "management state is missing")
            private_directory(self.state, create=True)
            write_new(self.state / "manager.json", canonical({"schema_version": 1,
                "skills_root": str(self.root), "installation_id": uuid.uuid4().hex}))
            (self.state / "archives").mkdir(mode=0o700)
            write_new(self.state / "lock", b"0")
        private_directory(self.state)
        self.meta = self.record("manager.json")
        fields(self.meta, ("schema_version", "skills_root", "installation_id"))
        require(type(self.meta["schema_version"]) is int and self.meta["schema_version"] == 1
                and self.meta["skills_root"] == str(self.root)
                and re.fullmatch(r"[a-f0-9]{32}", self.meta["installation_id"]),
                "management state belongs to a different root or format")
        directory(self.state / "archives")
        self.target = self.root / NAME

    def record(self, name):
        return parse(read_file(self.state, name, MAX_FILE), MAX_FILE)

    @contextmanager
    def locked(self):
        path = self.state / "lock"
        regular(path)
        with path.open("r+b") as stream:
            try:
                if os.name == "nt":
                    import msvcrt
                    msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as exc:
                raise Blocked("another package operation is active") from exc
            try:
                directory(self.root)
                private_directory(self.state)
                yield
            finally:
                stream.seek(0)
                if os.name == "nt":
                    msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    fcntl.flock(stream.fileno(), fcntl.LOCK_UN)

    def archive(self, identity):
        hash_text(identity)
        raw = read_file(self.state, "archives/" + identity + ".zip", MAX_ARCHIVE)
        manifest, files = verify(raw, identity)
        return manifest, files

    def cache(self, raw, identity):
        path = self.state / "archives" / (hash_text(identity) + ".zip")
        if path.exists():
            self.archive(identity)
        else:
            require(len(list((self.state / "archives").iterdir())) < 16,
                    "retained archive quota reached; preserve and review management state")
            write_new(path, raw)

    def installed_files(self, identity):
        manifest, files = self.archive(identity)
        return {**files, MANIFEST: canonical(manifest), RECEIPT: canonical({
            "schema_version": 1, "installation_id": self.meta["installation_id"],
            "archive_sha256": identity})}

    def inventory(self, path, expected, partial=False):
        directory(path)
        seen, seen_dirs = set(), set()
        allowed_dirs = {"/".join(n.split("/")[:i]) for n in expected
                        for i in range(1, len(n.split("/")))}
        for parent, dirs, files in os.walk(path, followlinks=False):
            relative = Path(parent).relative_to(path)
            for child in dirs:
                folder = Path(parent) / child
                directory(folder)
                name = folder.relative_to(path).as_posix()
                require(name in allowed_dirs, "unmanaged directory; preserve local data")
                seen_dirs.add(name)
            for child in files:
                name = (relative / child).as_posix()
                require(name in expected and len(seen) < MAX_FILES + 2,
                        "unmanaged file; preserve local data")
                info = regular(path / name)
                require(info.st_nlink == 1, "hard-linked installation content is not managed")
                actual = read_file(path, name, MAX_FILE)
                require(actual == expected[name], "managed file changed; preserve local edits")
                seen.add(name)
        require(partial or (seen == set(expected) and seen_dirs == allowed_dirs),
                "managed installation is incomplete")
        return seen, seen_dirs

    def clean(self, path, expected, partial=False):
        """Only unlink a freshly verified finite inventory; never recursive-delete."""
        if not path.exists():
            require(not path.is_symlink(), "linked transaction path")
            return
        require(path.parent == self.root and path != self.root and path != self.target,
                "cleanup is limited to the transaction's owned staging/backup directory")
        files, dirs = self.inventory(path, expected, partial)
        for name in sorted(files):
            require(read_file(path, name, MAX_FILE) == expected[name], "cleanup content changed")
            (path / name).unlink()
        for name in sorted(dirs, key=lambda n: (n.count("/"), n), reverse=True):
            directory(path / name)
            (path / name).rmdir()
        path.rmdir()

    def populate(self, path, expected):
        require(path.parent == self.root and not path.exists() and not path.is_symlink(),
                "staging path already exists")
        path.mkdir(mode=0o700)
        for name, data in sorted(expected.items()):
            dest = path / name
            dest.parent.mkdir(parents=True, exist_ok=True)
            directory(dest.parent)
            write_new(dest, data)
        self.inventory(path, expected)

    def current(self, expected=None):
        if not self.target.exists():
            require(not self.target.is_symlink(), "linked installation path")
            require(expected is None, "expected managed installation is missing")
            return None
        directory(self.target)
        receipt = parse(read_file(self.target, RECEIPT, MAX_FILE))
        fields(receipt, ("schema_version", "installation_id", "archive_sha256"))
        require(receipt["schema_version"] == 1 and receipt["installation_id"] == self.meta["installation_id"],
                "installation is not owned by this manager")
        identity = hash_text(receipt["archive_sha256"])
        require(expected is None or identity == hash_text(expected), "installed archive identity differs")
        self.inventory(self.target, self.installed_files(identity))
        return identity

    def journal(self):
        journal = self.record("transaction.json")
        fields(journal, ("schema_version", "id", "operation", "old", "new"))
        require(type(journal["schema_version"]) is int and journal["schema_version"] == 1
                and isinstance(journal["id"], str) and re.fullmatch(r"[a-f0-9]{32}", journal["id"])
                and journal["operation"] in ("install", "update", "uninstall"), "invalid recovery record")
        for key in ("old", "new"):
            if journal[key] is not None:
                hash_text(journal[key])
        require((journal["operation"] == "install" and journal["old"] is None and journal["new"] is not None)
                or (journal["operation"] == "update" and journal["old"] is not None and journal["new"] is not None)
                or (journal["operation"] == "uninstall" and journal["old"] is not None and journal["new"] is None),
                "invalid recovery transition")
        return journal

    def paths(self, journal):
        return (self.root / (".cybersecurity-stage-" + journal["id"]),
                self.root / (".cybersecurity-backup-" + journal["id"]))

    def restore_path(self, journal):
        return self.root / (".cybersecurity-restore-" + journal["id"])

    def status(self):
        with self.locked():
            pending = self.journal() if (self.state / "transaction.json").exists() else None
            current = self.current()
            return {"installed_archive_sha256": current, "pending_transaction": pending,
                    "freshness_verified": False, "security_verdict": "not_established"}

    def change(self, operation, archive_path=None, expected_sha256=None, expected_installed=None):
        require(operation in ("install", "update", "uninstall"), "unsupported package operation")
        new = None
        if operation != "uninstall":
            raw, _, _ = read_archive(archive_path, expected_sha256)
            new = expected_sha256
        with self.locked():
            require(not (self.state / "transaction.json").exists(), "pending operation requires explicit recovery")
            if operation == "install":
                require(not self.target.exists() and not self.target.is_symlink(), "skill destination already exists")
                old = None
            else:
                hash_text(expected_installed)
                old = self.current(expected_installed)
            if new is not None:
                self.cache(raw, new)
            journal = {"schema_version": 1, "id": uuid.uuid4().hex, "operation": operation, "old": old, "new": new}
            stage, backup = self.paths(journal)
            restore = self.restore_path(journal)
            require(all(not path.exists() and not path.is_symlink() for path in (stage, backup, restore)),
                    "transaction paths already exist")
            write_new(self.state / "transaction.json", canonical(journal))
            if new is not None:
                self.populate(stage, self.installed_files(new))
            if old is not None:
                self.current(old)
                self.target.rename(backup)
            if new is not None:
                require(not self.target.exists() and not self.target.is_symlink(), "destination appeared during operation")
                stage.rename(self.target)
                self.current(new)
            if old is not None:
                self.clean(backup, self.installed_files(old))
            (self.state / "transaction.json").unlink()
            return {"operation": operation, "installed_archive_sha256": new,
                    "previous_archive_sha256": old, "original_assessment_data": "not_accessed",
                    "freshness_verified": False, "security_verdict": "not_established"}

    def recover(self, transaction_id):
        with self.locked():
            journal = self.journal()
            require(transaction_id == journal["id"], "recovery requires the exact pending transaction ID")
            stage, backup = self.paths(journal)
            restore = self.restore_path(journal)
            old, new = journal["old"], journal["new"]
            current = self.current()
            require(current in (None, old, new), "installation changed outside the pending operation")
            # Validate every remaining owned byte before changing any directory.
            if stage.exists() or stage.is_symlink():
                require(new is not None, "unexpected uninstall staging content")
                self.inventory(stage, self.installed_files(new), partial=True)
            if backup.exists() or backup.is_symlink():
                require(old is not None, "unexpected installation backup")
                self.inventory(backup, self.installed_files(old), partial=True)
            if restore.exists() or restore.is_symlink():
                require(old is not None, "unexpected restoration staging content")
                self.inventory(restore, self.installed_files(old), partial=True)
            if restore.exists():
                self.clean(restore, self.installed_files(old), partial=True)
            if current is not None:
                if stage.exists():
                    self.clean(stage, self.installed_files(new), partial=True)
                if backup.exists():
                    self.clean(backup, self.installed_files(old), partial=True)
                outcome = "completed" if current == new else "rolled_back"
            else:
                if stage.exists():
                    self.clean(stage, self.installed_files(new), partial=True)
                if old is not None:
                    self.populate(restore, self.installed_files(old))
                    restore.rename(self.target)
                    self.current(old)
                if backup.exists():
                    self.clean(backup, self.installed_files(old), partial=True)
                current, outcome = old, "rolled_back"
            (self.state / "transaction.json").unlink()
            return {"recovery": outcome, "installed_archive_sha256": current,
                    "freshness_verified": False, "security_verdict": "not_established"}
