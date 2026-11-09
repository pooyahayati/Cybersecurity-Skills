"""Owned package fixtures; all lifecycle mutations stay in a disposable root."""

from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from security_runtime.package import ROOT_DIRS, ROOT_FILES, assemble, selected


def payload():
    files = {name: (ROOT / name).read_bytes() for name in ROOT_FILES}
    for folder in ROOT_DIRS:
        for path in (ROOT / folder).rglob("*"):
            if path.is_file() and "__pycache__" not in path.parts and path.suffix not in (".pyc", ".pyo"):
                name = path.relative_to(ROOT).as_posix()
                selected(name)
                files[name] = path.read_bytes()
    return files


class World:
    def __init__(self, files):
        self.temp = tempfile.TemporaryDirectory(prefix="cyber-m6-test-")
        self.root = Path(self.temp.name).resolve(strict=True)
        self.skills = self.root / "skills"
        self.skills.mkdir()
        self.state = self.root / "private-manager"
        self.files = files
        self.old = self.root / "old.zip"
        self.old.write_bytes(assemble(files, "1" * 40))
        self.new = self.root / "new.zip"
        self.new.write_bytes(assemble({**files, "docs/m6-owned-fixture.txt": b"reviewed successor\n"}, "2" * 40))

    def close(self):
        self.temp.cleanup()
