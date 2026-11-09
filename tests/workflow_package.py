"""Test-only explicit artifact selection, inherited by owned child fixtures.

The caller verifies and installs the archive before selecting this root. This is
test routing, not publisher authentication or a production execution authority.
"""

import atexit
import hashlib
import json
import os
from pathlib import Path
import sys


SOURCE = Path(__file__).resolve().parents[1]


def selected_root():
    value = os.environ.get("CYBER_TEST_PACKAGE_ROOT")
    if value is None:
        return SOURCE
    path = Path(value)
    if not path.is_absolute() or path != path.resolve(strict=True) or path == SOURCE:
        raise RuntimeError("installed test root must be a separate canonical absolute directory")
    # A test must not silently execute checkout modules or altered installed code.
    manifest = json.loads((path / "PACKAGE.json").read_text(encoding="utf-8"))
    expected = os.environ.get("CYBER_TEST_MANIFEST_SHA256")
    if not expected or hashlib.sha256((path / "PACKAGE.json").read_bytes()).hexdigest() != expected:
        raise RuntimeError("installed test manifest identity differs")
    for name, item in manifest["files"].items():
        target = (path / name).resolve(strict=True)
        if not target.is_relative_to(path) or target.is_symlink():
            raise RuntimeError("installed test member escaped its package")
        if hashlib.sha256(target.read_bytes()).hexdigest() != item["sha256"]:
            raise RuntimeError("installed test bytes differ")
    return path


ROOT = selected_root()
sys.path.insert(0, str(ROOT / "scripts"))


def assert_product_imports():
    modules = {name: Path(module.__file__).resolve() for name, module in tuple(sys.modules.items())
               if (name == "security_runtime" or name.startswith("security_runtime.")
                   or name == "security_assessment" or name.startswith("security_assessment."))
               and getattr(module, "__file__", None)}
    if any(not path.is_relative_to(ROOT / "scripts") for path in modules.values()):
        # Exceptions in atexit do not change exit status. Explicitly fail the child.
        os._exit(3)
    output = os.environ.get("CYBER_TEST_IMPORT_RECEIPT")
    if output:
        # Worker processes get their own receipt and cannot overwrite the parent.
        Path(output + "." + str(os.getpid()) + ".json").write_text(json.dumps({
            "package_root": str(ROOT), "modules": {n: str(p) for n, p in sorted(modules.items())}
        }, indent=2) + "\n", encoding="utf-8")


atexit.register(assert_product_imports)
