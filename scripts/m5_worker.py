#!/usr/bin/env python3
"""M1-only offline disposable SQLite integrity/restore/rollback worker."""

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from security_runtime.common import canonical, parse, portable_tree, read_file, require
from security_assessment.resilience_data import exercise


def main():
    try:
        require(sys.argv[1:] == ["sqlite"], "unsupported operation")
        inputs = Path("/inputs")
        files = portable_tree(inputs)
        require(len(files) <= 32, "too many inputs")
        value = parse(read_file(inputs, "m5-contract.json", 32768), 32768)
        output = exercise(inputs, Path("/tmp/m5-restore"), value)
        output["files"] = files
        print(canonical(output).decode(), flush=True)
        return 0
    except Exception:
        print('{"status":"blocked","reason":"Unsupported, inconsistent or unavailable SQLite inputs."}', flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
