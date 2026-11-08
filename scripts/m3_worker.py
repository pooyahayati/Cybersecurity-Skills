#!/usr/bin/env python3
"""M1-isolated static inspection or explicitly authorized Python probe execution."""

from pathlib import Path
import runpy
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from security_runtime.common import canonical, fields, parse, portable_tree, read_file, relpath, require
from security_assessment.source_rules import inspect_sources


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    root = Path("/inputs")
    if args == ["inspect"]:
        manifest = portable_tree(root)
        result = inspect_sources({path: read_file(root, path, 1024 * 1024) for path in manifest})
    else:
        require(len(args) == 3 and args[0] == "probe", "invalid worker operation")
        entry = relpath(args[1])
        require(entry.endswith(".py"), "only Python probe entrypoints are supported")
        request = parse(args[2], 3072)
        fields(request, {"request", "state"})
        read_file(root, entry, 1024 * 1024)
        # This branch executes target code, and MUST only be used in the M1
        # container. Import, startup and function execution share that boundary.
        namespace = runpy.run_path(str(root / entry), run_name="_security_probe")
        response = namespace["security_probe"](request["request"], request["state"])
        result = {"response": response, "state": request["state"]}
    sys.stdout.buffer.write(canonical(result) + b"\n")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception:
        # Target tracebacks can contain secrets. Failed output never qualifies.
        sys.stdout.write('{"status":"blocked"}\n')
        raise SystemExit(1)
