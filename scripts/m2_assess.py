#!/usr/bin/env python3
"""Offline discovery, evidence and redacted reports. Never scan a URL or run target code."""

import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from security_runtime.common import parse, read_file
from security_runtime.store import Store
from security_assessment.service import Assessment


def document(path):
    path = Path(path).absolute()
    return parse(read_file(path.parent, path.name, 1024 * 1024), 1024 * 1024)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, required=True)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("init")
    commands.add_parser("create").add_argument("file", type=Path)
    for name in ("observe", "import-operation", "coverage", "finding", "decide", "link", "refresh"):
        command = commands.add_parser(name)
        command.add_argument("assessment")
        command.add_argument("file", type=Path)
    for name in ("plan", "report"):
        commands.add_parser(name).add_argument("assessment")
    command = commands.add_parser("invalidate")
    command.add_argument("assessment")
    command.add_argument("evidence")
    command.add_argument("file", type=Path, help="Private JSON object containing a reason")
    # Parse errors must not echo arguments: callers may accidentally paste a secret.
    try:
        parser.error = lambda _message: (_ for _ in ()).throw(ValueError("invalid command"))
        args = parser.parse_args(argv)
        package = Path(__file__).resolve().parents[1]
        store = Store(args.state, package, initialize=args.command == "init")
        control = Assessment(store, package)
        if args.command == "init": result = {"status": "initialized"}
        elif args.command == "create": result = control.create(document(args.file))
        elif args.command == "plan": result = control.report(args.assessment)
        elif args.command == "report": result = control.write_report(args.assessment)
        elif args.command == "invalidate":
            value = document(args.file)
            from security_runtime.common import fields
            fields(value, {"reason"})
            result = control.invalidate(args.assessment, args.evidence, value["reason"])
        else:
            method = {"observe": "record", "import-operation": "record", "finding": "add_finding"}.get(args.command, args.command)
            parameters = {"controller": True} if args.command == "import-operation" else {}
            result = getattr(control, method)(args.assessment, document(args.file), **parameters)
    except KeyboardInterrupt:
        print(json.dumps({"status": "blocked", "code": "INTERRUPTED", "reason": "Operation interrupted; inspect private state before retrying."}))
        return 130
    except Exception:
        print(json.dumps({"status": "blocked", "code": "INVALID_OR_UNAVAILABLE", "reason": "Input, scope or evidence is invalid or unavailable. No security success is claimed."}))
        return 1
    print(json.dumps(result, ensure_ascii=True, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
