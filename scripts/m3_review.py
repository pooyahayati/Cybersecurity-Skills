#!/usr/bin/env python3
"""Scoped source review, private patch candidates and isolated-model retest evidence."""

import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from m2_assess import document
from security_runtime.store import Store
from security_assessment.remediation import SourceReview


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, required=True)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("init")
    commands.add_parser("create").add_argument("file", type=Path)
    for name in ("scan", "guidance", "trace", "propose", "test", "accept", "observe", "finding", "decide", "coverage", "link"):
        command = commands.add_parser(name)
        command.add_argument("assessment")
        command.add_argument("file", type=Path)
    for name in ("plan", "report", "evidence-report"):
        commands.add_parser(name).add_argument("assessment")
    command = commands.add_parser("export")
    command.add_argument("assessment")
    command.add_argument("proposal")
    command.add_argument("destination", type=Path)
    command = commands.add_parser("invalidate")
    command.add_argument("assessment")
    command.add_argument("evidence")
    command.add_argument("file", type=Path)
    try:
        parser.error = lambda _message: (_ for _ in ()).throw(ValueError("invalid command"))
        args = parser.parse_args(argv)
        package = Path(__file__).resolve().parents[1]
        control = SourceReview(Store(args.state, package, initialize=args.command == "init"), package)
        if args.command == "init": result = {"status": "initialized"}
        elif args.command == "create": result = control.create(document(args.file))
        elif args.command == "plan": result = control.source_report(args.assessment)
        elif args.command == "report": result = control.write_source_report(args.assessment)
        elif args.command == "evidence-report": result = control.report(args.assessment)
        elif args.command == "export": result = control.export(args.assessment, args.proposal, args.destination)
        elif args.command == "invalidate":
            from security_runtime.common import fields
            value = document(args.file)
            fields(value, {"reason"})
            result = control.invalidate(args.assessment, args.evidence, value["reason"])
        else:
            method = {"scan": "import_scan", "observe": "record", "finding": "add_finding"}.get(args.command, args.command)
            result = getattr(control, method)(args.assessment, document(args.file))
    except KeyboardInterrupt:
        print('{"status":"blocked","reason":"Interrupted; inspect private state before retrying."}')
        return 130
    except Exception:
        print('{"status":"blocked","reason":"Invalid, stale or unavailable scope, adapter or evidence. No security success is claimed."}')
        return 1
    print(json.dumps(result, ensure_ascii=True, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
