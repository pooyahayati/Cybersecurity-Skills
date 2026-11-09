#!/usr/bin/env python3
"""Bounded M5 workloads, disposable recovery and evidence-preserving incident triage."""

import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from m2_assess import document
from security_assessment.resilience import ResilienceReview
from security_runtime.common import read_file, require
from security_runtime.private import private_directory
from security_runtime.sandbox import Docker
from security_runtime.store import Store


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--docker", type=Path)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("init")
    commands.add_parser("create").add_argument("file", type=Path)
    methods = {"load-authorize": "load_authorize", "recovery-plan": "recovery_plan", "artifact": "import_artifact", "acknowledge": "acknowledge", "incident": "incident", "authorize": "web_authorize", "infrastructure": "import_infrastructure", "container": "inspect_container",
        "compare": "compare", "release-check": "release_check", "runtime-evidence": "import_runtime_evidence",
        "observe": "record", "finding": "add_finding", "decide": "decide", "coverage": "coverage", "link": "link",
        "source-scan": "import_scan", "trace": "trace", "propose": "propose", "test": "test", "accept": "accept"}
    for name in methods:
        command = commands.add_parser(name)
        command.add_argument("assessment")
        command.add_argument("file", type=Path)
    for name in ("plan", "report", "evidence-report", "source-report"):
        commands.add_parser(name).add_argument("assessment")
    commands.add_parser("cancel").add_argument("authorization")
    commands.add_parser("cancel-load").add_argument("authorization")
    command = commands.add_parser("load")
    for name in ("assessment", "authorization"): command.add_argument(name)
    command.add_argument("--credentials", type=Path)
    command.add_argument("--ca", type=Path)
    command = commands.add_parser("invalidate-resilience")
    for name in ("assessment", "kind", "id"): command.add_argument(name)
    command = commands.add_parser("request")
    for name in ("assessment", "authorization", "route"): command.add_argument(name)
    command.add_argument("--credentials", type=Path)
    command.add_argument("--ca", type=Path)
    command = commands.add_parser("invalidate-runtime")
    for name in ("assessment", "kind", "id"): command.add_argument(name)
    command = commands.add_parser("invalidate")
    command.add_argument("assessment")
    command.add_argument("evidence")
    command.add_argument("file", type=Path)
    command = commands.add_parser("export")
    command.add_argument("assessment")
    command.add_argument("proposal")
    command.add_argument("destination", type=Path)
    try:
        parser.error = lambda _message: (_ for _ in ()).throw(ValueError("invalid command"))
        args = parser.parse_args(argv)
        package = Path(__file__).resolve().parents[1]
        store = Store(args.state, package, initialize=args.command == "init")
        require(args.docker is None or args.docker.is_absolute(), "Docker path must be absolute")
        docker = Docker(args.docker, store) if args.docker else None
        control = ResilienceReview(store, package, docker=docker)
        if args.command == "init": result = {"status": "initialized"}
        elif args.command == "create": result = control.create(document(args.file))
        elif args.command in methods: result = getattr(control, methods[args.command])(args.assessment, document(args.file))
        elif args.command in {"request", "load"}:
            credentials, ca = None, None
            if args.credentials:
                path = args.credentials.absolute()
                require(path.is_relative_to(store.root), "credential file must be inside the disjoint private control directory")
                private_directory(path.parent)
                credentials = document(path)
            if args.ca:
                path = args.ca.absolute()
                ca = read_file(path.parent, path.name, 4096).decode("ascii")
            result = control.web_execute(args.assessment, args.authorization, args.route, credentials, ca) if args.command == "request" else control.load_execute(args.assessment, args.authorization, credentials, ca)
        elif args.command == "cancel-load": result = control.load.cancel(args.authorization)
        elif args.command == "invalidate-resilience": result = control.invalidate_resilience(args.assessment, args.kind, args.id)
        elif args.command == "cancel": result = control.web.cancel(args.authorization)
        elif args.command == "plan": result = control.resilience_report(args.assessment)
        elif args.command == "report": result = control.write_resilience_report(args.assessment)
        elif args.command == "source-report": result = control.write_source_report(args.assessment)
        elif args.command == "evidence-report": result = control.report(args.assessment)
        elif args.command == "invalidate-runtime": result = control.invalidate_runtime(args.assessment, args.kind, args.id)
        elif args.command == "export": result = control.export(args.assessment, args.proposal, args.destination)
        elif args.command == "invalidate":
            from security_runtime.common import fields
            value = document(args.file)
            fields(value, {"reason"})
            result = control.invalidate(args.assessment, args.evidence, value["reason"])
    except KeyboardInterrupt:
        print('{"status":"blocked","reason":"Interrupted; inspect retained intents before new authority."}')
        return 130
    except Exception:
        print('{"status":"blocked","reason":"Invalid, stale, out-of-scope or unavailable inputs/evidence. No security success is claimed."}')
        return 1
    print(json.dumps(result, ensure_ascii=True, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
