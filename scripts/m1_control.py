#!/usr/bin/env python3
"""Manage reviewed current components and bounded offline execution (M1)."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import sys

# Support isolated Python (-I); only this trusted package may supply controller code.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from security_runtime.common import Blocked, parse, read_file, require
from security_runtime.controller import Controller
from security_runtime.sandbox import Docker
from security_runtime.sources import GitHub, Http
from security_runtime.store import Store


def document(path):
    path = Path(path).absolute()
    return parse(read_file(path.parent, path.name))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", required=True, type=Path, help="Private directory outside package and targets")
    parser.add_argument("--docker", type=Path, help="Absolute path to the trusted Docker executable")
    parser.add_argument("--docker-endpoint", help="Local socket only; never a remote Docker host")
    parser.add_argument("--token-env", help="Explicit environment variable for an optional GitHub read token")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("init")
    for name in ("enroll", "review", "authorize"):
        sub.add_parser(name).add_argument("file", type=Path)
    sub.add_parser("prepare").add_argument("component")
    sub.add_parser("activate").add_argument("candidate")
    for name in ("begin", "resume"):
        sub.add_parser(name).add_argument("authorization")
    execute = sub.add_parser("execute")
    execute.add_argument("run")
    execute.add_argument("operation")
    sub.add_parser("cancel").add_argument("run")
    revoke = sub.add_parser("revoke").add_mutually_exclusive_group(required=True)
    revoke.add_argument("--component")
    revoke.add_argument("--authorization")
    sub.add_parser("recover")
    inspect = sub.add_parser("inspect")
    inspect.add_argument("kind", choices=("candidate", "review", "operation", "run", "authorization"))
    inspect.add_argument("id")
    args = parser.parse_args(argv)
    try:
        package = Path(__file__).resolve().parents[1]
        store = Store(args.state, package, initialize=args.command == "init")
        token = None
        if args.token_env:
            require(re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", args.token_env), "invalid token variable name")
            token = os.environ.get(args.token_env)
            require(isinstance(token, str) and bool(token) and "\n" not in token and "\r" not in token,
                    "explicit token variable is unavailable")
        require(not args.docker_endpoint or args.docker is not None, "Docker endpoint needs an executable")
        if args.docker:
            require(args.docker.is_absolute(), "Docker executable must use an absolute path")
        docker = Docker(args.docker, store, args.docker_endpoint) if args.docker else None
        control = Controller(store, package, GitHub(Http(token)), docker)
        if args.command == "init":
            result = {"status": "initialized", "operational_assessment": False}
        elif args.command in ("enroll", "review", "authorize"):
            result = getattr(control, args.command)(document(args.file))
        elif args.command == "prepare":
            result = control.prepare(args.component)
        elif args.command == "activate":
            result = control.activate(args.candidate)
        elif args.command in ("begin", "resume"):
            result = control.begin(args.authorization)
        elif args.command == "execute":
            result = control.execute(args.run, args.operation)
        elif args.command == "cancel":
            result = control.cancel(args.run)
        elif args.command == "revoke":
            result = control.revoke(args.component, args.authorization)
        elif args.command == "recover":
            result = control.recover()
        else:
            result = store.get(args.kind, args.id)
            require(result is not None, "record is unavailable")
    except KeyboardInterrupt:
        print(json.dumps({"status": "blocked", "reason": "interrupted; recover unfinished operations"}))
        return 130
    except Exception as exc:
        # Never echo untrusted source content, raw tool output, tokens or exception URLs.
        reason = str(exc) if isinstance(exc, Blocked) else "invalid or unavailable input; operation blocked"
        print(json.dumps({"status": "blocked", "reason": reason}))
        return 1
    print(json.dumps(result, indent=2, ensure_ascii=True, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
