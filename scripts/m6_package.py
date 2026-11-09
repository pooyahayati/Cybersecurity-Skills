#!/usr/bin/env python3
"""Build/inspect reviewed skill packages; manage one explicitly selected install."""

import argparse
import json
from pathlib import Path
import subprocess
import sys
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
from security_runtime.common import Blocked
from security_runtime.package import build, read_archive
from security_runtime.package_lifecycle import Manager


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    subs = parser.add_subparsers(dest="command", required=True)
    builder = subs.add_parser("build", help="Package exact Git objects; worktree changes are excluded")
    builder.add_argument("--root", type=Path, required=True)
    builder.add_argument("--revision", required=True)
    builder.add_argument("--output", type=Path, required=True)
    inspect = subs.add_parser("inspect", help="Verify an independently reviewed archive digest; execute no code")
    inspect.add_argument("--archive", type=Path, required=True)
    inspect.add_argument("--sha256", required=True)
    for command in ("install", "update", "uninstall", "status", "recover"):
        sub = subs.add_parser(command)
        sub.add_argument("--skills-root", type=Path, required=True)
        sub.add_argument("--state", type=Path, required=True)
        if command in ("install", "update"):
            sub.add_argument("--archive", type=Path, required=True)
            sub.add_argument("--sha256", required=True)
        if command in ("update", "uninstall"):
            sub.add_argument("--expected-installed-sha256", required=True)
        if command == "recover":
            sub.add_argument("--transaction", required=True)
    try:
        parser.error = lambda _message: (_ for _ in ()).throw(Blocked("invalid package command; use --help"))
        args = parser.parse_args(argv)
        if args.command == "build":
            result = build(args.root, args.revision, args.output)
        elif args.command == "inspect":
            _, manifest, _ = read_archive(args.archive, args.sha256)
            result = {"archive_sha256": args.sha256, "manifest": manifest,
                      "integrity_verified": True, "freshness_verified": False,
                      "publisher_authenticated": False, "security_verdict": "not_established"}
        else:
            manager = Manager(args.state, args.skills_root, create=args.command == "install")
            if args.command == "status":
                result = manager.status()
            elif args.command == "recover":
                result = manager.recover(args.transaction)
            else:
                result = manager.change(args.command, getattr(args, "archive", None),
                    getattr(args, "sha256", None), getattr(args, "expected_installed_sha256", None))
        print(json.dumps({"result": "completed", **result}, indent=2))
        return 0
    except (Blocked, OSError, ValueError, KeyError, TypeError, UnicodeError,
            subprocess.SubprocessError, zipfile.BadZipFile) as exc:
        message = str(exc) if isinstance(exc, Blocked) else "package operation failed; inspect private state before retrying"
        print(json.dumps({"result": "blocked", "reason": message, "security_verdict": "not_established"}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
