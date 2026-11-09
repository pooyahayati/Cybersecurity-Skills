#!/usr/bin/env python3
"""Print a complete offline checklist plan; never scan, install or assess a target."""

import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from security_assessment.checklist import load_catalog, markdown_plan, plan


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("validate", "plan"))
    parser.add_argument("--format", choices=("json", "markdown"), default="json")
    try:
        parser.error = lambda _message: (_ for _ in ()).throw(ValueError("invalid command"))
        args = parser.parse_args(argv)
        catalog = load_catalog(Path(__file__).resolve().parents[1])
        if args.command == "validate":
            if args.format != "json":
                raise ValueError("validation has JSON output only")
            result = {"result": "structure_valid", "scope": "checklist_catalog_only", "controls": 36,
                      "assessment_performed": False, "freshness_verified": False}
        else:
            result = plan(catalog)
            if args.format == "markdown":
                print(markdown_plan(result), end="")
                return 0
    except Exception:
        print('{"result":"blocked","assessment_performed":false,"reason":"Invalid or unavailable checklist resources; no assessment outcome is established."}')
        return 1
    print(json.dumps(result, ensure_ascii=True, allow_nan=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
