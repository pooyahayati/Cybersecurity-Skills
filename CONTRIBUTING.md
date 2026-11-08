# Contributing

Read `AGENTS.md`, `STATUS.md` and the relevant roadmap milestone first. Keep skill
instructions and documentation in precise English. Prefer a small reviewable
change that closes an acceptance criterion over adding speculative features.

## Local checks

Use an existing Python 3.11+ interpreter. The controller uses only the standard
library; there is no dependency installation step.

```bash
python scripts/validate_project.py
python -m unittest discover -s tests -v
python -B tests/m2_workflow.py
python -B tests/docker_integration.py --docker /absolute/path/to/docker
git diff --check
```

On Windows, use the full path to an actual interpreter if `python` resolves to a
nonfunctional application alias. Tests create temporary fixture copies in the OS
temporary directory and do not modify the checked-out project or access a target.
The real Docker suite requires a running local Linux daemon and registry access;
it fails rather than skips if isolation is unavailable. It creates synthetic
snapshots and only its own labeled containers. Unit tests do not need Docker or
network access. Run hard-link/symlink tests in a host context that permits their
creation; Linux CI must exercise them without a skip. Windows may need Developer
Mode or appropriate symlink privileges for the existing symlink fixture.

The M2 CLI workflow tests source-only, URL-only and combined intake, reporting,
unchanged target bytes, secret canaries and invalidation. The real Docker suite
also imports an actual M1 operation into M2 and rejects invented provenance.
Neither measures application vulnerability-detection accuracy. Keep new catalog,
evidence-binding and redaction checks behavioral: verify the prohibited effect
and a relevant legitimate path, not merely a helper's internal representation.

The validator checks this project's intentionally limited metadata format and
relative file references. It is not a general YAML/JSON Schema validator, a
security scanner, a freshness verifier, or an OS isolation boundary. Keep the
input tree stable while validating; concurrent filesystem replacement is outside
this helper's protection. See `docs/EVALUATION.md` for behavioral qualification.

## Module changes

Keep module IDs stable, reference an existing in-package guidance file, and
describe concrete activation evidence and required inputs. External source
entries remain candidates until their adapter, license review, compatibility
assessment and tests are implemented. A catalog flag must not silently activate
code or grant permissions.

Do not copy an upstream skill wholesale. Record exact adopted paths and revision,
applicable license and changes in `THIRD_PARTY_NOTICES.md` when adoption occurs.
Policy selects current stable components; reproducible execution receipts record
exact resolved revisions outside the product tree.

## Pull requests

Explain the observable problem, resulting behavior, relevant checks, capability
limits and any changed trust boundary. Keep generated scans and receipts private.
Do not include real secrets in examples or attach customer data to an issue.

CI pins third-party Actions to reviewed commit SHAs. Review an upstream update,
resolve the current official release, update its immutable identity and rerun
checks. This development CI pin is distinct from a runtime latest-version policy.
Do not add scheduled jobs or auto-merge changes merely to keep a version label fresh.
