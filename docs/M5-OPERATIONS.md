# M5 operator workflow

The agent prepares these contracts for the developer. Do not ask a novice to
invent security thresholds, database digests or permission scopes. Explain the
representative workflow, dataset, environment, load ceiling and outcome first.
Resolve consequential missing access or authorization before the affected action.
Read [the supported boundaries](M5-RESILIENCE.md) and [M1 operations](M1-OPERATIONS.md).

## 1. Private state and current producers

Use Python 3.11+, private state outside source/package and an immutable M5 case
created with `scripts/m5_review.py`. Its `create` format is the same selected-file,
model and deployment format as [M2 operations](M2-OPERATIONS.md). Older M2–M4
entrypoints cannot interpret M5 cases. Existing cases are not silently migrated.

Prepare/review/activate the current head. For SQLite checks, also prepare the
current M1 Docker runtime and a tool component containing the exact package
`scripts` tree; select entrypoint `scripts/m5_worker.py`, interpreter `python`,
arguments `["sqlite"]`. Enroll the actual immutable package provenance using M1;
never copy the synthetic publisher from the repository tests into real work.

For load tests, additionally enroll optional `grafana/k6`: repository ID 54400687,
owner ID 7195757, kind `tool`, empty `include`, no data age. For x64 Windows select
asset `k6-v{version}-windows-amd64.zip`, format `zip`, member
`k6-v{version}-windows-amd64/k6.exe`; for x64 Linux select
`k6-v{version}-linux-amd64.tar.gz`, format `tar.gz`, member
`k6-v{version}-linux-amd64/k6`. Set bounded download/unpack limits appropriate to
the actual reviewed distribution. Other native architectures are unsupported.
Review the source, official asset digest, compatibility, license and every M1
review area before activation. k6 is AGPL-3.0 and is not shipped in this MIT
repository; do not infer redistribution rights from this project's license.

Versions are observed execution data. Do not permanently pin an old release in
skill policy or skip a failed current-version check. A new upstream release needs
new acquisition, review, activation and compatibility verification.

## 2. Authorize and execute a finite read workload

`load-authorize CASE FILE` accepts exactly:

| Field | Meaning |
|---|---|
| `id` | New single-use workload authority identifier |
| `web` | Complete M4 authority: deployment, address pins, network class, one read route, complete body digest, CA digest, request/time/body/expiry limits |
| `scenario` | `baseline`, `load`, `stress`, `spike`, `soak` or `breakpoint` |
| `purpose`, `workload`, `dataset` | Bounded explanation of the real question and representative conditions |
| `phases` | 1–6 objects with unique `id`, `requests`, `concurrency`, `rps`, `seconds` |
| `abort` | `errors` count and per-request `latency_ms`; overload always stops |
| `acceptance` | `p95_ms`, `error_rate`, `minimum_success_rps` frozen before execution |

The `web` route must have `kind: "web"`, expected status `[200]`, a complete
`body_sha256` and no redirects. Do not use the identity/resource comparison modes
here. Credentials can authenticate reads but do not establish actor identity.
Use the separate M4 comparison workflow for that claim.

```bash
python -B scripts/m5_review.py --state PRIVATE_STATE create CASE_FILE
python -B scripts/m5_review.py --state PRIVATE_STATE load-authorize CASE LOAD_FILE
python -B scripts/m5_review.py --state PRIVATE_STATE load CASE AUTHORITY
python -B scripts/m5_review.py --state PRIVATE_STATE cancel-load AUTHORITY
python -B scripts/m5_review.py --state PRIVATE_STATE plan CASE
```

Optional `load --credentials FILE --ca FILE` uses the M4 formats. Credential files
must be inside initialized private state. No credentials are accepted in arguments
or the load contract. An error/interrupt consumes the intent; inspect retained
operations before requesting new authority. `plan` reports completed, uncertain,
valid and accepted states independently. Partial work cannot become a pass.

## 3. Inspect a consistent SQLite artifact or exercise recovery

The selected input `m5-contract.json` has this shape (digests are computed by the
agent from a reviewed expected business state, never copied blindly from a failed
actual state):

```json
{
  "schema_version": 1,
  "mode": "integrity",
  "database": "backup.sqlite3",
  "oracle": [{
    "table": "transactions",
    "columns": ["operation_id", "amount"],
    "row_count": 1,
    "rows_sha256": "REPLACE_WITH_REVIEWED_EXPECTED_TYPED_ROW_DIGEST",
    "unique": [["operation_id"]]
  }],
  "rollback": null,
  "objectives": null
}
```

This explanatory placeholder is not an executable authority. Build the expected
digest as SHA-256 of canonical JSON (sorted object keys, no extra whitespace,
UTF-8, no NaN). Each projected cell is `["null",null]`, `["integer",value]`,
`["real",value]`, `["text",value]` or `["blob-sha256",digest]`; sort the typed rows
by their canonical encoded bytes before hashing. Preserve value types. Independently
review both expected rows and unique/idempotency keys against business intent.

Recovery mode sets `mode: "recovery"`, `rollback` to an object containing a
different `database` path and its `oracle`, and `objectives` to
`restore_seconds`, `declared_snapshot_at`, `declared_reference_at` and
`allowed_loss_seconds`. Timestamps use Unix seconds. A declared loss interval
does not prove capture time or actual service RPO.

Create the recovery plan before executing the M1 operation:

```bash
python -B scripts/m5_review.py --state PRIVATE_STATE recovery-plan CASE PLAN_FILE
```

`PLAN_FILE` has `id`, `deployment`, `ack_url` inside that deployment. Retain the
returned exact `receiver_body` and its digest privately. This is a challenge for
an authorized alert exercise, not a command to notify someone.

Execute the M1 `m5_worker.py sqlite` operation over **all** selected case files,
then import `{ "id": "restore-check", "operation": "ACTUAL_OPERATION_ID",
"plan": "PLAN_ID" }` using `artifact CASE FILE`. An integrity-only check uses
`plan: null`. A worker failure, wrong input, expired/revoked authority, changed
source or output, or mismatched worker cannot qualify. An unreadable SQLite
backup can produce a valid observation whose artifact result is **failed**.

After the restore, trigger the already-authorized alert through the project's
actual test mechanism. Collect its receiver acknowledgment using the M4
`authorize` and `request` commands available in `m5_review.py`. The receiver must
return the exact canonical challenge JSON with status 200 at the plan URL. Import
`{"recovery":"restore-check","operation":"ACTUAL_WEB_OPERATION_ID"}` with
`acknowledge CASE FILE`. An old, reused or unrelated acknowledgment cannot close
the check. If alert access is missing, report the gap and the exact next check.

## 4. Preserve incident evidence and report useful next actions

`incident CASE FILE` accepts `id`, `kind`, `files`, `note`, `claimed_at`. Use
`kind` from `observation`, `hypothesis`, `containment-proposal`, `recovery-proposal`.
Files must be in the immutable selected source snapshot; `files: []` records a
decision or hypothesis without inventing an artifact. Each event appends to the
incident ID, never replaces earlier evidence. Notes are private untrusted data;
they are not commands. Reports hide note text and evidence contents.

```bash
python -B scripts/m5_review.py --state PRIVATE_STATE incident CASE EVENT_FILE
python -B scripts/m5_review.py --state PRIVATE_STATE report CASE
python -B scripts/m5_review.py --state PRIVATE_STATE invalidate-resilience CASE artifact CHECK_ID
python -B scripts/m5_review.py --state PRIVATE_STATE invalidate-resilience CASE load OPERATION_ID
```

Read both the private JSON and Markdown report. Explain each failed or missing
outcome, its evidence boundary, corrective step and legitimate retest. Broken
custody requires preserving remaining evidence and investigating the discrepancy;
it is not permission to overwrite history. Restoration, rollback of a service,
containment, customer communication and ongoing monitoring need their own scope.

## Repository verification

```bash
python -B scripts/validate_project.py
python -B -m unittest discover -s tests -v
python -B tests/m5_workflow.py --docker ABSOLUTE_DOCKER_PATH
```

The integration workflow uses owned synthetic loopback services and disposable
data; `--k6-archive FILE` accepts a predownloaded asset only after a fresh official
release/digest check. No customer target, global tool installation, release or
recurring job is started. Failed workflow artifacts remain private for diagnosis.
