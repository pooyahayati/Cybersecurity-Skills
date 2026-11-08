# M3 operator flow

The agent prepares these records from inspected evidence; the novice developer
should receive decisions, impact, limitations and concrete next steps, not a demand
to author JSON. All request files, targets, candidates, state and reports below are
private and outside this repository. Examples use placeholders, not real customers.

Read [M1 operations](M1-OPERATIONS.md), [M2 intake](M2-OPERATIONS.md) and the
[M3 contracts](M3-SOURCE-REMEDIATION.md). M1's current head, tool and runtime are
mandatory. There is no offline stale fallback or host execution fallback.

## 1. Create the case and select current components

```bash
python -I -B scripts/m3_review.py --state /private/control init
python -I -B scripts/m3_review.py --state /private/control create /private/scope.json
```

`scope.json` uses the M2 schema: exact source root/files/revision, deployments,
actors/assets/flows/capabilities and sensitive literals. URL-only scope can be
recorded, but M3 source operations remain blocked without source access.

Enroll a tool component named `m3` from this project's same verified publisher
identity as `config/head-source.json`, with `kind: tool`, `include: ["scripts"]`,
`asset: null`, bounded download/unpacked sizes and `data_max_age_seconds: null`.
Do not copy synthetic publisher identities from tests. Prepare, review and activate
the current `head`, `runtime` and `m3` candidates through M1. The full selected
script manifest must equal the executing installed package. Local unpublished edits
cannot pass a public current-head preflight; fixture publishers are tests only.

Optionally enroll `addy-hardening` as `kind: skill` from its official numeric
repository/owner identities with `include` containing `LICENSE`,
`skills/security-and-hardening` and only supporting resources actually needed and
reviewed. M1 acquisition does not install it globally. Never auto-enable a catalog.
For dependency review, also enroll the chosen authoritative advisory snapshot as
`kind: data` with an explicit age limit; matching versions/advisories needs review.

## 2. Inspect source without executing it

Prepare M1 authorization for the exact full case source root/files, component
`m3`, `network: none` and bounded resource/call/time limits. The static operation is:

```json
{
  "id": "source-inspection",
  "component": "m3",
  "entrypoint": "scripts/m3_worker.py",
  "interpreter": "python",
  "arguments": ["inspect"],
  "timeout_seconds": 30,
  "max_output_bytes": 1048576
}
```

Run M1 `authorize`, `begin` and `execute` as documented there. Retain the actual
operation ID, then import it using a private JSON object with `id` and `operation`:

```bash
python -I -B scripts/m3_review.py --state /private/control scan case-id /private/scan-import.json
python -I -B scripts/m3_review.py --state /private/control plan case-id
```

Importing arbitrary scanner JSON is unsupported. A valid scan still produces
only leads. Select source files deliberately; do not run the worker directly on
the host to bypass unavailable isolation.

## 3. Record multi-angle review and findings

`trace case-id /private/trace.json` accepts exactly:

```json
{
  "id": "owner-review",
  "run": "ACTUAL_READY_M1_RUN_ID",
  "adapter": "builtin-review",
  "domain": "identity",
  "actor": "owner",
  "assets": ["records"],
  "locations": [{"path": "app.py", "line": 1}],
  "entrypoint": "Describe the actual route or function.",
  "untrusted_input": "Describe the request and caller-controlled identifier.",
  "guard": "Describe the observed owner/tenant guard or its absence.",
  "sink": "Describe the protected read/write.",
  "abuse_case": "Describe another customer's attempted operation.",
  "counterevidence": "Record inspected middleware and alternative explanations.",
  "conclusion": "inconclusive",
  "next_step": "State the concrete missing evidence or safe correction.",
  "dependency": null
}
```

Use `supported_issue`, `no_issue_observed` or `inconclusive`; none is an overall
pass. Domains are `architecture`, `application`, `identity`, `data`, `business`,
`dependencies`, `secrets`. The active M1 run must cover the full case input. For
`addy-hardening`, that component must also be bound to the run. Dependency traces
replace null with `package`, `ecosystem` (`npm`, `pypi`, `composer`), exact `version`,
`lock_path`, selected `advisory_component` and `advisory_reference`; cite the lockfile
in locations. All free text is attributed operator reasoning.

Record M2 `observe` and `finding` through **m3_review.py**, using the same M2 schemas.
Source reasoning must cite current files/control/actor and required asset/flow
context. Explain impact, uncertainty, counterevidence, priority and legitimate
behavior to preserve. Confirm only supported findings; a raw lead is insufficient.
`evidence-report case-id` returns the M2 controls/findings for this M3 case.
The M2-compatible `decide`, `coverage` and `link` commands also accept their M2
request schemas. Correct or retract a finding through `decide`; invalidate evidence
with `invalidate case-id evidence-id /private/reason.json`, where the file contains
only `reason`. These routes preserve decision history. M3 does not support in-place
scope/context refresh; create a new case for changed roles, assets or source.

## 4. Propose and inspect a scoped fix

`propose case-id /private/proposal.json` accepts `id`, `finding`, `rationale`,
`replacements` and `behavior`. Each replacement has a selected `path`, exact
`before_sha256` and new UTF-8 `content`. The finding must be confirmed, on source,
with currently valid supporting evidence. No additions, deletions or out-of-scope
paths are silently introduced.

`behavior` has `entrypoint`, `oracle_basis`, `limitations`, and `cases`. Each case
has `id`, `kind` (`legitimate`, `denied`, `variant`), declared `actor` (`anonymous`,
`owner`, `non-owner`, `cross-tenant`, `low-privilege`, `service`), `request`, object
`state`, `expected: {"response": ..., "state": ...}` and `forbidden_response`
(null for legitimate cases). Denied and variant cases require distinct requests,
unchanged expected state and a distinct concrete forbidden response.

The selected Python entrypoint defines `security_probe(request, state)` and returns
the response while mutating the supplied synthetic state, if appropriate. This
is an explicit serialized-model test interface, not a generic application runner.
Inspect the adapter and subject for output spoofing; real database verification is
unsupported. Existing projects need an authorized, reviewed test seam before this
adapter can be used; do not alter acceptance expectations to fit current behavior.

```bash
python -I -B scripts/m3_review.py --state /private/control propose case-id /private/proposal.json
python -I -B scripts/m3_review.py --state /private/control export case-id fix-id /private/new-candidate
```

The destination must not exist and must be disjoint from source, state and package.
Review candidate versus original; the original is not modified. Keep exported
candidates private, including on multi-user hosts. M1 captures them read-only.

## 5. Execute original and candidate cases through M1

For each case, generate the exact operation with the same component, entrypoint
and interpreter as static inspection, but arguments:

```json
["probe", "app.py", "{\"request\":{...},\"state\":{...}}"]
```

The third argument must be the canonical JSON representation of that case's
request/state: sorted keys, compact separators, UTF-8, no non-finite numbers.
`security_runtime.common.canonical` generates these bytes. Do not use a shell to
compose or execute target text. Authorize the full original selection for baseline
and the full exported candidate selection for candidate runs, with sufficient
bounded call/time budgets. Run each through M1; no host imports or direct worker
execution. The probe branch intentionally executes target Python in isolation.

Import each actual operation with `test case-id /private/test-import.json`:

```json
{
  "proposal": "fix-id",
  "case": "case-name",
  "variant": "original",
  "operation": "ACTUAL_COMPLETED_OPERATION_ID",
  "root": null
}
```

For `variant: candidate`, supply the canonical exported directory in `root`.
Every case requires both variants; failed/missing observations do not qualify.
Tests cannot be overwritten. A new patch or changed test contract needs a new
proposal. The initial forbidden effect, all candidate outcomes, exact resources
and protected-state expectations are rechecked before acceptance and reporting.

## 6. Review the bounded result

`accept case-id /private/acceptance.json` takes `proposal`, `reviewer`, `reason`,
`oracle_review` and `residual_risk`. Explain the actual code/oracle review, not a
copied pass message. Missing/failed cases block acceptance even with this record.
Acceptance means only `accepted_for_declared_model`, never deployed remediation.

```bash
python -I -B scripts/m3_review.py --state /private/control report case-id
```

The command returns private JSON/Markdown basenames. Inspect the reports and the
M2 evidence report together. Apply an accepted candidate only through separately
authorized project changes, then recapture and test the actual resulting source.
Keep production verification, unsupported languages/frameworks and untested paths
explicitly pending. Do not interpret a retained historical test match as current
eligibility when its input, finding, authority or data has become invalid.
