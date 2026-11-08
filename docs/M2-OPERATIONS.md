# M2 intake, evidence and reports

M2 is an offline assessment ledger, not a vulnerability scanner. It reads selected
files, records supplied context, checks evidence bindings and produces useful
private reports. It does not fetch scoped URLs, execute project code, install
dependencies, apply fixes or authorize deployment. An agent prepares these records
for the developer and explains meaningful gaps in ordinary language.

## Prerequisites and starting point

Use trusted Python 3.11+ and the reviewed package. Keep a private state directory
outside this package and all targets. M2 reuses M1 authenticated SQLite state; an
existing M1 state may be reused without initialization. The trusted operator,
controller, host account and key boundary is unchanged. State authentication is
not proof that a human judgment is correct. Protect raw snapshots and the key.

```bash
python -I -B /path/to/skill/scripts/m2_assess.py --state /private/state init
python -I -B /path/to/skill/scripts/m2_assess.py --state /private/state create /private/scope.json
python -I -B /path/to/skill/scripts/m2_assess.py --state /private/state plan example
python -I -B /path/to/skill/scripts/m2_assess.py --state /private/state report example
```

Replace the paths and IDs with actual authorized values. Use absolute Windows
paths on Windows. `init` creates a new private state; it is not a reset command.
`plan` emits a sanitized JSON view. `report` writes a new `report-<random>.json`
and matching `.md` inside private state and returns only their generated basename.
Neither command publishes anything. CLI failures use a fixed sanitized response
and exit 1; they do not echo secret-bearing arguments, payloads or stack traces.

Run the complete, disposable synthetic example with:

```bash
python -B tests/m2_workflow.py
```

It exercises the real CLI, including allowed and rejected records. It is a test
of the ledger, not an assessment of a user's project. No Docker/network is needed.

## Scope record

All JSON contracts reject duplicate/unknown fields, invalid types and unsupported
schema versions. IDs use `[a-z][a-z0-9-]{0,63}`. Do not use a person's name, email,
credential or customer identifier as an ID. All timestamps are finite Unix UTC
seconds. Revisions are a lowercase 40-character Git hash, 64-character digest,
`sha256:` followed by a 64-character digest, or `null` when unknown.

```json
{
  "schema_version": 1,
  "id": "example",
  "source": {
    "root": "/absolute/authorized/project",
    "files": ["app.py", "pyproject.toml"],
    "revision": null
  },
  "deployments": [
    {"id": "preview", "environment": "staging", "url": "https://example.invalid/", "artifact": null}
  ],
  "model": {
    "actors": [{"id": "owner", "kind": "user", "trust": "external"}],
    "assets": [{"id": "records", "kind": "database", "classification": "sensitive", "revision": null}],
    "flows": [{"id": "read-record", "actor": "owner", "asset": "records", "direction": "read", "boundary": "client to application"}],
    "capabilities": {
      "authentication": {"state": "unknown", "basis": "Not yet corroborated."},
      "sensitive_data": {"state": "present", "basis": "Owner describes customer records; verify the implementation."},
      "transactions": {"state": "unknown", "basis": "Not yet examined."},
      "ai": {"state": "unknown", "basis": "Not yet examined."},
      "infrastructure": {"state": "unknown", "basis": "No configuration access established."},
      "delivery": {"state": "unknown", "basis": "No deployment evidence established."},
      "resilience": {"state": "unknown", "basis": "No recovery evidence established."}
    }
  },
  "redact_values": []
}
```

Set `source` to `null` for URL-only intake; set `deployments` to `[]` for source-only
intake. At least one must exist. No URL causes DNS, crawling or an HTTP request.
Only HTTP(S) scope with no user information, query or fragment is accepted. A
normalized address supplies neither access credentials nor execution authority.

| Context | Accepted values and meaning |
|---|---|
| Actor kind | `anonymous`, `user`, `administrator`, `service`, `unknown` |
| Actor trust | `external`, `internal`, `unknown`; operator declared |
| Asset kind | `database`, `file`, `service`, `queue`, `credential`, `dataset`, `unknown` |
| Asset classification | `public`, `internal`, `personal`, `sensitive`, `secret`, `unknown` |
| Asset revision | Optional immutable digest or null; useful for dataset/configuration changes |
| Flow direction | `read`, `write`, `exchange`, `unknown`; actor/asset IDs must resolve |
| Capability state | `present`, `absent`, `unknown`, with a nonempty basis; no automatic exclusion |
| Environment | `local`, `staging`, `production`, `unknown`; artifact remains declared |

Source capture accepts 1–256 explicit, portable relative paths, at most 1 MiB per
file and 16 MiB in total. Root, state and package must be disjoint. Links, hard
links, traversal, case collisions and reparse points fail. The selected immutable
snapshot is private; original files stay unchanged. Source revision labels and
deployed artifact labels are separate from the observed selected-file digest.

Discovery reads structured `package.json`, `package-lock.json`, `composer.json`,
`composer.lock` and `pyproject.toml`, plus a limited WordPress version assignment.
It does not import source or run package-manager commands. Manifest constraints,
lockfile declarations and source-version markers have distinct bases; none proves
the installed runtime version. Malformed or omitted manifests leave explicit gaps.
Aggregate fact limits do not imply absence of omitted dependencies. WordPress
hints need both a selected version marker and a recognized package declaration;
arbitrary README keywords cannot activate a module. AI SDK declarations establish
planning relevance, not a deployed AI feature.

Module routes are `relevant`, `needs_confirmation`, `exclusion_needs_evidence` or
`unknown`; every route remains `not_activated`. All partial control templates stay
visible. Their IDs are generated from template, surface, environment and actor.
Read IDs from `plan`; do not invent them. Access, applicability, review progress
and security outcome are different facts. The catalog maps selected chapters of
the numbered ASVS 5.0.0 publication, verified against its release tree on 2026-11-08;
the rolling `latest` artifact is labeled Bleeding Edge. This historical mapping
neither pins runtime tools nor asserts current/full standard compliance.

## Recording observations and coverage

```bash
python -I -B /path/to/skill/scripts/m2_assess.py --state /private/state observe example /private/observation.json
python -I -B /path/to/skill/scripts/m2_assess.py --state /private/state coverage example /private/coverage.json
```

An observation has exactly these fields:

| Field | Contract |
|---|---|
| `schema_version`, `id`, `control` | Version 1, new observation ID, generated control ID in this assessment |
| `method` | `design_review`, `source_reasoning`, `configuration_inspection`, `deployed_observation`; must match the control and surface |
| `actor` | Exact actor ID of the control, or null if the control has none |
| `files` | Selected relative paths; nonempty for source evidence, empty for other surfaces |
| `context_refs` | Unique `asset:<id>` / `flow:<id>` references; data/authorization controls need an asset when assets exist; business controls need a flow when flows exist |
| `summary` | Reviewer observation and limits, at most 4096 characters; never an instruction to the controller |
| `observed_at`, `expires_at` | Actual observation time, expiry after now and no more than 31 days after observation; at most 60 seconds of future clock tolerance |

Manual observations are always `operator_observation`. A reviewer can establish
a scoped source finding through a sufficient trace, but recording a statement is
not independent proof of its truth. The controller verifies references and
bindings, not the reasoning. Arbitrary `verified`, `passed` or producer flags fail.
Flow references automatically bind their actor and asset as dependencies.

A coverage record has exactly `schema_version`, `control`, `state`, `outcome`,
`reason`, and an array `evidence` of observation IDs. Progress is `not_started`,
`in_progress`, `reviewed`, `blocked`, or `not_applicable`. Unfinished progress must
use `unverified` and no evidence references. `reviewed` requires valid same-control
evidence and outcome `satisfied`, `failed` or `inconclusive`. `not_applicable`
requires evidence and the matching outcome; missing access cannot justify it.
A reviewed control may have failed. None of these states creates an overall pass.

## Importing an M1 execution

Use `import-operation` with the observation contract above, `method` set to
`controlled_reproduction`, and one additional `operation` ID returned by M1.
Set `observed_at` to the actual authenticated operation's `finished_at` value.
The M1 operator must obtain it from private authenticated state. Do not copy a
timestamp or success flag from target output. The state must contain the M1 run,
authorization, candidates and completed operation; JSON alone cannot supply them.

M2 checks the authorized target, specification, times, selected components,
revocations, data-feed age and actual output bytes/hash. Every M1 mounted input
must exist unchanged in the M2 capture and current target, even if only one file
is cited. M2 rechecks that entire dependency set whenever the evidence is used.
It rejects wrong-target, missing-input and changed-output provenance. An expired
authorization does not retroactively erase an operation completed before expiry;
explicit revocation invalidates its evidence. Run cancellation/resume blocks
future M1 calls but does not erase an already completed historical observation.

M1's offline backend cannot authenticate a deployed observation or actor identity.
Its process exit cannot automatically mark a control reviewed, establish a finding
or prove security. A nonzero operation cannot satisfy a control. The raw output
remains private untrusted data; the report exposes scoped provenance metadata.
New operational execution still requires M1's current-version gate. M2 offline
reports always say `component_freshness_verified: false`.

## Findings, counterevidence and relationships

`finding example FILE` takes a version-1 record with these exact fields:

- Identity/scope: `id`, `root_cause`, `control`, `title`, `category`, `location`,
  `actor`, `prerequisites`, `trust_boundary`.
- Assessment: `impact`, `severity`, `severity_reason`, `confidence`,
  `confidence_reason`, `evidence`, `counterevidence`, `disposition`.
- Action: `fix`, `preserve`, `retest`, `uncertainty`.

Category is `vulnerability`, `hardening` or `operational`. Severity is `critical`,
`high`, `medium`, `low` or `informational`; confidence is `high`, `medium` or `low`.
Text fields are nonempty and bounded to 4096 characters. Evidence and counterevidence
are disjoint arrays of same-assessment/control references. `confirmed` needs valid
support; `rejected` needs valid refuting evidence; `needs_validation` may lack proof.
Record the technical basis and seek counterevidence before confirming an important
claim. Never derive severity or confidence merely from a tool label.

`decide example FILE` records a later decision with exactly `schema_version`,
`finding`, `disposition`, `evidence`, `counterevidence`, `reason`. Previous decisions
are retained privately, at most 32 per finding. Rejection does not delete a finding.
Root-cause grouping uses explicit cause + control + actor; it retains all members
and conflicting dispositions. Similar titles are insufficient for grouping.

`link example FILE` accepts `schema_version`, `from`, `to`, `reason`. Endpoints must
exist in the same assessment; self-links, dangling links and cycles fail. Links are
hypotheses, not an automatically verified exploit chain or severity increase.

Remediation is always `not_verified` in M2. Patch, local/staging/production verification
and risk-acceptance state machines belong to later work; extra success flags fail.
The report still supplies useful fix and retest guidance for a human or agent.

## Refresh, invalidation and compatibility

`refresh example FILE` takes exactly `schema_version`, `deployments`, `model` with
the original actor and deployment ID sets. It recaptures the same selected file list
and updates declared context. New actors, deployments or selected files need a new
assessment. Changed relevant files, environments, actors, assets and flows invalidate
their dependent evidence; unrelated evidence remains valid. A flow also depends on
its actor/asset revisions. Runtime changes not supplied to M2 remain unobserved.

`invalidate example EVIDENCE FILE` takes only `{"reason":"Explain the evidence error."}`.
Explicit invalidation is irreversible. Refresh preserves invalidated/expired claims
as history. Reports recompute current validity even without refresh: stale reviews
become blocked/unverified; confirmed or rejected findings lose their current
disposition when its required evidence becomes invalid. The recorded disposition
remains visible. Restoring old bytes before refresh may match an old binding again;
use explicit invalidation when an observation itself is discredited.

Assessment creation, observation IDs, finding IDs and relationship pairs reject
conflicting reuse. Exact identical creation/observation retries return `exists`;
this acknowledgment does not revalidate historical evidence. Reports do that.
IDs are local to an assessment, never a cross-assessment reference mechanism.
Engine and catalog fingerprints are recorded privately. A changed engine/catalog
blocks old assessments; this development version has no silent migration or
cross-version promotion of historical evidence. Retain old reports as history and
create a new assessment with the reviewed current package.

## Privacy, bounds and interpretation

Use pseudonyms and minimum necessary evidence. `redact_values` accepts up to 128
literal strings of 3–4096 characters for sensitive names or values that patterns
cannot identify. Redaction applies to outward string values, including identifiers,
paths, summaries, findings and model context. Public schema keys stay unchanged;
private identifiers are never used as protocol keys. Common quoted JSON credentials,
tokens, email/number patterns, URLs and local root paths are suppressed. Markdown
metacharacters and terminal/bidirectional control characters are neutralized.

This is conservative masking, not a semantic privacy classifier. Arbitrary names,
encoded secrets and novel credential formats need explicit literals or removal.
Masking may hide useful context or make two displayed IDs alike; the private ledger
retains exact distinctions. Do not infer identity from identical redacted text.
Review JSON as data, and review either report before sharing. Nothing is uploaded.

Additional bounds: 16 deployments, 64 actors/assets each, 128 flows, 2048 control
instances, 256 observations, 256 findings, 512 chain links, 4 MiB per persisted
assessment record and 4 MiB per rendered report. CLI input files are at most 1 MiB.
Exceeding a limit fails; it cannot produce a success claim. Raw captures and historical
reports consume private disk over time; operator retention/deletion is required.
Same-account/key compromise and concurrent hostile host mutation are outside the
controller's trusted-host boundary.

Read a report in this order: inspect scope and revision limits; act on prioritized
findings; follow their evidence summaries and counterevidence; review blocked and
unexamined controls; plan the next authorized check. An empty finding list, clean
process exit or high reviewed count never proves the system secure.
