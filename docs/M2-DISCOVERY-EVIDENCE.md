# M2 discovery and evidence contract

M2 adds offline intake, coverage, evidence and reporting to the M1 control plane.
It does not execute a target, contact a supplied URL, run a vulnerability scanner,
apply a patch or approve production. An agent prepares the bounded input records;
a novice should not need to choose scanners or invent security terminology.

## Implementation plan and boundaries

1. Reuse M1 regular-file capture and private authenticated SQLite records. Add
   explicit assessment contracts without changing M1 execution authority.
2. Inspect selected source files without importing them or invoking their tools.
   Record supplied URLs as passive scope, separate from source identity. Retain
   missing access and uncorroborated application facts as unknown.
3. Build a versioned, partial control inventory from observed facts and the eleven
   existing domain modules. Keep applicability, review progress and security
   outcome separate. A reviewed control is not necessarily a successful control.
4. Bind observations to their source/environment/actor context. Distinguish local
   capture, operator statements and authenticated M1 execution. Invalidate affected
   evidence on relevant changes; preserve still-valid unrelated observations.
5. Record findings, counterevidence, root causes, attack-chain links and concrete
   remediation/retest guidance. Produce escaped, redacted novice reports in private
   state. Never export raw source or raw tool output automatically.
6. Verify allowed and denied workflows, privacy, stale evidence and platform
   behavior; independently review actual contracts and implementation; scan the
   exact delivery source and observe GitHub checks before integration.

The existing standard-library implementation is sufficient. Reusing its path,
permission and HMAC boundaries avoids a second database, dependency framework or
background service. New modules separate intake, evidence semantics and report
presentation because they have different untrusted-input boundaries. M1 remains
the only operational tool-execution path.

## Trust and input semantics

The same operator, controller, OS account and private-state authority described in
M1 remain trusted. Target content and imported records are data. A signature proves
which private controller recorded a claim; it cannot prove that a human assessment
is correct or defend against an attacker who controls that account and key.

Source intake requires an explicit canonical root and a bounded relative file
selection. Capture only regular, unlinked files; reject traversal, reparse points,
hard links and oversized inputs. Do not enumerate beyond the authorized selection
or execute installation scripts. Preserve original target bytes.

A source revision supplied by an operator is a declared label. Captured content
digests identify the actual selected bytes. A deployed artifact/environment is a
different binding and is never inferred from the local source revision. URL-only
intake cannot establish private source, cloud configuration or deployed identity.
URLs containing credentials, queries or fragments are rejected; intake never
performs DNS resolution or an HTTP request to them.

Actors, assets, data flows and business capabilities require provenance. Missing
facts remain unknown. Manifest declarations do not establish installed/runtime
versions. Platform routing needs corroborated structured evidence; arbitrary words
in a README, comment or tool message do not activate a platform adapter.

## Evidence and coverage

Each observation has a stable ID, method, provenance, observation time, explicit
bindings, expiry where relevant, private supporting references and a redacted
summary. Imported flags such as `verified: true` are not controller provenance.
An M1 observation must resolve authenticated completed records, matching input
identity and the actual bounded output digest. The output remains untrusted data.
All producer-mounted inputs belong to that dependency closure, even if an
operator cites only one. Role identity remains unverified by the offline backend.

Controls retain `not_started`, `in_progress`, `reviewed`, `blocked` or
`not_applicable` progress, with a factual basis for exclusions. A review must cite
valid in-scope evidence. Stale or missing evidence cannot satisfy review coverage.
Standards references identify an edition and control/section; this inventory is a
partial planning aid, not a full standards certification or a claim that its
reference snapshot is perpetually current.

No overall security percentage or unqualified safe-to-launch verdict is produced.
Reports state the selected input scope, inaccessible surfaces, evidence provenance,
unresolved findings and next checks. An empty finding list is not proof of safety.

## Findings and output

Findings keep severity and confidence with separate rationales, supporting evidence,
counterevidence, actor/prerequisites, affected surface, customer impact, disposition,
fix guidance, legitimate behavior to preserve, retest instructions and uncertainty.
Group duplicate observations only by an explicit root cause in the same affected
scope. Similar titles do not establish a shared cause. Attack-chain links require
existing findings and an explained relationship; cyclic or dangling links fail.

Source fixes cannot claim staging or production verification. Rejected findings
need counterevidence; uncertain findings stay visible. Stale supporting evidence
reopens the need for validation rather than silently preserving confirmation.

CLI output contains safe identifiers and result metadata, not input payloads or
exception traces. Reports suppress raw artifacts and sensitive scope details,
redact declared sensitive values and common secret/personal-data patterns, and
escape untrusted presentation content. Automated redaction has limits; the operator
must review a report before sharing it. Private records are not automatically
uploaded, committed, installed globally or scheduled for repeated execution.

The executable commands, complete field contracts, resource bounds, redaction
limits and development-version compatibility rules are in
[M2 operations](M2-OPERATIONS.md).
