# Evidence, coverage and remediation contract

## Coverage

Each applicable control has a versioned reference when available, a target and
environment, a required method, evidence and one coverage state:
`not_started`, `in_progress`, `reviewed`, `blocked`, or `not_applicable`.
`not_applicable` needs a factual reason. `reviewed` means examined, not secure.
Record limits of source, configuration and runtime access separately.

## Findings

Record a stable root-cause identifier, title, category, affected file/line or
endpoint/resource, actor and prerequisites, trust boundary, customer impact,
severity and rationale, confidence and rationale, observation time, target
revision/artifact/environment, tool and data identities, evidence references,
counterevidence, disposition and remaining uncertainty.

Disposition is `confirmed`, `needs_validation`, or `rejected`. An unresolved
finding is not a false positive. Separate hardening suggestions and operational
defects from demonstrated vulnerabilities. Connect related findings or attack
chains without double-counting one root cause across scanner outputs.

Identify evidence as source reasoning, configuration inspection, controlled
reproduction or observed deployment behavior. A complete static trace may establish
a defect without a live exploit; describe the proof and its limits. A scanner label,
HTTP status or agreement between models cannot alone establish impact.

## Fix and retest

Provide a minimal root-cause fix, changed behavior, legitimate flows to preserve,
related variants, owner, prerequisites and rollback/recovery where relevant.
For rejected mutations verify protected state remains unchanged. For reads verify
the sensitive content is not disclosed, not merely that the status code changed.

Use separate states: `open`, `fix_proposed`, `fixed_in_source`, `verified_local`,
`verified_staging`, `verified_production`, and `reopened`. Attach evidence to each
claimed transition. A source patch does not imply a new artifact was deployed.
Record valid risk acceptance separately with owner, reason, scope and review date;
it does not remove the finding or turn a failed test into a pass.

## Evidence binding and validity

Bind evidence to source/configuration inputs, artifact, environment, identity/role,
workload/dataset where relevant, tool/rule/data identities and observation time.
Changes to relevant inputs invalidate that claim. Reuse still-valid unrelated
evidence. A copied timestamp or user-written success flag does not authenticate an
execution; the future controller must verify the actual producer and bindings.

## Delivery

Lead with prioritized actions and customer impact. Include assessed scope, blocked
checks, evidence strength and remaining risk. Report security, capacity and recovery
outcomes independently. Do not invent a single security percentage or an unqualified
"safe to launch" verdict when required checks are unavailable.
