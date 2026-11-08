# Evaluation and acceptance

## Separate the claims

| Check | Establishes | Cannot establish |
|---|---|---|
| Repository validation | Supported metadata and file-reference invariants | Current upstream versions, correct security decisions |
| Helper regression tests | Observed behavior of the implemented helper | Accuracy of the full skill |
| Adapter contract tests | Compatible bounded execution and normalized outputs | Completeness of application analysis |
| Behavioral fixtures | Detection, rejection and remediation on specified cases | Universal protection or all-platform support |
| Deployment checks | Observed artifact/environment behavior | Untested environments or future operation |

## Required behavioral families before operational qualification

- Known vulnerable and safe near-match cases; absence of a warning alone is not
  a correct safe-case result unless the relevant path was examined.
- Anonymous, owner, non-owner, low-privilege and cross-tenant access. Verify denied
  mutations leave protected state unchanged and permitted operations still work.
- Sensitive data in logs, browser state, exports, caches, backups and external
  integrations. Verify redaction in the auditor's own output.
- Source-only, URL-only and incomplete credentials: maintain truthful coverage.
- Complete and partial fixes, related variants and legitimate-flow regressions.
- Fixed source paired with an old deployed artifact: reject production success.
- Unavailable or stale metadata, wrong installed binary, compromised candidate,
  incompatible update and stale vulnerability data: enforce freshness boundaries.
- Prompt injection in code, documentation, tool output and specialist resources:
  do not change scope, permissions, secrets handling or completion criteria.
- Production test budgets and cancellation: prove request limits and stopping
  behavior, not just the existence of a timeout setting.
- Backup exists but restore fails; duplicate transaction under concurrent load;
  alert exists but is not delivered. Report the actual failed outcome.

Use isolated synthetic targets. Do not send production credentials or customer
data to an evaluation provider. Agent evaluations require an available authorized
execution environment and a bounded cost; this document does not start one.

## Method

Record target and fixture revision, expected behavior and its independent basis,
model/provider and configuration, skill/tool revisions, rule/data identities,
permissions, environment and budgets. Compare with a documented no-skill or
previous-version baseline under equivalent conditions. Repeat stochastic cases
when needed to distinguish a stable effect from a single lucky result.

Measure confirmed findings, false positives, important misses, correct rejections,
patch correctness, scope violations and novice usability. Report denominators and
unsupported surfaces. Do not invent a security percentage or require a universal
coverage quota. Define release thresholds from the actual risk and supported scope.

For an independent pass, provide the realistic request and minimum raw artifacts
without revealing the suspected defect or intended answer. Label self-review as
self-review. Human or agent agreement does not replace reproducible evidence.

## Foundation acceptance

The initial helper must reject duplicate/unknown catalog fields, invalid states,
missing references, path traversal and references that resolve outside the package.
It must never install a candidate or run a command found in a file. Its output must
identify the inspected inputs by digest and scope without asserting an audit pass.
CI must run the actual documented commands on supported host families.

M1 implements source/freshness, authenticated control-state and offline execution
boundaries. Unit fixtures cover their allowed and denied transitions; the required
real Docker suite checks protected state, kernel limits, no egress/secrets,
cancellation, revocation, controller termination and recovery. Neither suite
measures application-vulnerability detection. Keep later assessment families
pending in `STATUS.md` until their own execution evidence exists.

M2 qualification adds synthetic source/URL/combined CLI workflows, context and
producer binding tests, changed/expired/revoked evidence, counterevidence and
conflicting root-cause members, report privacy and actionable standalone output.
Independent reviewers must exercise realistic workflows before seeing suspected
defects, retain their initial findings, and recheck required fixes against the final
source. These evaluations establish ledger behavior only; M3-M6 detection and
remediation effectiveness still require their own baselines and measurements.
