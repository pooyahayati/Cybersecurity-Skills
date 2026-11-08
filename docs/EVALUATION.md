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

## M3 bounded evaluation

M3 adds twelve vulnerable/safe syntax-rule pairs across Python, JavaScript,
TypeScript and PHP, with explicit comment/string near-matches and parse-failure
gaps. The previous M2 helper supplied declaration metadata only, not automatic
source leads or patch acceptance. This is a capability baseline, not a measured
comparison of model-level security reasoning or full SAST precision/recall.

The real M3 workflow executes a synthetic Python customer-record function through
M1 and the public CLI. It compares the same five frozen cases on the original and
four candidates: partial tenant fix, deny-all, deny-after-write and complete fix.
Owner read/write, non-owner mutation, anonymous read and cross-tenant read cover
the concrete policy. Compare complete serialized state, actual responses and
original file bytes. Revoke supporting evidence and observe acceptance reopen.
Record exact source, runtime, operations and command outcomes privately.

Independent reviewers exercise realistic requests without intended answers and
retain initial failures, fixes and final input hashes. Finite deterministic
fixtures do not measure stochastic agent performance. Full skill qualification,
live identity, persistent database effects, load/concurrency and production testing
remain M4–M6. A target can falsify the shared-interpreter serialized probe model;
oracle review and the explicit claim boundary are required, not a substitute for
a separately isolated collector when stronger assurance is needed.

## M4 bounded evaluation

Compare against M3's source-only behavior: M4 adds independently observed owned
HTTP/TLS requests, finite configuration leads and local artifact observations.
This capability baseline is not a model-level accuracy or full-skill benchmark.
Exercise legitimate reads and redirects, wrong/cross-origin destinations, complete
body/identity predicates, positive and denied actors, protected content returned
with a denial status, unrelated-resource comparisons, TLS failures, persistent
concurrent budgets, cancellation, controller death and uncertain-intent replay.
Independent server counters establish actual effects rather than only CLI errors.

Run `tests/m4_workflow.py` with the current official reviewed Trivy release and
real M1 Docker workers, target configuration/ignore traps, a disposable exact
container/image and public M4 CLI reads/reports. Bind current upstream identities
separately from the explicit synthetic publisher used for unmerged checkout code.
Retain original bytes and failures, verify cleanup and ensure output contains no
response/credential/secret excerpts. Missing external prerequisites fail this
workflow rather than substituting synthetic scanner success.

Reviewers retain their original findings and independently rerun prohibited and
legitimate effects after fixes on an immutable source snapshot. Required negative
checks include invalid producer/output/candidate, revoked identity, stale artifact,
failed role comparison, and imported web evidence that must not satisfy coverage
when its predicate fails. URL-only cases retain inaccessible source/infra gaps.
Exact-hash body predicates detect only the declared content contract; partial or
transformed leakage, real customer sessions, broad cloud posture, build/routing
attestation and all-replica assurance need additional supported evidence.
