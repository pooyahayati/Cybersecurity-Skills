# Cybersecurity Skills

A standalone, modular security skill for developers who need to understand what
can go wrong, what customer data is at risk, how to fix a confirmed weakness, and
how to verify the result. It works independently of the person, framework or
coding assistant that created a project. It does not require another head skill.

**Development version: `0.4.0-dev`. M3 adds bounded source leads, modular source
reviews, private patch candidates and finite behavioral retesting on M1/M2.**
General-purpose scanner integrations and live website/load testing remain later milestones. This is not
a stable security-auditor release and does not establish that an application is secure.

## What this skill is for

The complete product is intended to help a novice developer review source code,
APIs, deployed websites, sensitive data, customer isolation, infrastructure and
delivery. Its workflow will connect weaknesses across these surfaces instead of
treating a clean scanner result as sufficient evidence. A useful finding identifies
the affected code or environment, attack prerequisites, customer impact, evidence,
counterevidence, a concrete fix, and checks that preserve legitimate behavior.

Source-only, URL-only and combined reviews have different coverage. A public URL
does not reveal private source code, cloud permissions or backup recoverability.
The skill must retain those unknowns, distinguish staging from production, and
explain next steps in plain language. Detection accuracy and remediation quality
will be measured in the [evaluation protocol](docs/EVALUATION.md), not assumed.

Today the package provides eleven domain guidance modules, a bounded intake and
assessment ledger, useful private reports, and a foundation for acquiring and
running reviewed components. M3 now adds finite syntax-based security leads and
evidence-bound remediation workflows. These help an agent investigate and justify
a review; they do not automatically establish application security.

## Implemented M3 source review and fixes

- Inspect selected Python syntax trees and JS/TS/PHP tokens inside M1 isolation.
  Six limited rule families flag direct dynamic execution, object deserialization,
  selected constructed queries, literal credentials, weakened cookies and sensitive
  logging. The [support matrix](docs/M3-SOURCE-REMEDIATION.md) lists exact language
  forms and omissions. Comments, safe near-matches and failed parsing are tested.
- Review architecture, identity/session, application, data lifecycle, business,
  dependency and secret boundaries through attributed source traces. Bind actors,
  assets, concrete locations, guards, effects, abuse cases and counterevidence.
- Optionally use the reviewed current Addy hardening resource through M1. No
  external skill is required or installed automatically. Dependency traces need
  exact inventory and a current reviewed advisory-data component; matching remains
  reviewer judgment. Installed WordPress/WooCommerce versions remain unverified.
- Propose exact-hash replacements only for selected files and export a separate
  private candidate. Original source is preserved. Review and apply that candidate
  through the project's authorized development process.
- Run frozen legitimate, denied and related-variant cases on original/candidate
  Python probe entrypoints. Compare actual response and entire serialized state;
  missing cases, deny-everyone fixes, deny-after-write and partial fixes fail.
- Require reviewer assessment before accepting a fix for its declared serialized
  model. Changed source/candidates, revoked evidence and stale dependencies reopen
  the result. Reports omit raw source and test payloads and retain unsupported gaps.

The probe deliberately executes target Python only in M1 isolation. Its finite
response/state model can be falsified by malicious subject code, so it does not
verify actual database state, installed identity or production protection. No
overall security pass is generated. See [M3 operations](docs/M3-OPERATIONS.md).

## Implemented M2 assessment records

- Accept source-only, URL-only and combined scope. Read only explicitly selected
  regular files; do not run project code, installation hooks or website requests.
- Discover file-language and structured dependency/version declarations. Keep
  installed versions unknown. Corroborate WordPress hints with a package declaration
  and source-version marker; treat AI dependencies as planning hints.
- Retain declared actors, assets, flows and capabilities with explicit provenance.
  Separate selected source digests from declared deployed artifacts and environments.
- Route planning across the eleven modules using observed declarations and known
  scope. Unknown capability or an unsupported claim of absence cannot hide a gap.
- Inventory twelve partial control templates, expanded by surface, environment
  and actor. Keep applicability, progress and outcome separate. Standard references
  name a historical edition/chapter; this is not comprehensive ASVS certification.
- Bind evidence to relevant files, model facts and environments. Authenticate M1
  operation records and all producer-mounted inputs; reject fake flags, wrong targets,
  changed output, revoked authority and stale data. Recheck validity on use/export.
- Preserve findings, severity/confidence rationales, counterevidence and rejected
  claims. Group explicit shared root causes without deleting conflicting members.
  Validate attack-chain links without treating a relationship as a working exploit.
- Generate private JSON and Markdown with priority, customer impact, location,
  evidence, fix guidance, legitimate behavior to preserve and retest instructions.
  Redact declared sensitive values and common credential/personal-data patterns;
  escape untrusted Markdown. Review remaining sensitive prose before sharing.

M2 records observations; they are not an automated verdict. Manual judgments remain
labeled as such, process completion does not mark a control reviewed, and every
report keeps `security_verdict: not_established`. Missing access stays visible.
See [M2 operations](docs/M2-OPERATIONS.md) for exact commands, limits and contracts.

## Implemented M1 controls

- Resolve the publisher-designated latest stable GitHub release. Use the exact
  default-branch commit only after confirming that no stable release exists.
- Check enrolled numeric repository/owner identities, immutable Git objects,
  selected file hashes and official SHA-256 release-asset digests. A displayed
  version string cannot establish the identity of the executed bytes.
- Acquire bounded resources into quarantine, reject unsafe archive/file paths,
  and execute no installation hooks. Require review of instructions, dependencies,
  permissions, licensing, compatibility and provenance.
- Activate an accepted candidate atomically. A failed update preserves the old
  pointer but cannot make that old version pass a new current-version check.
- Require the head itself and every selected component to pass current preflight.
  Reload an updated head from its accepted bundle. Bind exact resources for a
  bounded run; recheck on new runs, resumes and changed module selections.
- Treat rule/feed freshness separately from binary identity, including expiry
  during a run. Unavailable or invalid upstream evidence blocks affected execution.
- Authorize exact input snapshots, components, entrypoints, arguments, expiry and
  shared call/time budgets using private authenticated records.
- Execute offline in a local Linux Docker container with read-only snapshots,
  a cleared environment, non-root identity, dropped capabilities, no-new-privileges,
  and bounded memory, CPU, processes, scratch space, output and elapsed time.
- Interrupt on cancellation, revocation or expiry. A container-side deadline
  remains effective if the controller exits. Recover owned interrupted operations
  without resetting budgets or deleting unrelated containers.

See [the control-plane design](docs/M1-CONTROL-PLANE.md) for the trust model and
[the operator guide](docs/M1-OPERATIONS.md) for commands, inputs and failure handling.

## Auxiliary skills and tools

**No third-party assessment skill is automatically active in M3.** The controller
can acquire explicitly enrolled resources, but a catalog entry does not provide
a reviewed assessment adapter or permission to invoke it. This table distinguishes
development use, implemented opt-in adapters and planned runtime composition.

| Skill or tool | Purpose | Current use/status |
|---|---|---|
| `vibe-coding-skill` | Development workflow, evidence and delivery controls | Used to develop this repository; no product runtime dependency |
| `skill-creator` | Skill packaging and independent behavioral evaluation | Development only |
| `security-and-hardening` | Review of material security boundaries | Development specialist; optional product source-review adapter through M1 |
| `api-and-interface-design` | Review of scope, evidence and report contracts | Development specialist; no product runtime dependency |
| [briiirussell cybersecurity skills](https://github.com/briiirussell/cybersecurity-skills) | Broad security methods and triage | Disabled candidate; select individual resources after review |
| [Trail of Bits skills](https://github.com/trailofbits/skills) | Deep source review and post-fix verification | Disabled candidate |
| [Cloudflare security audit skill](https://github.com/cloudflare/security-audit-skill) | Source evidence and refutation methods | Disabled candidate |
| [Addy Osmani agent skills](https://github.com/addyosmani/agent-skills) | Focused secure-development guidance | M3 supports selected hardening guidance after current enrollment/review; disabled by default |
| [WordPress agent skills](https://github.com/WordPress/agent-skills) | Platform-specific WordPress/WooCommerce methods | Disabled candidate; relevant only on platform evidence |
| [OpenAI skills](https://github.com/openai/skills) | Selected threat-model and language-specific guidance | Disabled candidate |
| [Trivy](https://github.com/aquasecurity/trivy) | Artifact, secret, dependency and configuration analysis | Repository delivery checks; product adapter remains a candidate |
| [Semgrep](https://github.com/semgrep/semgrep) | Source analysis | Disabled candidate; edition/rule licenses require review |
| [ZAP](https://github.com/zaproxy/zaproxy) | Scoped dynamic web/API testing | Disabled candidate; no network-enabled backend in M1 |
| [k6](https://github.com/grafana/k6) | Load, concurrency and capacity measurements | Disabled candidate; M5 work |
| Python standard library | Controller, source verification, signed SQLite state and tests | Implemented; host Python 3.11+ required |
| Docker and official `python:3-slim` image | Local offline isolation | Implemented backend; image resolved to a reviewed current immutable digest |

Candidate selection rationale is in [source review](docs/SOURCE_REVIEW.md).
Original domain guidance remains useful without an external specialist. The head
owns scope, evidence and final decisions; a specialist cannot grant itself more access.

## Security operations and coverage

“Guidance” is written methodology, not an implemented scanner. Planned operations
must not be reported as performed merely because they appear in this table.

| Area | Operations/checks | Available now | Delivery boundary |
|---|---|---|---|
| Component supply chain | Current source, publisher identity, content integrity, review and activation | Implemented M1 controls | Exact accepted resources only |
| Execution safety | Immutable snapshots, no egress, resource budgets, cancellation, recovery | Implemented M1 controls | Local Linux Docker; offline only |
| Intake and coverage | Selected-file discovery, passive URL scope, actors/assets/flows, module routing and explicit unknowns | Implemented M2 records | No target execution, crawling or network probe |
| Architecture | Assets, trust boundaries, data flows, attack chains and insecure design | M2 records and M3 source traces | Attributed review of selected source/context |
| Identity and access | Sessions, recovery, roles, ownership and tenant separation | M3 cookie leads, source traces and finite role tests | Actual authentication/session/deployed identity needs additional evidence |
| Sensitive/customer data | Secrets, leaks, storage, logs, retention and deletion | M3 selected credential/log leads and lifecycle review | Privacy requirements and other data copies need project context |
| Application and API code | Injection, XSS, SSRF, uploads, traversal, deserialization and API controls | M3 finite source rules plus structured review | No whole-program analysis; live behavior remains M4 |
| Business logic | Abuse cases, authorization order, payments and idempotency | M3 source traces and finite state/variant cases | Concurrency, real payments and operational state remain unverified |
| Dependencies and artifacts | Vulnerabilities, packages, install hooks, containers and provenance | M1 acquisition and M3 exact-version/advisory review path | Reviewer matching; automated scanner integrations remain M4 |
| Infrastructure and DevOps | Host/cloud access, storage exposure, IaC, containers and CI/CD secrets | Guidance | M4 |
| Pre-release and release | Artifact/environment identity, staging checks, deployment controls and rollback readiness | Guidance | M4/M5 |
| Post-release web/API | Scoped production verification, authenticated role comparisons and exposure checks | Guidance | M4; explicit target scope required |
| Capacity and concurrency | Concurrent users versus RPS, load/stress/spike/soak, latency, errors and persisted state | Planned, with guidance | M5; heavy testing normally uses staging |
| Recovery and incidents | Backup restoration, recovery objectives, alerts and evidence-preserving triage | Guidance | M5 |
| AI features | Prompt injection, tool authority, sensitive context, output handling and tenant isolation | M2 planning and M3 general source reasoning | Specialized AI runtime assessment remains unavailable |
| Findings and fixes | Counterevidence, scoped causes, private candidates, before/after tests and retest guidance | M2 ledger and M3 scoped proposal/acceptance workflow | Finite declared model only; no automatic source overwrite or production claim |
| Evidence privacy and validity | Redaction, provenance, actor/environment/source bindings, selective invalidation | Implemented M2 controls | Private state; redaction cannot recognize arbitrary sensitive prose |

## Getting started

Read [current status](STATUS.md), [the roadmap](ROADMAP.md) and [SKILL.md](SKILL.md).
For local repository checks, use an existing Python 3.11+ interpreter:

```bash
python -B scripts/validate_project.py
python -B -m unittest discover -s tests -v
python -B tests/m2_workflow.py
```

No third-party Python packages are needed. These commands inspect this repository
and synthetic fixtures; they do not assess your application. Structural validation
returns `structure_valid` with `operational_assessment: false` and
`freshness_verified: false`. Actual source/preflight checks are separate commands.

For M1, start with [the operator guide](docs/M1-OPERATIONS.md). You need private
state outside this package and every target; a trusted local Docker CLI; a Linux
daemon with cgroup v2 and required resource/seccomp controls; and network access
to GitHub and Docker's official registry for acquisition/preflight. Target code
has no external network access. There is no unrestricted native fallback.

For M2, follow [the intake and evidence guide](docs/M2-OPERATIONS.md). The offline
ledger itself needs only Python and private state; it does not certify that its
components are current. An agent should prepare scope/observation records from
available evidence and explain missing access. Every actual tool execution still
requires M1 current-version preflight and authorization. No external assessment
skill is downloaded or installed merely to create a plan or report.

For M3, follow [the source review and remediation guide](docs/M3-OPERATIONS.md).
The agent prepares the private scope, review and behavior contracts, runs the
bounded operations and explains findings, fixes and remaining uncertainty. Use
`m3_review.py` for new M3 cases, including their M2 observations/findings. A changed
engine needs a new assessment rather than silently migrating historical records.

The controller is an operator interface, not a one-command automatic audit. It
requires concrete source and execution contracts. An authorized operator can reuse
an existing scope; the package does not ask for confirmation on every bounded call.

Run the real isolation regression suite against synthetic data with:

```bash
python -B tests/docker_integration.py --docker /absolute/path/to/docker
python -B tests/m3_workflow.py --docker /absolute/path/to/docker
```

It fails if isolation is unavailable and creates only its own disposable state,
inputs and labeled containers. See [contribution instructions](CONTRIBUTING.md)
for platform details and [status](STATUS.md) for observed results.

## Trust and limitations

The operator, controller, OS account, local Docker daemon and enrolled publisher
identities are trusted. HMAC records protect against unauthenticated edits, not
an attacker with the same account/key or host/Docker authority. Keep those powers
outside an untrusted agent's tool access. Containers share a kernel; this backend
is not a guarantee against kernel or daemon vulnerabilities.

The source adapter supports public GitHub repositories and digest-bearing release
assets. Available GitHub signature metadata is recorded; this is not independent
signature/transparency-log verification. The official Python image uses a
stable-major channel and digest, not GitHub's release-selection policy. Host
Python/Docker are observed prerequisites, not automatically upgraded products.

M1 has no advisory subscription, unattended updater, scheduled monitoring,
network-enabled scanner, production load test or automatic remediation. Explicit
revocation stops affected work; external advisories must be supplied by the
operator until an advisory integration exists. Blocked coverage stays visible.

All maintained project documentation is English. Keep credentials, customer data,
raw output, private SQLite records and evidence outside Git. Retention/deletion
are operator responsibilities; do not publish output automatically. Only synthetic
fixtures belong here. Original project code uses [MIT](LICENSE);
[third-party notices](THIRD_PARTY_NOTICES.md) describe adoption obligations.

## Author and license

Pooya Hayati · [https://pooyahayati.com/](https://pooyahayati.com/) · MIT

##
