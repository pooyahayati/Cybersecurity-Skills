# Cybersecurity Skills

A standalone, modular security skill for developers who need to understand what
can go wrong, what customer data is at risk, how to fix a confirmed weakness, and
how to verify the result. It works independently of the person, framework or
coding assistant that created a project. It does not require another head skill.

**Development version: `0.7.0-dev`. M6 adds bounded behavioral qualification and
exact-source skill packaging/lifecycle to the M1–M5 controls.**
General active scanning and deployment approval remain unsupported. This is not
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
explain next steps in plain language. [Measured bounded results](STATUS.md) follow
the [evaluation protocol](docs/EVALUATION.md); full-application detection accuracy
and remediation quality remain unestablished.

Today the package provides eleven domain guidance modules, a bounded intake and
assessment ledger, useful private reports, and a foundation for acquiring and
running reviewed components. M3 adds finite source leads and evidence-bound fixes;
M4 adds bounded runtime/configuration observations; M5 adds bounded resilience checks. These help an agent investigate and justify
a review; they do not automatically establish application security.

## M6 qualification and skill packages

Use the [M6 guide](docs/M6-QUALIFICATION.md) to build a deterministic package from
an exact Git commit, inspect it against a separately reviewed digest, and manage
an explicitly selected installation. No package code or installation hook runs
during verification. Update/uninstall refuse unmanaged content and local edits;
private pending transactions support recovery after interrupted directory moves.
Unrelated skills and assessment data remain outside the managed inventory.

Behavioral evaluation compares frozen realistic synthetic requests against the
previous version, without revealing expected answers to evaluating agents. It
records concrete findings, examined safe paths, missed issues, false alarms,
unsafe actions, proposed fix quality and novice-report usefulness. Actual package
and operator workflows remain separate from static agent reasoning. See
[status](STATUS.md) for observed results and limitations; no security percentage,
universal detection guarantee or unobserved model setting is invented.

Package identity does not establish freshness or security. Every assessment
keeps M1 current-version checks. This task prepares a development candidate;
merging it does not publish a stable release or update a user's installed skill.

## Implemented M5 capacity, recovery and incident checks

- Run a current reviewed native k6 binary with generated private broker tickets.
  A trusted collector enforces one exact GET/HEAD route, destination/TLS checks,
  total requests, admission rate, concurrency, time, byte limits and stopping.
  Target code and credentials never enter k6. M1 execution stays offline.
- Measure actual read latency percentiles, matching successful RPS, errors,
  overload and generator completion. Failed or incomplete workloads cannot pass.
  Choose explicit phases for baseline/load/stress/spike/soak/breakpoint questions;
  heavy production work is unsupported and short samples do not prove capacity.
- Inspect exact standalone SQLite artifacts in M1. Detect duplicate/null
  transaction keys, missing rows and altered typed values against a reviewed
  expected state. Restore a backup and a separate rollback snapshot into disposable
  databases; an existing but corrupt backup fails. Original data is preserved.
- Measure disposable restore time and report declared data-loss intervals
  separately. Correlate a fresh, observed receiver acknowledgment with a recovery
  challenge. Missing/revoked evidence remains visible and retracts dependent results.
- Preserve explicitly selected incident bytes privately, append authenticated
  chronology and verify custody on export. Separate facts, hypotheses and proposed
  actions. Reports hide raw evidence and private notes and give corrective steps.

These are bounded observations. Resource saturation, live database linkage,
actual capture time, whole-service RTO/RPO and end-to-end notification delivery
need additional evidence. No containment, deployment rollback, customer message
or recurring monitoring is performed. The agent prepares the contracts and
explains these limits to the developer. See [M5 operations](docs/M5-OPERATIONS.md)
and [M5 contracts](docs/M5-RESILIENCE.md).

## Implemented M4 runtime, infrastructure and delivery checks

- Collect explicit GET/HEAD observations through a separate trusted collector.
  Bind exact routes, actors, address pins, verified TLS, approved redirects, expiry
  and persistent request/time/body budgets. No crawling, proxy inheritance or
  automatic retries. Unknown outcomes consume their single-use intent.
- Compare the same protected resource for an owner, other user, other tenant or
  anonymous actor. Authenticated actors need observed complete identity predicates
  and distinct credential bindings. Preserve the positive control; a denial with
  the owner's complete body fails even when its status is 403.
- Inspect selected Terraform/Kubernetes/IAM JSON, Dockerfile and CI workflow forms
  for finite storage, privilege, secret and permission leads. Optionally run the
  current reviewed Trivy binary for embedded secret/misconfiguration rules inside
  M1. No target hooks/configuration, external check cache or vulnerability DB is
  silently used. Unsupported files and absence of reported results stay explicit.
- Read one exact local container and its image identity, minimizing recorded
  configuration. Compare it with the declared deployment artifact and required
  role evidence for a pre/post-release correspondence record. Wrong or expired
  artifacts and failed role checks block that result.
- Revalidate evidence and retract dependent results after changes or revocation.
  Produce private JSON and readable Markdown with locations, correction steps,
  producer identities and remaining coverage gaps.

These are observations with explicit limits. Server identity assertions are not
independent identity attestation. Local Docker evidence does not prove which
container served a URL, all replicas, source-to-image provenance or deployment of
an M3 fix. Remote host/cloud administration, capacity testing and automatic target
changes remain unavailable. Use [M4 operations](docs/M4-OPERATIONS.md) and review
[the exact support boundaries](docs/M4-RUNTIME-SECURITY.md).

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

**No third-party assessment skill is automatically active.** The controller
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
| [Trivy](https://github.com/aquasecurity/trivy) | Secret and configuration leads | M4 opt-in current reviewed Linux binary; release-embedded rules in offline M1; no product vulnerability DB |
| [Semgrep](https://github.com/semgrep/semgrep) | Source analysis | Disabled candidate; edition/rule licenses require review |
| [ZAP](https://github.com/zaproxy/zaproxy) | General dynamic web/API testing | Disabled candidate; M4 uses a smaller explicit-read collector; M1 stays offline |
| [k6](https://github.com/grafana/k6) | Load, concurrency and capacity measurements | M5 opt-in current reviewed x64 native binary; generated broker workload only; not bundled |
| Python standard library | Controller, source verification, signed state, bounded HTTP/TLS and tests | Implemented; host Python 3.11+ required |
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
| Identity and access | Sessions, recovery, roles, ownership and tenant separation | M3 source paths; M4 observed identity predicates and same-resource role comparisons | Server assertions only; session lifecycle and real database effects need further evidence |
| Sensitive/customer data | Secrets, leaks, storage, logs, retention and deletion | M3 selected credential/log leads and lifecycle review | Privacy requirements and other data copies need project context |
| Application and API code | Injection, XSS, SSRF, uploads, traversal, deserialization and API controls | M3 finite source rules; M4 exact bounded reads | No whole-program analysis, crawler, form submission or arbitrary active payloads |
| Business logic | Abuse cases, authorization order, payments and idempotency | M3 source traces and finite state/variant cases | M5 can check selected persisted SQLite artifacts; real payments and deployed state linkage remain unverified |
| Dependencies and artifacts | Vulnerabilities, packages, install hooks, containers and provenance | M1 acquisition, M3 exact-version/advisory review, M4 observed local image identity | Product Trivy adapter does not select vulnerability databases or build attestation |
| Infrastructure and DevOps | Host/cloud access, storage exposure, IaC, containers and CI/CD secrets | M4 finite structured/lexical leads, Trivy adapter and local container reads | Selected forms only; no remote account discovery or infrastructure mutation |
| Pre-release and release | Artifact/environment identity, staging checks, deployment controls and rollback readiness | M4 declared/observed local artifact correspondence and role prerequisites | URL routing/build provenance unverified; no release approval or rollback execution |
| Post-release web/API | Scoped production verification, authenticated role comparisons and exposure checks | M4 exact authorized GET/HEAD, TLS and complete response predicates | No general scan or monitoring; explicit target scope, credentials and budgets required |
| Capacity and concurrency | Concurrent users versus RPS, load/stress/spike/soak, latency, errors and persisted state | M5 bounded read workloads and independent SQLite artifact oracles | Small explicit budgets; target resource saturation and deployed write linkage remain unknown |
| Recovery and incidents | Backup restoration, recovery objectives, alerts and evidence-preserving triage | M5 disposable SQLite restore/rollback, receiver acknowledgment and private custody | Service RTO/RPO, deployment rollback and notification transport need independent evidence |
| AI features | Prompt injection, tool authority, sensitive context, output handling and tenant isolation | M2 planning and M3 general source reasoning | Specialized AI runtime assessment remains unavailable |
| Findings and fixes | Counterevidence, scoped causes, private candidates, before/after tests and retest guidance | M2 ledger and M3 scoped proposal/acceptance workflow | Finite declared model only; no automatic source overwrite or production claim |
| Evidence privacy and validity | Redaction, provenance, actor/environment/source bindings, selective invalidation | Implemented M2 controls | Private state; redaction cannot recognize arbitrary sensitive prose |
| Skill qualification and packaging | Blind baseline/candidate cases, exact-source archives, owned installation/update/uninstall and recovery | M6 development-candidate workflow | Finite measured cases; no universal protection, publisher authentication or automatic global update |

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

For M4, follow [the runtime and infrastructure guide](docs/M4-OPERATIONS.md).
Use `m4_review.py` for new combined cases; it also exposes the supported M3 source
methods. The agent prepares private scope/authority records and explains access
gaps. HTTP collection requires a current reviewed head and explicit target
authority; source scanners additionally require M1 Docker and reviewed tools.
Credentials and complete response contents never belong in project files.

The controller is an operator interface, not a one-command automatic audit. It
requires concrete source and execution contracts. An authorized operator can reuse
an existing scope; the package does not ask for confirmation on every bounded call.

Run the real isolation regression suite against synthetic data with:

```bash
python -B tests/docker_integration.py --docker /absolute/path/to/docker
python -B tests/m3_workflow.py --docker /absolute/path/to/docker
python -B tests/m4_workflow.py --docker /absolute/path/to/docker
```

It fails if isolation is unavailable and creates only its own disposable state,
inputs and labeled containers. See [contribution instructions](CONTRIBUTING.md)
for platform details and [status](STATUS.md) for observed results.
The M4 workflow also resolves the current official Trivy release; it fails if
freshness/acquisition is unavailable. Its network targets are owned loopback
fixtures, not customer sites. TLS unit fixtures require an existing OpenSSL
executable (including Git for Windows' bundled executable).

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
