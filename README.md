# Cybersecurity Skills

A standalone, modular security skill for developers who need to understand what
can go wrong, what customer data is at risk, how to fix a confirmed weakness, and
how to verify the result. It works independently of the person, framework or
coding assistant that created a project. It does not require another head skill.

**Development version: `0.2.0-dev`. M1 implements the freshness and restricted
execution control plane.** Automated vulnerability discovery, scanner adapters,
remediation and live website/load testing remain later milestones. This is not
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

Today the package provides eleven domain guidance modules, planning/report
templates, and an executable foundation for acquiring and running reviewed
components. Use the domain material for planning; use the M1 controller for its
documented operations. Neither is a completed customer audit.

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

**No third-party assessment skill is automatically active in M1.** The controller
can acquire explicitly enrolled resources, but a catalog entry does not provide
a reviewed assessment adapter or permission to invoke it. This table distinguishes
development use from planned runtime composition.

| Skill or tool | Purpose | Current use/status |
|---|---|---|
| `vibe-coding-skill` | Development workflow, evidence and delivery controls | Used to develop this repository; no product runtime dependency |
| `skill-creator` | Skill packaging and independent behavioral evaluation | Development only |
| `security-and-hardening` | Review of material security boundaries | Development specialist; not a product assessment adapter |
| [briiirussell cybersecurity skills](https://github.com/briiirussell/cybersecurity-skills) | Broad security methods and triage | Disabled candidate; select individual resources after review |
| [Trail of Bits skills](https://github.com/trailofbits/skills) | Deep source review and post-fix verification | Disabled candidate |
| [Cloudflare security audit skill](https://github.com/cloudflare/security-audit-skill) | Source evidence and refutation methods | Disabled candidate |
| [Addy Osmani agent skills](https://github.com/addyosmani/agent-skills) | Focused secure-development guidance | Disabled candidate |
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
| Architecture | Assets, trust boundaries, data flows, attack chains and insecure design | Guidance | Discovery/evidence in M2; assessment in M3 |
| Identity and access | Authentication, sessions, recovery, roles, ownership and tenant separation | Guidance | M3 |
| Sensitive/customer data | Secrets, leakage, storage, encryption, logs, retention and deletion | Guidance | M3; privacy requirements need project context |
| Application and API code | Injection, XSS, SSRF, uploads, traversal, unsafe deserialization and API controls | Guidance | M3/M4 |
| Business logic | Abuse cases, authorization order, payments, race conditions and idempotency | Guidance | M3; capacity/state tests in M5 |
| Dependencies and artifacts | Vulnerabilities, malicious packages, install hooks, containers and provenance | Guidance plus M1 acquisition controls | Assessment adapters in M3/M4 |
| Infrastructure and DevOps | Host/cloud access, storage exposure, IaC, containers and CI/CD secrets | Guidance | M4 |
| Pre-release and release | Artifact/environment identity, staging checks, deployment controls and rollback readiness | Guidance | M4/M5 |
| Post-release web/API | Scoped production verification, authenticated role comparisons and exposure checks | Guidance | M4; explicit target scope required |
| Capacity and concurrency | Concurrent users versus RPS, load/stress/spike/soak, latency, errors and persisted state | Planned, with guidance | M5; heavy testing normally uses staging |
| Recovery and incidents | Backup restoration, recovery objectives, alerts and evidence-preserving triage | Guidance | M5 |
| AI features | Prompt injection, tool authority, sensitive context, output handling and tenant isolation | Guidance | Routed on actual AI functionality in M2/M3 |
| Findings and fixes | Counterevidence, deduplication, prioritization, understandable fixes and retesting | Templates/guidance | Operational reporting in M2; remediation in M3 |

## Getting started

Read [current status](STATUS.md), [the roadmap](ROADMAP.md) and [SKILL.md](SKILL.md).
For local repository checks, use an existing Python 3.11+ interpreter:

```bash
python -B scripts/validate_project.py
python -B -m unittest discover -s tests -v
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

The controller is an operator interface, not a one-command automatic audit. It
requires concrete source and execution contracts. An authorized operator can reuse
an existing scope; the package does not ask for confirmation on every bounded call.

Run the real isolation regression suite against synthetic data with:

```bash
python -B tests/docker_integration.py --docker /absolute/path/to/docker
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
