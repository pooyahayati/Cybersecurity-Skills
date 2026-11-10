# Cybersecurity Skills

A standalone skill for AI coding assistants that helps developers review code,
websites and delivery environments, protect customer data, investigate weaknesses,
and propose fixes with concrete retests. It works with existing projects regardless
of how they were built. No other head skill is required.

**Stable release: [1.0.0](https://github.com/pooyahayati/Cybersecurity-Skills/releases/tag/v1.0.0).**
This release supports the bounded operations below. It does not certify that an
application is secure or provide unrestricted penetration testing.

## Install

You need an AI coding assistant that supports `SKILL.md` and trusted Python 3.11+
for the helpers. Windows and Linux are tested. Git is used below to obtain the
trusted management tool; no third-party Python packages are needed.

1. Download **`cybersecurity-skills-1.0.0.zip`** and its **`.sha256`** file from
   [the release](https://github.com/pooyahayati/Cybersecurity-Skills/releases/tag/v1.0.0).
   The automatically generated GitHub source archives are different files.
2. Review the publisher and release notes. Obtain the management tool in a
   separate directory, outside the installation you will manage:

   ```sh
   git clone --branch v1.0.0 --depth 1 https://github.com/pooyahayati/Cybersecurity-Skills.git trusted-cybersecurity-skills
   cd trusted-cybersecurity-skills
   ```

3. Choose an **existing, host-supported skills directory**, such as a project's
   `.agents/skills`, and a **new private management path that does not yet exist**.
   Keep management state outside the checkout, installed skill and skills directory.
   Use your own absolute paths below; Windows paths such as `C:/Users/you/...` work.

   ```sh
   python -I -B scripts/m6_package.py inspect --archive /absolute/downloads/cybersecurity-skills-1.0.0.zip --sha256 799f02bbee3129220f7fbfaa3d25c0888ee9b3f9a17283396ca21606168a69a4
   python -I -B scripts/m6_package.py install --archive /absolute/downloads/cybersecurity-skills-1.0.0.zip --sha256 799f02bbee3129220f7fbfaa3d25c0888ee9b3f9a17283396ca21606168a69a4 --skills-root /absolute/project/.agents/skills --state /absolute/private/cybersecurity-package-manager
   python -I -B scripts/m6_package.py diagnose --skills-root /absolute/project/.agents/skills --state /absolute/private/cybersecurity-package-manager
   ```

   Stop if inspection or installation is blocked. Do not force an overwrite or
   replace an existing skill directory manually. See the
   [upgrade, recovery and uninstall commands](docs/M6-QUALIFICATION.md#owned-installation-lifecycle).

4. Reload your assistant's skill catalog or start a new session, then select
   `cybersecurity-skills`. In hosts supporting explicit skill mentions, use
   `$cybersecurity-skills`.

Inspection verifies the package bytes, not publisher identity or currentness.
Before an assessment, the skill still checks the current approved head, selected
tools and rule/advisory data. Missing current evidence blocks the affected work.
Keep the trusted management checkout available for future recovery.

## Start your first review

Give the assistant the project path, what you own or may test, the environment
(local, staging or production), and the most important data or user roles.
Start with a source-only review:

```text
Use $cybersecurity-skills to review my project at [absolute project path].
Start with selected source files and an offline coverage plan. Focus on login,
customer data and isolation between users. Do not contact the deployed site yet.
Explain confirmed findings, unverified leads, concrete fixes, legitimate behavior
to preserve, and the checks needed to verify each fix. Keep evidence private.
```

For a deployed site, provide an explicit URL/route scope, test accounts when
needed, permitted methods and request/time limits. The agent should explain what
can be checked with the available access and retain unsupported areas as gaps.
Load tests, mutations, recovery actions and production access need their own
appropriate scope; a URL alone does not authorize them.

A useful report identifies the affected file or route, evidence and confidence,
customer impact, corrective steps and a retest. Source-only, URL-only and combined
reviews have different coverage. A proposed fix is not a verified deployed fix.

For a quick offline planning check, run this from the trusted checkout or installed
skill directory:

```sh
python -I -B scripts/security_checklist.py plan --format markdown
```

It produces a 36-item plan with unverified outcomes. It does not scan a target,
contact a website or install a tool. Your assistant can then follow the
[assessment and private-report guide](docs/M2-OPERATIONS.md) or the
[supported execution profiles](docs/CHECKLIST-EXECUTION.md).

## Security operations

| Area | Available work | Coverage boundary |
|---|---|---|
| Architecture and source code | Trust-boundary review, finite Python/JS/TS/PHP source leads, reviewed fix candidates | Selected source and syntax forms; no whole-program detection guarantee |
| Identity, sessions and customer isolation | Source reasoning, scoped role comparisons and selected HTTP/SQLite scenarios | Project-specific actor and business rules are required; no automatic login or general MFA validation |
| Sensitive data and secrets | Source/configuration leads, selected rotation/deletion scenarios, private redacted reports | Other stores, complete data flows and arbitrary sensitive prose need separate review |
| Dependencies and artifacts | Selected npm inventory/advisory matching, inventory SBOM, approved-key Cosign verification | Declared inventory does not establish shipped reachability; no keyless/transparency claim |
| Websites and APIs | Explicit bounded HTTP capture/navigation, role comparisons and offline ZAP passive leads | No browser/JavaScript execution or unrestricted active scan |
| Infrastructure and DevOps | Selected IaC/container/configuration leads and authenticated Actions defaults | Local qualified profiles; no general cloud-account or remote-host assessment |
| Pre-release and post-release | Selected source/artifact/service correspondence and scoped deployed observations | No automatic deployment approval or production mutation |
| Load and concurrency | Bounded read workloads, latency/errors and selected HTTP/SQLite state checks | Explicit budgets; no distributed or heavy production capacity claim |
| Recovery and incidents | Disposable SQLite restores, selected read-service recovery, instrumented event transport and private incident chronology | No general outage RTO/RPO, automatic containment or real notification service |
| Fix verification and evidence | Original/fixed comparisons, legitimate and denied cases, counterevidence and invalidation | Independent expectations required; incomplete or stale evidence cannot become a pass |
| AI features | Guidance for prompt injection, tool authority and sensitive context | Specialized AI runtime assessment remains unavailable |

The [complete coverage map](docs/CHECKLIST-COVERAGE.md) describes all 36 checklist
items, evidence requirements and remaining gaps. Guidance and scanner leads are
kept separate from confirmed findings.

## Auxiliary skills and tools

Nothing in this table is installed or activated automatically. Selected resources
must pass identity, currentness, license, instruction and permission review.

| Resource | Use | Status |
|---|---|---|
| [Addy security and hardening](https://github.com/addyosmani/agent-skills/tree/main/skills/security-and-hardening) | Focused secure-development guidance | Optional reviewed source-review resource; disabled by default |
| [Trivy](https://github.com/aquasecurity/trivy) | Secret/configuration leads and selected current advisory data | Opt-in adapter; binary and advisory data checked separately |
| [ZAP](https://github.com/zaproxy/zaproxy) | Passive analysis of admitted HTTP captures | Opt-in offline profile; no browser or active scan |
| [k6](https://github.com/grafana/k6) | Bounded load and concurrency measurements | Opt-in generated workload through the trusted request broker |
| [Cosign](https://github.com/sigstore/cosign) | Approved-key artifact/provenance verification | Opt-in profile with reviewed key and policy |
| Docker and official Python image | Bounded offline execution | Required only for operations using that backend; actual isolation must pass preflight |
| [Vibe Coding Skill](https://github.com/pooyahayati/Vibe-Coding-Skill), security and interface specialists | Engineering and review of this repository | Development tools; not dependencies of the installed skill |

Other catalog entries are disabled candidates. See the
[source review](docs/SOURCE_REVIEW.md) and [catalog](config/sources.json) for their
status. Docker, scanners and their data are not bundled with this package.

## Practical limits

- Keep credentials, customer data, reports and assessment state outside the skill
  and outside Git. Review reports for sensitive prose before sharing them.
- Explicit target authority, current prerequisites and finite budgets remain
  required. Unavailable access or stale resources leave the affected work blocked.
- Package checks and reported findings are not a whole-application security
  verdict. The trusted operator, host account and Docker daemon remain part of the
  trust boundary; same-account compromise is outside local record protection.
- The stable release preserves `bounded-qualification` and `operational: false`:
  supported individual operations are qualified; general operational assessment
  is not. Global installation, autonomous routing and unlisted platforms are not
  implied by the release.

## Documentation

| Need | Guide |
|---|---|
| Release identity, support, upgrade and recovery | [Release guide](docs/RELEASE-READINESS.md) |
| Current-version checks and bounded execution | [M1 operations](docs/M1-OPERATIONS.md) |
| Scope, evidence and private reports | [M2 operations](docs/M2-OPERATIONS.md) |
| Code review and fixes | [M3 operations](docs/M3-OPERATIONS.md) |
| Web, infrastructure and release observations | [M4 operations](docs/M4-OPERATIONS.md) |
| Load, recovery and incidents | [M5 operations](docs/M5-OPERATIONS.md) |
| Additional supported execution profiles | [Checklist execution](docs/CHECKLIST-EXECUTION.md) |
| Measured results and retained limitations | [Status](STATUS.md) |
| Future work and contributions | [Roadmap](ROADMAP.md) · [Contributing](CONTRIBUTING.md) |

The release ZIP is fixed to its published source commit. This repository's main
branch can contain later documentation updates; it is not the identity of an
already published archive. Original project code is [MIT](LICENSE); see
[third-party notices](THIRD_PARTY_NOTICES.md) for adopted-resource obligations.

## Author and license

Pooya Hayati · [https://pooyahayati.com/](https://pooyahayati.com/) · MIT

##
