# Cybersecurity Skills

A standalone skill for AI coding assistants that helps developers review code,
websites and delivery environments, protect customer data, investigate weaknesses,
and propose fixes with concrete retests. It works with existing projects regardless
of how they were built. No other head skill is required.

**Version 1.1.0** includes optional Cloudflare source-review guidance. Install only a
[published stable release](https://github.com/pooyahayati/Cybersecurity-Skills/releases).
The skill supports the bounded operations below. It does not certify that an
application is secure or provide unrestricted penetration testing.

## Install

You need an AI coding assistant that supports `SKILL.md` and trusted Python 3.11+
for the helpers. Windows and Linux are tested. Git is used below to obtain the
trusted management tool; no third-party Python packages are needed.

1. Download **`cybersecurity-skills-1.1.0.zip`** and its **`.sha256`** file from
   [the release](https://github.com/pooyahayati/Cybersecurity-Skills/releases/tag/v1.1.0).
   The automatically generated GitHub source archives are different files.
2. Review the publisher and release notes. Obtain the management tool in a
   separate directory, outside the installation you will manage:

   ```sh
   git clone --branch v1.1.0 --depth 1 https://github.com/pooyahayati/Cybersecurity-Skills.git trusted-cybersecurity-skills-1.1.0
   cd trusted-cybersecurity-skills-1.1.0
   ```

3. Choose an **existing, host-supported skills directory**, such as a project's
   `.agents/skills`, and a **new private management path that does not yet exist**.
   Keep management state outside the checkout, installed skill and skills directory.
   Use your own absolute paths below; Windows paths such as `C:/Users/you/...` work.

   ```sh
   python -I -B scripts/m6_package.py inspect --archive /absolute/downloads/cybersecurity-skills-1.1.0.zip --sha256 REVIEWED_ARCHIVE_SHA256
   python -I -B scripts/m6_package.py install --archive /absolute/downloads/cybersecurity-skills-1.1.0.zip --sha256 REVIEWED_ARCHIVE_SHA256 --skills-root /absolute/project/.agents/skills --state /absolute/private/cybersecurity-package-manager
   python -I -B scripts/m6_package.py diagnose --skills-root /absolute/project/.agents/skills --state /absolute/private/cybersecurity-package-manager
   ```

   Replace `REVIEWED_ARCHIVE_SHA256` with the 64-character digest in the reviewed
   release's checksum file. The helper checks the downloaded bytes against it;
   a checksum alone does not authenticate the publisher.
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

### Upgrade an existing managed installation

Download and review the new release, and obtain its trusted management checkout
as above in a new directory. Retain the previous management checkout for recovery;
do not delete or overwrite it. Run the new tool outside the skill being upgraded.
Reuse the **same skills root
and private management path** from the original installation; do not create a
second manager or overwrite the installed directory manually.

```sh
python -I -B scripts/m6_package.py diagnose --skills-root /absolute/project/.agents/skills --state /absolute/private/cybersecurity-package-manager
python -I -B scripts/m6_package.py update --archive /absolute/downloads/cybersecurity-skills-1.1.0.zip --sha256 REVIEWED_ARCHIVE_SHA256 --expected-installed-sha256 OBSERVED_INSTALLED_SHA256 --skills-root /absolute/project/.agents/skills --state /absolute/private/cybersecurity-package-manager
python -I -B scripts/m6_package.py diagnose --skills-root /absolute/project/.agents/skills --state /absolute/private/cybersecurity-package-manager
```

Replace `OBSERVED_INSTALLED_SHA256` with `installed_archive_sha256` from the first
diagnosis. Preserve private assessment state and backups outside the installation.
Local edits, extra files or an identity mismatch block the update for review.
Reload the skill afterward and start new assessment IDs: old evidence remains
historical, and currentness checks must pass again. See the
[recovery guide](docs/M6-QUALIFICATION.md#owned-installation-lifecycle) if an update
is interrupted.

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

For the most useful review, describe the rules your application must preserve:
which roles may access which records, what data is sensitive, and which recent
changes worry you. These details help the assistant assess your actual business
rules and explain what remains unverified. Ask it to prioritize findings by impact
and show how to retest each proposed fix.

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

The skill provides its own instructions and helpers. The table distinguishes
supported optional tools, candidate skills and tools used to develop this project.
No upstream skill is enabled by default. Nothing is installed or activated
automatically; selected resources must pass identity, currentness, license,
instruction and permission review.

| Resource | Purpose | Relationship to this skill |
|---|---|---|
| [Trivy](https://github.com/aquasecurity/trivy) | Secret/configuration leads and selected current advisory data | Opt-in adapter; binary and advisory data checked separately |
| [ZAP](https://github.com/zaproxy/zaproxy) | Passive analysis of admitted HTTP captures | Opt-in offline profile; no browser or active scan |
| [k6](https://github.com/grafana/k6) | Bounded load and concurrency measurements | Opt-in generated workload through the trusted request broker |
| [Cosign](https://github.com/sigstore/cosign) | Approved-key artifact/provenance verification | Opt-in profile with reviewed key and policy |
| Docker and official Python image | Bounded offline execution | Required only for operations using that backend; actual isolation must pass preflight |
| [Addy security and hardening](https://github.com/addyosmani/agent-skills/tree/main/skills/security-and-hardening) | Focused secure-development guidance | Candidate source-review resource; disabled by default |
| [Cloudflare security audit](https://github.com/cloudflare/security-audit-skill) | Source trust boundaries, counterevidence and focused review guidance | Opt-in guidance adapter starting with `1.1.0`; no upstream full-audit execution |
| [Vibe Coding Skill](https://github.com/pooyahayati/Vibe-Coding-Skill), security and interface specialists | Engineering and review of this repository | Development tools; not dependencies of the installed skill |

The [upstream source review](docs/SOURCE_REVIEW.md) is a maintainer research log:
it explains why repositories were considered and what requires review before
adoption. A listing there does not mean the skill uses that repository. The
[source catalog](config/sources.json) distinguishes research candidates from the
available opt-in guidance adapter; all remain disabled by default.
Docker, scanners and their data are not bundled with this package.

The [Cloudflare integration guide](docs/CLOUDFLARE-INTEGRATION.md) explains its
license, resource selection, private guidance packets and source traces. The
adapter keeps the mother skill in control of access, confirmation and fixes. It
requires current reviewed upstream resources and cannot silently use an older
copy. Use a published release containing the adapter and pass the ordinary
current-head checks; a version label in an unpublished checkout is insufficient.

## Practical limits

- Keep credentials, customer data, reports and assessment state outside the skill
  and outside Git. Review reports for sensitive prose before sharing them.
- Explicit target authority, current prerequisites and finite budgets remain
  required. Unavailable access or stale resources leave the affected work blocked.
- Package checks and reported findings are not a whole-application security
  verdict. The trusted operator, host account and Docker daemon remain part of the
  trust boundary; same-account compromise is outside local record protection.
- Qualification covers the supported individual operations, not a general
  operational assessment. The release does not imply automatic global
  installation, autonomous routing or support for unlisted platforms.

The release ZIP is fixed to its published source commit. This repository's main
branch can contain later documentation and unreleased capabilities; it is not the identity of an
already published archive. Original project code is [MIT](LICENSE); see
[third-party notices](THIRD_PARTY_NOTICES.md) for adopted-resource obligations.

## Author and license

Pooya Hayati · [https://pooyahayati.com/](https://pooyahayati.com/) · MIT

##
