# Bounded release contract and operator guide

The `1.0.0-rc.1` candidate prepares the existing bounded controls for release.
It is not a published stable release, a general vulnerability detector, a
certification, a guarantee against compromise or permission to test a system.
Read [observed results](../STATUS.md) before selecting a capability.

## Supported capability contract

| Capability | Supported behavior | Remaining boundary |
|---|---|---|
| M1 execution control | Current-source resolution/review, exact component identity, bounded offline Docker execution, private receipts | Requires current accepted prerequisites and actual host enforcement; no stale fallback |
| M2 scope and evidence | Explicit target/access scope, redacted findings, counterevidence and incomplete-coverage reports | Available evidence cannot prove unseen infrastructure or deployed correspondence |
| M3 source and correction | Finite source leads, reviewed proposals and authorized Python model retests | Syntax leads are not confirmed exploits; arbitrary languages/databases need additional reviewed evidence |
| M4 runtime and release | Exact authorized web reads, role comparisons, selected current Trivy secret/configuration rules, local artifact observations | No broad active scanning, remote administration, full CVE coverage or deployment approval |
| M5 resilience | Bounded read workloads, offline SQLite integrity/restoration, receiver acknowledgments and private incident chronology | No business-write load, whole-service recovery proof, automatic containment or recurring monitoring |
| M6 package management | Exact-source archive, data-only inspection, explicit-root managed install/update/uninstall, interruption recovery | Integrity is not publisher authentication; trust the management host and exclude foreign concurrent writers |

All eleven domain modules remain guidance. Optional specialists require current
identity and instruction review when selected; none is automatically installed or
required merely to load this skill. Version labels never bypass M1 freshness.

Python 3.11 and the current Python 3 release on Windows/Linux are the maintained
test matrix. Package management supports owned local directories. macOS, network
shares, power-loss durability and hostile writers with the same account are not
qualified. Docker, Git, Trivy and k6 are operation-specific external requirements,
not bundled dependencies. A Docker executable's presence does not prove isolation.
See the operation guides for actual preflight and explicit scope/budget contracts.

## Version and compatibility rules

Supported canonical labels are `0.MINOR.PATCH-dev`, `MAJOR.MINOR.PATCH-rc.N`
and `MAJOR.MINOR.PATCH`, where release major and candidate number start at one.
Numbers use ASCII digits without leading zeroes. Prefixes, build metadata,
arbitrary prerelease names and floating labels are unsupported. Archive and skill
metadata must agree. Candidate/stable packages must include lifecycle/support
content. The skill header accepts only its documented plain-scalar fields and
one `metadata` mapping with one author and version; duplicate keys, YAML aliases,
tags, quoted/block scalars and ambiguous comments are rejected. Packages must
preserve `maturity: bounded-qualification` and `operational: false`.
The latter means general operational assessment qualification is not established;
it does not deny the individually documented implemented controls.

The archive manifest and managed installation format remain schema 1. This
candidate changes no M1-M5 state schemas, command authority or assessment data.
Receipts stay outside the immutable install. Existing content-identity checks can
invalidate prior assessment evidence after an upgrade: preserve historical state,
create fresh required context and rerun affected checks. Do not rewrite history to
make old evidence appear current. M1 re-resolves actual source; a candidate label
does not make an unmerged archive the current official head.

The old development manager rejects release-candidate/stable version syntax.
Use the newly reviewed trusted management tool outside the installation for this
upgrade and retain it for recovery. Do not run the installed manager while that
same directory is being replaced. A future incompatible state change requires an
explicit migration and recovery contract before support is claimed.

## Install, inspect, upgrade and restore

1. Review the publisher, exact commit, license, changes and package digest through
   a trusted delivery channel. A digest supplied beside untrusted bytes is not
   publisher authentication. Inspect using the trusted external management tool.
2. Choose an explicit existing skills root and a new private management path
   outside it. Follow [package commands](M6-QUALIFICATION.md). Do not put customer
   evidence, credentials, notes or interpreter caches inside the managed skill.
3. Run the offline diagnosis after installation:

   ```sh
   python -I -B /trusted/source/scripts/m6_package.py diagnose --skills-root /chosen/skills --state /private/package-manager
   ```

   This checks actual owned bytes and reports package identity, version channel,
   Python/platform observations and prerequisite guidance. It does not start
   subprocesses, install anything, contact a service, load candidate code, check
   latest versions or prove runtime readiness. Missing/edited files or a pending
   transaction block diagnosis. A successful diagnosis alone does not authorize
   an assessment. Follow the selected M1-M5 operation guide next.
4. Stop active use before updating. Preserve the existing private manager and
   assessment state; retain the verified previous archive and a tested backup of
   private state, including its private permissions. Verify backup readability
   with the relevant operation before updating; stop if that check fails. A byte
   copy alone may not preserve required Windows access controls. Supply both the
   reviewed new archive digest and the observed
   currently installed digest. Local edits or unmanaged content block mutation;
   preserve and review them instead of forcing an overwrite.
5. On interruption, use `status` and the exact pending transaction ID with
   `recover`. After successful recovery inspect the returned installed digest.
   Explicitly restoring an older verified archive uses `update` with that archive
   and the current installed digest. Restoration preserves availability of files,
   not permission to run stale assessments. Changed instructions need a host
   reload and fresh M1 acceptance before operational use.

There is no automatic channel promotion, downgrade, global install, scheduled
assessment, cloud scan or release publication. Uninstall preserves private state
and unrelated skills. Sixteen retained archives are the existing bounded cache;
reaching the limit requires a separate preservation/maintenance decision.

## Qualification and release decision

`tests/installed_workflow.py` builds an exact-commit archive and runs the existing
M1-M5 workflow assertions using the managed installed modules, CLIs and worker
bytes. It records import attribution for parent and child controllers, verifies
the installed inventory again after each suite and keeps raw evidence private.
The copied test harness has no checkout scripts, configuration or documentation
beside it, so misplaced relative product-resource lookups fail. Synthetic publisher identities apply
only to owned head/worker fixtures; actual current tool metadata is still required.

`tests/host_discovery.py` checks a real host catalog in an isolated owned project
and home, with no model invocation, credentials or global installation. Catalog
registration is separate from autonomous routing, task quality and runtime
enforcement. Host protocol/version and unsupported hosts stay explicit in results.
The M6 static agent measurements remain historical; new operator observations
must use held-out requests and remain separately attributed.

Before a stable publication, require an explicitly authorized release, an exact
candidate commit, passing required platform and installed-workflow checks,
independently accepted security/contract review, no unresolved required control
failure, current prerequisite observations and native source/exact-artifact scans.
Rebuild and inspect the final stable-labelled asset, retain its digest and source
identity, and rerun affected checks after any change. Then publish only the tested
scope and actual results. A passing validator, version label, clean scan or merged
pull request is not that release decision and never an application-security pass.
