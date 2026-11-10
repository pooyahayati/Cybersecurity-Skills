# Checklist completion roadmap

The [coverage matrix](CHECKLIST-COVERAGE.md) maps the 36 items in the selected
Security Audit section. This roadmap separates delivered planning capability
from separately qualified adapters and target-specific verification. The current
bounded profiles are described in [the execution guide](CHECKLIST-EXECUTION.md);
the exits below remain unchanged and actual results belong in STATUS.md. It is not permission to
install every candidate, send requests, publish a stable release or change a
customer system. M1-M6 authorization, evidence and freshness contracts remain.

## C1 - Complete coverage inventory and assessment planning

Deliver a stable identifier for every source item; existing capability and its
limits; minimum evidence; a legitimate case; a prohibited-effect case; acceptance
criteria; remaining work; and the next implementation phase. Generate an offline
36-item plan with unknown applicability and unverified outcomes. Validate complete
coverage, references, identities and the prohibition on execution/readiness claims.

Keep the legacy M2 catalog and stored assessment schemas unchanged. A checklist
item can reference a broad legacy control as a routing aid, but must retain its
own evidence and outcome. An accepted broad control does not automatically close
its child items. The planner does not import a filled template as authenticated
evidence, perform an assessment or mark items passed.

**Exit:** all 36 items remain present; missing, duplicated, remapped or invented
items and promoted defaults fail validation; installed-package planning works;
source and target results remain distinct; focused checks and independent review
pass. C1 completion does not close C2-C6.

## C2 - Current dependency and artifact inventory

Prefer extending the existing Trivy adapter where its supported ecosystem and
official data-distribution mechanism fit. Evaluate OSV-Scanner as an alternative
for a demonstrated coverage gap, not a mandatory second scanner. Establish the
actual lockfile and shipped/build artifact boundary; support explicit ecosystems
first and retain unsupported and missing-version results. Add SBOM output only
with an explicit completeness/support statement.

The data-acquisition adapter must identify the official feed, resolved revision
or publication/observation time, complete selected data, integrity and maximum
age. The tool binary, rules and advisory data are independent freshness subjects.
No failed lookup may silently use cached success. Observe actual scanner identity
and data use; isolate scanning from target hooks/configuration, credentials and
network. Review network disclosure of package names and versions before lookup.
Do not enable automatic dependency remediation that can invoke package scripts.

**Exit:** a known vulnerable fixture is attributed to the correct exact component;
a supported fixed near-match remains distinct; stale, missing, truncated and
unsupported data cannot pass; target suppression/configuration cannot hide the
fixture; no target script or unauthorized network effect occurs; the exact
packaged adapter works with an actual current tool/data source. A clean selected
lookup does not prove reachability, installed identity or benign dependencies.

## C3 - Broader authorized web and browser verification

Evaluate a selected ZAP automation adapter for concrete gaps in the M4 exact-read
collector. Treat browser/Java dependencies, add-ons, rules and active scan plans
as separately reviewed executable inputs. Start with selected response/header and
route coverage; add login/session and active methods only with their own tested
authority. testssl.sh is a conditional candidate for TLS configuration coverage.

Do not weaken or repurpose M1's offline backend. A network-capable backend must
enforce exact destinations, redirect scope, methods/effects, credentials, aggregate
request/rate/concurrency/byte/time limits, cancellation and controller-death stops.
Crawler, passive-traffic collection and browser subresources still send requests.
No external scan service, target-supplied script, automatic authentication flow or
floating add-on update is implicitly authorized.

**Exit:** owned fixtures show legitimate navigation and selected checks work;
cross-origin redirects/subresources, disallowed methods, unexpected authentication
destinations and exhausted budgets cause no prohibited request; sensitive bodies
and credentials remain private; actual current-tool execution is observed. Browser
and semantic security claims need browser observations, not header presence alone.

## C4 - Project-specific security and remediation scenarios

Build reusable scenario contracts, then instantiate them against the actual stack
and independently specified business rules. Select a representative disposable
application before claiming runtime qualification. Cover account recovery and MFA,
session revocation, owner/non-owner/tenant boundaries, field and operation access,
file handling, webhook signature and replay, transaction idempotency/concurrency,
secret rotation, and retention/deletion across data copies.

Each exercised scenario needs positive, denied and related-variant cases; an
independent protected-state oracle; exact source/deployment identity; controlled
data; and original/candidate results when validating a fix. Test response and
durable state separately. A controller's own authentication, budgets or custody
must not be reported as evidence of the target application's controls.

Use selected Trail of Bits, Cloudflare or Brii guidance only after exact-resource
review and compatibility with the mother skill. Candidate reports enter M2's
evidence and counterevidence process; specialist prose cannot self-approve a fix.
Semgrep is a source-analysis candidate, with its engine and each rule set reviewed
separately. External packages do not replace actual language/framework knowledge.

**Exit:** the original protected-state failure is independently reproduced, the
correction blocks it and related variants, and legitimate behavior is preserved.
Retain misses, false alarms, failed fixes and untested platforms. Follow EVALUATION.md
for any claim about agent detection or remediation quality.

## C5 - Infrastructure and build provenance

Choose Prowler only for an observed supported cloud account and read authority;
consider Checkov only where required IaC coverage is missing from the selected
Trivy path. Use Cosign or another separately reviewed verifier for a concrete
publisher/attestation policy. A digest alone cannot establish publisher identity.

Bind observations to effective settings, selected resources and the actual
environment. Verify host/database/web-server configuration, exposed services,
privileged identities, network separation, hosted pipeline settings and artifact
provenance. Configuration declarations, a local image and URL observations are
separate facts until their relationship has independent evidence.

**Exit:** misconfiguration and safe near-match fixtures are distinguished; wrong
publisher/signing identity, tampered artifacts and inaccessible settings cannot
pass; ordinary authorized operation survives correction. Remote mutation and
deployment remain separate authorized actions with recovery requirements.

## C6 - Detection, backup security and service recovery

Define target audit events, retention/integrity controls, detection rules, actual
receivers, escalation ownership and exercise criteria. Correlate the synthetic
event through the log and alert transports; an assessor receipt is not proof of
the target pipeline. Use tabletop and disposable-service incident exercises.

Test backup access and independent protection against a compromised application
identity. Restore representative data and a usable application; establish capture
time and loss independently. Add database-specific adapters only for selected
engines. Distinguish backup-file integrity, declared loss, measured service RTO,
actual RPO and restored application behavior.

**Exit:** unreadable/inconsistent backups, missing alert hops, forged acknowledgments,
incorrect restored state, excess loss and retained compromised access remain failed
or unverified. Originals and evidence survive. No automatic containment, cleanup,
notification sending or recurring job follows from an incident artifact.

## Candidate selection and currentness

The [source review](SOURCE_REVIEW.md) and disabled catalog record research, not
installed capabilities. Prefer the smallest adapter that closes an observed gap.
Before adoption, inspect exact content, host assumptions, dependencies, license,
permissions and outbound effects; run applicable legitimate/prohibited fixtures.
Keep optional upstream failure local to that module while reporting the gap.

Resolve the current stable release or, only when none exists, the authoritative
default-branch revision. A default branch may be development; an upstream release
named `latest` may be explicitly bleeding edge even when its API prerelease flag
is false. Review the publisher's channel semantics before activation. Never
silently turn a deprecated source, unsupported stable channel or unavailable feed
into current accepted evidence. Freeze accepted resources within a bounded run;
refresh before a new/materially resumed run. Record exact observed versions in
private receipts, not fixed version requirements in this roadmap.

## Delivery and stable-release follow-up

C1 planning and the selected C2-C6 profiles are merged. Their measured support
boundaries and the subsequently observed contention failure/correction are in
[STATUS.md](../STATUS.md). Their exit requirements below are retained unchanged;
implementation does not close a target checklist item. Continuing release
gates are tracked separately in the [release checklist](RELEASE-READINESS.md#stable-release-checklist).
Stable `1.0.0` adds new bounded novice observations and actual candidate upgrade
qualification. These do not replace a target's per-item evidence or expand the
supported profiles. The authorized stable release is published and its public
ZIP/checksum downloads match the approved archive. Future publication remains a
separate explicit delivery decision.

## Release decision

A bounded release may publish only the supported scope actually tested and
independently accepted. A broader claim of checklist execution requires the
corresponding C2-C6 gates, platform support and retained results. Updating a version
label, adding a candidate repository, completing C1 or passing a structural
validator cannot substitute for these outcomes.
