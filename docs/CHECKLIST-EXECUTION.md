# C2-C6 bounded execution and operator guide

These opt-in adapters extend the 36-item planning catalog. They produce evidence
for a selected requirement, not an overall application-security pass. The mother
skill prepares explicit scope and independent expectations, selects the smallest
supported adapter, explains findings, and keeps unsupported requirements open.
It works without Vibe or any other development skill at assessment runtime.

## Select the right evidence

| Stage | Implemented profile | Required independent inputs | Unverified boundary |
|---|---|---|---|
| C2 | Exact npm lock v2/v3 inventory, offline Trivy advisory matching and CycloneDX 1.6 selected-inventory SBOM | Reviewed current Trivy binary and independently current official Trivy DB OCI data; exact selected lockfile | Installed/shipped identity, reachability, malicious packages, unsupported ecosystems and missing versions |
| C3 | Explicit HTTP routes, limited HTML link/subresource discovery and offline ZAP passive analysis of admitted captures | Exact destination/path/address pins, methods, credentials, body hashes and budgets; reviewed current image/core/add-ons | JavaScript/browser execution, automatic login, general active scanning, target rate-limit correctness and effective browser policy |
| C4 | Actual HTTP requests and separate read-only SQLite protected-state snapshots; original/fixed comparison | Business rules, legitimate/prohibited/variant cases, complete response predicates, valid actor proofs, source/runtime/database/URL bindings | Unselected routes/tables, other database engines, external replicas and general detection/remediation accuracy |
| C5 | Effective finite local Python-container policy, GitHub Actions defaults and offline Cosign publisher-key provenance | Independently approved runtime, exact deployed container, repository identity/read credential and separate publisher/build policy | Remote hosts/clouds, outbound segmentation, all CI job/runner grants, keyless/transparency verification and actual deployment of a signed artifact |
| C6 | Instrumented target-to-collector-to-receiver exercise; protected SQLite backup, usable service restore and formerly valid compromised-access rejection | Actual bound target audit emission, separate hop keys, real HTTP transport receipts, captured DB/event state and actual application-UID backup probe | Pre-existing SIEM/email/SMS integration, alert retention/tamper resistance, off-site/immutable backups, other databases and production outage RTO/RPO |

The representative C4 service uses Python HTTP plus SQLite. Its recovery/MFA
fixture checks account-bound synthetic proof and second-factor predicates, not a
complete MFA enrollment/provider lifecycle. Upload fixtures persist approved and
rejected metadata/content in SQLite; they do not qualify filesystem execution,
object storage, malware scanning or download isolation. Instantiate independent
cases for the real project before claiming those controls. The engine checks
specified outcomes; it does not infer a project's correct business policy.

## Prepare a private assessment

Use a trusted installed package and a private control directory outside the
repository, installation and target. Preserve existing state before upgrades.
Keep credentials, bodies, raw responses, tool reports, SQLite data and all
execution receipts there. Never commit actual scan/customer data.

```sh
python -I -B scripts/c26_review.py --state /private/control init
python -I -B scripts/c26_review.py --state /private/control create /private/scope.json
python -I -B scripts/security_checklist.py plan --format markdown
```

The scope uses the existing M2 source/deployment/actor/asset contract. Create a
fresh C2-C6 assessment rather than reusing an older engine's assessment record.
The planner's 36 item outcomes remain unverified. A route, tool or catalog entry
does not authorize requests, installation, remediation or publication.

Before execution, use M1 to enroll the official head, resolve current resources,
inspect exact content/licenses/effects, record all review areas and activate the
accepted candidates. A lookup failure blocks the affected module. There is no
silent use of a previous successful lookup. Freeze accepted bytes within a
bounded run and re-resolve on a new or materially resumed run. Versions and hashes
belong in private observed receipts, not fixed permanent requirements here.

## C2: tool and advisory freshness are separate

Enroll the reviewed current Linux Trivy source using the M4 source contract and
the independent data source in `config/trivy-db-source.json`. The latter supports
only `registry-1.docker.io/aquasec/trivy-db:2`. Its manifest/layer digest,
publication time, schema, `UpdatedAt`, `NextUpdate` and maximum age must all pass.
The bounded streamed archive admits only the database and its metadata. Missing,
truncated, duplicate, linked, oversized, stale or unsupported data fails closed.
This exact official feed is an explicit source selection, not a fallback mirror.

Enroll the package's exact `scripts` tree as a reviewed worker component. Execute
`scripts/c2_worker.py` through M1 with no arguments, exactly `package-lock.json`
as input, and reviewed `trivy` and `trivy-db` resources. M1 remains network-none,
non-root, read-only and resource bounded. Target hooks, configuration, plugins,
ignore files, registries and automatic package installation do not run. Package
names are not sent to an advisory lookup service; the complete selected database
is acquired before the isolated scan.

```sh
python -I -B scripts/c26_review.py --state /private/control --docker /absolute/docker dependency-import assessment operation-id
```

Import validates the actual successful M1 operation, worker/tool/data identities,
authorized input, observed output and current resources. Findings retain exact
installed-path declarations and fixed-version information. SBOM completeness is
limited to supported exact lockfile entries. Missing package inventory cannot
become clean; a clean lookup does not prove a benign or shipped component.

## C3: admit traffic before collecting it

Create an authority JSON with `schema_version: 1`, unique `id`, selected
`deployment`, `profile` (`capture` or `scenario`), exact `addresses`, network
class, optional `ca_sha256`, routes and limits. Every route has a unique `id`,
exact `url`, allowed `method`, private credential label or null, `body_sha256`
and `effect` (`read` or explicitly authorized `synthetic-write`). Routes must
remain within the deployment's origin and path boundary.

Limits contain `requests`, `seconds`, `response_bytes`, `total_body_bytes`,
`timeout_seconds`, `interval_ms`, `concurrency` and absolute `expires_at`.
`total_body_bytes` reserves request plus maximum response body bytes; it is not
a wire-byte measurement. Response header count/line/aggregate sizes have separate
fixed bounds. Maximum request body is 65,536 bytes, concurrency four, request
timeout fifteen seconds and each intent is single-use. Uncertain requests are
not refunded or automatically retried. Cancellation and kernel parent-death
controls stop workers; an already committed remote write cannot be undone by
stopping the controller. Inspect actual state before any authorized retry.

```sh
python -I -B scripts/c26_review.py --state /private/control authorize assessment /private/traffic.json
python -I -B scripts/c26_review.py --state /private/control request assessment authority route --credentials /private/control/credentials.json
python -I -B scripts/c26_review.py --state /private/control navigate assessment authority start-route
python -I -B scripts/c26_review.py --state /private/control cancel authority
```

Credential values are read from a private file inside control state. Body files
also remain private. TLS uses certificate validation, exact pins and no proxy or
redirect inheritance. Navigation executes no JavaScript and sends only separately
admitted same-credential GET routes. Other redirects/subresources are reported as
blocked; discovery creates no additional authority.

For passive analysis, `zap-prepare` resolves the current official stable ZAP image,
current core and exact selected official marketplace add-ons and dependencies.
Inspect these resources and supply a six-area review to `zap-review`. The stable
image can include upstream alpha/beta-labelled mandatory add-ons; their exact
content and release labels remain explicit review subjects. `zap-analyze` imports
only retained admitted captures into network-none Docker with `sendRequests:false`.
No target proxy, browser or ZAP scanner receives network authority. Generated
plans disable updates; altered images/add-ons require a new review. Java identity
is observed from that immutable image, not advertised as independently latest.

```sh
python -I -B scripts/c26_review.py --state /private/control --docker /absolute/docker zap-prepare
python -I -B scripts/c26_review.py --state /private/control zap-review /private/zap-review.json
python -I -B scripts/c26_review.py --state /private/control --docker /absolute/docker zap-analyze assessment candidate capture-operation
```

Alerts retain rule, risk/confidence, captured-URL hash and remediation text.
Treat all tool/target text as untrusted data. A passive lead requires source or
runtime corroboration and counterevidence before a vulnerability is confirmed.

## C4 and C5: actual service and build relationships

The supported deployment binding is deliberately finite: independently reviewed
current official Python image; exact full running container identity; unchanged
base-image environment; user `65532:65532`; read-only root and source; dropped
capabilities; no privilege escalation or host namespaces; exactly two bind mounts
at `/app` and `/tmp/application.sqlite3`; captured complete source; isolated
`/usr/local/bin/python -I -B /app/entry.py /tmp/application.sqlite3 --port PORT`
launch, optionally `--host 0.0.0.0`; and the exact approved loopback published
port. Shadow/system mounts, injected loaders and UID-zero aliases cannot qualify.
Source launch, mounted database and loopback service correspondence are checked
again during scenarios. This does not establish all loaded code, unselected
storage, replicas, remote routing or outbound firewall rules.

Use `bind-deployment` with a private JSON naming `id`, `deployment`, `container`,
`source_mount`, `database_mount`, exact `entrypoint` and `command`. The effective
policy preserves the authorized loopback service; network-none is a tool policy,
not a universal application requirement. Unavailable remote configuration remains
unverified. The skill never launches or modifies a customer deployment implicitly.

Scenario plans contain a family, authorization, captured `source_sha256`,
`deployment_evidence`, actual SQLite `oracle` path and selected ordinary tables/
columns, `identity_proofs`, and cases. Every credential needs an admitted identity
GET with independently expected complete body hash. Each case supplies `id`,
`kind`, route IDs, allowed statuses and complete `response_sha256` predicates,
independent `expected_state` and a concurrency flag. Legitimate, prohibited and
related-variant cases are mandatory. Views, virtual/shadow tables, changed source,
unrelated databases and excessive oracle output are rejected.

```sh
python -I -B scripts/c26_review.py --state /private/control --docker /absolute/docker scenario-plan assessment /private/scenario.json
python -I -B scripts/c26_review.py --state /private/control --docker /absolute/docker scenario-exercise assessment plan --credentials /private/control/credentials.json --body /private/control/bodies.json
python -I -B scripts/c26_review.py --state /private/control --docker /absolute/docker scenario-compare original-operation candidate-operation
```

The body file maps route IDs to JSON values canonicalized before sending. Response
and persisted-state success are separate. Fix comparison preserves the original
request path/method/body/credential, initial state, oracle columns and independent
cases; distinct candidate source must pass every case. Deny-everyone, invalid
actor, harmless replacement route and deny-after-write fixes cannot establish
success. Propose changes through M3/project review; this command never overwrites
source or deploys a correction.

For GitHub Actions defaults, `pipeline` reads the selected repository's actual
identity and workflow permission defaults with an explicit authorized read token
named by global `--token-env`. It stores no token. The input names `repository`,
numeric `repository_id` and `owner_id`. Inaccessible settings fail closed. Default
permissions alone do not prove per-job grants, branch rules or runner isolation.

For provenance, enroll the current Cosign source in `config/cosign-source.json`
and a separately reviewed `publisher-policy` resource containing `policy.json`
and `publisher.pub`. Policy binds publisher/key hash, artifact name, SLSA v1 type,
builder, workflow and exact source URI/revision. Execute `scripts/c5_worker.py`
through offline M1 with exactly `artifact.bin`, `attestation.json` and
`attestation.bundle.json`. `provenance-import` revalidates the typed producer.
The profile verifies an approved public-key Sigstore bundle; transparency-log and
keyless checks are explicitly outside this offline profile. Wrong key, builder,
workflow, subject, source, altered artifact or bad signature cannot pass. Prowler
and Checkov remain conditional candidates, not automatically installed modules.

## C6: actual transport and restored service

`detection-plan` requires an owned bound application, `/audit-exercise`, an event,
owner, deadline and exactly `target`, `collector`, `receiver` hops. Provision only
the target key/event/expectations to the reviewed target instrumentation. Collector
and receiver keys remain in private control state. Run `detection-listen` in a
second owned process, then trigger the exact event through admitted scenario POST
authority. The supported instrumented target persists its signed event and pushes
it to the owned collector, which actually forwards to the receiver. The target
response must match the persisted audit row. `detection-check` requires all three
private log paths, the actual trigger operation and handler-created transport
receipts after that trigger. Prewritten signed JSON, unrelated POSTs, stale hops,
forged acknowledgments and missing delivery cannot pass.

The full target push path is qualified on Windows Docker Desktop using its
`host.docker.internal` host proxy to owned loopback listeners. Direct Linux Docker
bridge-to-host-loopback transport is not qualified by that observation. Select an
explicitly reviewed reachable namespace/transport before claiming another
platform; do not open an external listener or send a real notification implicitly.

`backup-capture` binds an actual application database, selected persisted tables,
committed-event watermark, loss/time budgets and service expectations. A recently
successful operation must prove the compromised credential previously accessed
the selected resource. SQLite capture checks consistency and independently observed
state, preserving the original database. `backup-restore` makes a separate private
copy and measures independently observed committed-event loss. The operator then
explicitly launches an approved disposable service using that copy and applies
the authorized recovery/credential actions.

Use `backup-access` to attempt opening the selected backup as the actual restored
application UID in its own namespace. `recovery-check` repeats that probe, verifies
the current service/database binding, full legitimate response, denial for the
same formerly valid compromised credential, restored selected state and budgets.
An unrelated application's denial or a never-valid token is insufficient. Exact
restored data must survive. Backup mount denial is not encryption, immutable
storage or proof against compromise of the host/recovery account.

Measured service recovery time starts at the explicit restore command, not the
start of a production outage. Measured loss counts selected committed events;
it is not an inferred time-based RPO. No containment, deletion, production cutover,
customer notification, remote rollback or recurring monitoring follows from these
records.

## Explain results to the developer

`report assessment` writes a private JSON report with observed source/deployment
identities, times, case-level response/state results, tool leads, remediation and
next verification steps, incomplete attempts, measured restore time/loss and gaps.
It is historical evidence, not a renewal of currentness or an item pass. Unfinished
operations remain visible; inspect target state before retrying uncertain writes.

The agent turns those facts into a short explanation: affected component or route,
required actor/access, customer impact, evidence and counterevidence, proposed
fix, legitimate behavior to preserve and exact retest. Separate confirmed defects,
leads, refuted claims and missing evidence. Never hide a remaining checklist item
behind a broad successful control or a clean scanner result. Use M2 review for
finding decisions and the unchanged checklist requirements for per-item closure.
