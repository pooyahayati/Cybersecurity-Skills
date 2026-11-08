# M4 operator guide

Read [the contracts and boundaries](M4-RUNTIME-SECURITY.md) before operation. The
agent prepares these documents for the user's authorized target. Examples below
are contract shapes, not authority to probe a listed site or local service.

## Entry and prerequisites

Use Python 3.11+ and the same private M1 state. Source scanners additionally require
the existing local Linux Docker backend and current reviewed M1 head/runtime/worker
components. Runtime HTTP uses the trusted host collector with separate authority;
M1 continues to reject all network-enabled untrusted execution. No Vibe skill is
required to install or operate this package.

```text
python scripts/m4_review.py --state PRIVATE_DIRECTORY init
python scripts/m4_review.py --state PRIVATE_DIRECTORY create PRIVATE_SCOPE_JSON
python scripts/m4_review.py --state PRIVATE_DIRECTORY plan ASSESSMENT_ID
```

`create` uses the unchanged M2 scope schema, including selected source, deployments,
actors/assets/flows and redaction literals. An M4 case is immutable. Changed
engine, source, role, environment or artifact requires a new case; old cases remain
historical. Source-only and URL-only cases keep inaccessible surfaces unverified.

## Authorize bounded HTTP observations

First enroll, prepare, semantically review and activate the current project head
through M1. The executing package must match its complete accepted resources.
`authorize` performs a fresh upstream check; failure has no stale fallback.

```text
python scripts/m4_review.py --state PRIVATE_DIRECTORY authorize CASE AUTHORITY_JSON
python scripts/m4_review.py --state PRIVATE_DIRECTORY request CASE AUTHORITY_ID ROUTE_ID --credentials PRIVATE_CREDENTIALS_JSON --ca PRIVATE_CA_PEM
python scripts/m4_review.py --state PRIVATE_DIRECTORY cancel AUTHORITY_ID
```

Omit credentials/CA options when not selected. The credential file must live inside
the initialized private control directory (or a private child directory). The CLI
rejects other locations before reserving or sending a request; this directory is
already disjoint from the package and target repositories.
Its shape is `{ "credential-id": { "header": "Authorization", "value": "Bearer SYNTHETIC_EXAMPLE_ONLY" } }`.
Cookie is also supported. No secret appears in the authority file or process args.

Authority fields are exact; unknown fields fail:

| Field | Value |
|---|---|
| `id`, `deployment` | Unique authority ID and existing deployment ID |
| `network` | `public`, `private`, or `loopback`; loopback requires local environment |
| `addresses` | One to eight explicit canonical IP pins; every DNS answer must belong |
| `ca_sha256` | Exact SHA-256 of the explicitly supplied ASCII CA PEM, or null |
| `routes` | One to 32 route records below |
| `limits` | `requests`, `seconds`, `body_bytes`, `response_bytes`, `timeout_seconds`, `expires_at` |

Each route has `id`, canonical `url`, `method` (GET/HEAD), declared `actor`,
`credential` reference or null, `kind` (identity/resource/web), `identity` route ID
or null, expected `statuses`, complete `body_sha256` or null, and `redirects` (zero
to four exact same-origin destinations). URL query strings are unsupported.

Identity/resource routes require GET and a complete body hash. Identity routes
require a credential, status 200 and no parent identity. Authenticated resource
routes reference an identity route with the same actor/credential. Anonymous
routes have neither. General web observations can omit a body predicate; they
cannot thereby satisfy a resource/role comparison.

Every route intent is consumed once. Examine its retained outcome after failure,
timeout, cancellation or interruption. Neither restarting the CLI nor a redirect
resets budgets. A new attempt requires a separately valid explicit authority.

## Compare roles

Collect each authenticated actor's identity route before its resource route, then
the anonymous/other denied resources. Supply:

```json
{
  "id": "record-access",
  "deployment": "staging",
  "policy_basis": "Explain who may read the selected synthetic record and why.",
  "identity_basis": "Explain how each complete expected identity response identifies its user and tenant.",
  "cases": [
    {"operation": "OBSERVED_WEB_ID", "identity_operation": "OBSERVED_IDENTITY_ID", "expectation": "allowed"},
    {"operation": "OBSERVED_DENIED_ID", "identity_operation": null, "expectation": "denied"}
  ]
}
```

```text
python scripts/m4_review.py --state PRIVATE_DIRECTORY compare CASE COMPARISON_JSON
```

Use actual returned operation IDs. The supported comparison has one positive
control and one to seven denied actors, distinct identities/credential bindings,
and recent valid identity observations. A recorded mismatch is useful evidence;
it does not become a confirmed vulnerability without review and counterevidence.

## Offline infrastructure/source scans

Enroll a tool component containing this package's complete `scripts` tree; prepare,
review and activate it with the head and current runtime. Authorize M1 selected-file
inputs and the exact Python entrypoint `scripts/m4_worker.py` with arguments
`["infra"]` or `["trivy"]`. M1 network remains `none`.

For Trivy, additionally enroll component ID `trivy`, kind `tool`, official
repository `aquasecurity/trivy` (repository ID 180687624, owner ID 12783832), asset
`trivy_{version}_Linux-64bit.tar.gz`, format `tar.gz`, member `trivy`, and no repository
file includes. Prepare/verify/review its actual current release and Apache-2.0
license before activation. Select `trivy` in the same M1 authorization. A 120-second
operation, 1024 MiB memory and 128 MiB tmpfs are useful starting budgets for this
adapter; adjust only within the existing M1 limits and actual authorized scope.

```json
{"id":"configuration-scan","operation":"ACTUAL_M1_OPERATION_ID","adapter":"infra"}
```

```text
python scripts/m4_review.py --state PRIVATE_DIRECTORY infrastructure CASE IMPORT_JSON
```

Use adapter `trivy` for that worker mode. The importer verifies exact command,
current worker manifest, all selected source, authenticated producer/output and
actual scanner version. Missing files/producers or altered output cannot qualify.
No output generated by a user or an arbitrary scanner command can impersonate it.

M3 commands `source-scan`, `trace`, `propose`, `export`, `test`, `accept` and
`source-report` are available on M4 cases using the documented M3 payloads. They
retain their original source/serialized-model limitations.

## Observe one local container and compare delivery identity

```json
{
  "id": "running-container",
  "deployment": "staging",
  "container_id": "EXACT_FULL_64_HEX_CONTAINER_ID",
  "expected_image": "sha256:EXACT_64_HEX_IMAGE_OR_REPOSITORY_DIGEST",
  "expires_at": 0
}
```

Replace placeholders and expiry with actual authorized values. The expiry must
be in the next hour. The explicit Docker executable is trusted host tooling.

```text
python scripts/m4_review.py --state PRIVATE_DIRECTORY --docker ABSOLUTE_DOCKER_PATH container CASE CONTAINER_JSON
```

This captures minimized read-only inspect fields, not a Docker exec or full host
inventory. Local image IDs and repository digests are separate immutable identities;
the expected digest must match one observed identity. Tag names are insufficient.

A release-check payload has `id`, `deployment`, `stage` (pre-release/post-release),
`artifact` (exact sha256 digest also declared in that deployment), `container`
(observation ID), `comparisons` (required comparison IDs), `reviewer` and `basis`.

```text
python scripts/m4_review.py --state PRIVATE_DIRECTORY release-check CASE RELEASE_CHECK_JSON
```

Success records only declared correspondence. It never establishes source-to-image
provenance, URL-to-container routing, other replicas, deployment permission or
overall security. Mismatched/stopped/expired/revoked evidence stays blocked.

## Findings, corrections and reports

Import a completed HTTP producer with `runtime-evidence`: an object containing
`operation` and `observation` (the M2 deployed-observation schema). Use its actual
finished time, no source file citations, the same deployment/actor, and expiry no
later than authority expiry. Its origin is `m4_web`, distinct from manual prose
and M1 source execution. Existing observe/finding/decide/coverage/link commands
retain M2 contracts; evidence-backed source/runtime relationships remain judgments.

```text
python scripts/m4_review.py --state PRIVATE_DIRECTORY invalidate-runtime CASE web OPERATION_ID
python scripts/m4_review.py --state PRIVATE_DIRECTORY invalidate-runtime CASE comparisons COMPARISON_ID
python scripts/m4_review.py --state PRIVATE_DIRECTORY invalidate CASE EVIDENCE_ID REASON_JSON
python scripts/m4_review.py --state PRIVATE_DIRECTORY report CASE
python scripts/m4_review.py --state PRIVATE_DIRECTORY evidence-report CASE
```

Runtime invalidation kinds are web/scans/containers/comparisons/releases. Reports
revalidate dependencies and mark stale results invalid. Report files stay private;
only their generated basenames are returned. Read the runtime and M2 evidence
reports together for concrete observed predicates, contextual findings and fixes.
Use `--help` for the complete command list. No command installs another skill,
updates customer code, modifies infrastructure or publishes a deployment.
