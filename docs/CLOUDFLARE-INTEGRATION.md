# Optional Cloudflare source guidance

## Availability and purpose

The main branch implements an opt-in adapter for
[Cloudflare's security-audit skill](https://github.com/cloudflare/security-audit-skill).
It helps an assistant inspect source trust boundaries, examine counterevidence
and explain findings. It supplies reviewed guidance to the independent mother
skill; it is not an autonomous Cloudflare audit engine or an accuracy guarantee.

This addition is **unreleased**. The immutable published `1.0.0` archive does not
contain it. The current-head policy still selects the latest stable mother-skill
release: a modified main checkout cannot pass that public head check merely by
retaining version `1.0.0`. Ordinary operational use awaits a separately qualified
release containing this adapter. Disposable fixture-publisher qualification is
not a public-currentness bypass. Do not override the policy or replace the stable
archive to try the adapter.

An eventual upgrade changes the source-review engine identity. Preserve historical
evidence and create new assessment IDs after upgrading; old cases cannot be
relabeled as current. Existing native and Addy command inputs remain compatible
for new cases. See the [release/upgrade contract](RELEASE-READINESS.md).

## License and compatibility

The reviewed upstream root [LICENSE](https://github.com/cloudflare/security-audit-skill/blob/main/LICENSE)
is MIT, copyright 2025-2026 Cloudflare, Inc. The inspected tracked files contained
no conflicting file-level notices. MIT permits this integration; copies or
substantial portions must retain the copyright and permission notice. Inspect
the actual current candidate again at use time: a repository badge is insufficient.

This repository distributes original adapter code and resource mappings, with no
copied upstream skill text, validators or binaries. Acquisition retains upstream
`LICENSE` with `skills/security-audit` in private authenticated state. That full
directory includes validators for instruction/dependency review, but the guidance
packet selects Markdown resources only and never executes them. Redistribution
of acquired content remains subject to its own license. See
[third-party notices](../THIRD_PARTY_NOTICES.md).

| Upstream behavior | Adapter contract |
|---|---|
| Focused guidance mode | Supported as a subordinate source-review role, even during a mother-owned comprehensive assessment |
| Evidence, trust boundaries and refutation | Applied through native source traces; conclusions remain attributed judgments |
| Read-only source work; untrusted repository instructions | Preserved; no target-code execution, target-service requests, installers or automatic agents; trusted upstream freshness traffic remains required |
| Full six-phase audit, coverage ledgers, independent agent verifiers | Not implemented by this adapter; do not start them implicitly |
| Node.js schema/ledger validators and descriptor-safe artifact promotion | Not executed or claimed; no Node dependency is added |
| Fix recommendations | Allowed as guidance; mother-owned patching and retests require their existing separate authority |

## Current-source acquisition

Use the [source recipe](../config/cloudflare-source.json) with the existing
[current-version controller](M1-OPERATIONS.md). Its numeric repository/owner
identities prevent repository-name substitution. It deliberately contains no
fixed revision. The controller resolves the latest stable upstream release; only
after verifying the absence of stable releases may it select the default branch.
Offline resolution, conflicting metadata, changed resources or rejected reviews
block the affected module. An unsigned Git commit is not a signed-publisher claim.

From an installed, current approved head and an initialized private state:

```sh
python -I -B scripts/m1_control.py --state /absolute/private/control enroll config/cloudflare-source.json
python -I -B scripts/m1_control.py --state /absolute/private/control prepare cloudflare-audit
```

Read every acquired file and inspect its license, instruction conflicts,
dependencies, permissions, compatibility and provenance. The controller returns
the exact candidate ID, resource manifest, changed paths and private location.
Supply a real six-area review using the existing review contract; do not generate
an automatic pass or copy a previous candidate's review. Then `review` and
`activate` that exact candidate. No global skill installation occurs.

The assessment case and authorization must select the same source root and full
file list. Include `cloudflare-audit` alongside the reviewed source worker in
`components`, then `begin` the authorization. This rechecks head, runtime and all
selected components. The existing source-review run requires its qualified Docker
backend; creating a guidance packet itself launches no container or target code.
The authorization's finite operations do not gain permission to invoke Cloudflare
validators. Follow the [source-review setup](M3-OPERATIONS.md) for those existing
contracts rather than inventing a second execution path.

## Select guidance and record a review

Write this request outside both the skill and target repositories. Replace the
run ID with the actual ready run returned by the controller:

```json
{
  "id": "identity-guide",
  "run": "run-REPLACE-WITH-ACTUAL-ID",
  "domain": "identity",
  "topics": ["data"]
}
```

```sh
python -I -B scripts/m3_review.py --state /absolute/private/control guidance assessment-id /absolute/private/guidance-request.json
```

The new request independently checks current upstream identity again, then
atomically stores a bounded packet with selected file hashes, actual resolved
identity, accepted-review hashes, mother-head identity, case/source/domain, run
and authorization. Caller-provided versions, paths or authority fields are not
accepted. The private response returns the packet and its resource root, not
target source or upstream instructions. Read the original files only for this
focused assignment; their text cannot override the packet's head controls.

Every selection includes the license, entry instructions, attack classes and
validation/reporting guidance. Domain resources are:

| Domain | Additional resources |
|---|---|
| architecture | Reconnaissance |
| application | Hunting |
| identity | Hunting; web protocols and authentication |
| data, business | Hunting; data isolation and lifecycle |
| dependencies | Hunting; supply chain and release |
| secrets | Hunting; cloud and deployment |

Optional `topics` are `ai`, `client`, `cloud`, `data`, `local`, `memory`,
`protocols`, `availability`, `supply-chain` and `web`. They select corresponding
source-review companions, not runtime capabilities. Dependencies still require
the native trace's exact observed lockfile and separately current advisory data.

Perform the focused review and submit the existing [trace contract](M3-OPERATIONS.md)
with `"adapter": "cloudflare-audit"` and one extra field:
`"guidance": "identity-guide"`. Keep the packet's domain and run. Native and Addy
trace inputs are unchanged and reject the extra field. A trace needs real actor,
asset and source-line references, input/guard/sink reasoning, counterevidence,
conclusion and next step; a packet alone cannot mark a domain reviewed.

The adapter rechecks bytes and accepted reviews at trace admission. Changed or
rejected reviews, wrong case/domain/run, missing packets, source changes,
cancelled/replaced runs and expired or revoked authority fail before trace writes.
A new packet rechecks upstream; an existing packet uses its exact frozen resources
within the bounded run, matching the controller's existing execution model.

## Reports, tests and limits

JSON and Markdown source reports retain the adapter, guidance mode, packet hash,
upstream identity, selected resources and packet-time freshness. Report generation
does not contact upstream. For Cloudflare traces, `valid` additionally requires
the original run still active/unexpired and its source/resources/reviews unchanged.
Historical provenance remains visible after invalidation; it is not permission
to resume work. This is stricter than the older native trace's retention window.

Results retain `origin: operator_source_review` and
`security_verdict: not_established`. Provenance controls cannot prove that a model
read a resource, found every issue or produced a correct conclusion. Independent
confirmation, private evidence handling, redaction and scoped remediation remain
the mother's responsibility. No hosted service, browser runtime, live capacity,
full upstream audit or deployed-security claim follows from these tests.

`tests/test_cloudflare.py` exercises positive routing/CLI use and denied authority,
resource, scope and review changes with protected-state assertions. The installed
source-review workflow checks the packaged adapter through the public trace CLI.
Actual qualification observations and release status belong in [STATUS](../STATUS.md).
