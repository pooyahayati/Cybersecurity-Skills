# M3 source review and remediation

M3 adds bounded source leads, structured specialist review and evidence-bound
patch proposals to M1/M2. It is an independent implementation using Python's
standard library. Neither Vibe nor a third-party skill is required at runtime.
This development milestone does not qualify a whole application as secure.

## Implemented adapters

| Adapter | Input and behavior | Support boundary |
|---|---|---|
| `builtin-source` | M1-isolated Python AST inspection and JS/TS/PHP lexical inspection of every selected file | Six finite rule families; findings are leads needing validation |
| `builtin-review` | Attributed source traces for architecture, application, identity, data, business, dependencies and secrets | Operator/agent reasoning, with exact source/context and current M1 component bindings |
| `addy-hardening` | Optional source-review guidance from `addyosmani/agent-skills`, selected through M1 enrollment, review and current-run preflight | Only `skills/security-and-hardening/SKILL.md` and explicitly reviewed supporting resources; no upstream code/hooks executed |
| `cloudflare-audit` | Optional current reviewed guidance packet and native source trace, bound to case/domain/run, resource and review hashes | Read-only guidance; no full upstream audit or automatic confirmation; unreleased main addition |
| Python serialized-model probe | Explicitly authorized execution of `security_probe(request, state)` inside M1 isolation; host compares observed JSON against frozen expectations | Synthetic, finite response/state model; no database, installed-platform or deployed-environment verification |

The upstream catalog remains disabled by default. The Addy adapter is implemented
but not installed, vendored or globally activated. Include the publisher's LICENSE
and review the exact acquired resources, permission changes and supporting links.
Its repository's MIT license was inspected during M3 development; each newly
acquired revision still needs its own license review. A link inside a skill does
not authorize another download or operation. The [Cloudflare adapter](CLOUDFLARE-INTEGRATION.md)
adds a separately selected subordinate guidance role with its own current source,
reviewed license and packet contract. Other unimplemented catalog adapters remain
future work. The mother skill retains scope, evidence acceptance and execution authority.

## Static analysis and its limits

The worker inspects only the M1 input snapshot, with at most 256 selected regular
files, 1 MiB each and 16 MiB total. Python syntax trees and lexical token inventories
are bounded at 60,000 items per file; the container also enforces memory, CPU,
time and output limits. At most 2,048 leads are returned. Source text and credential
values are never included in a lead. A parser/resource failure is a gap or failed
operation, not a safe result. Target imports, builds and package installation never
occur in static mode. Comments and ordinary quoted examples are not executable
tokens. Python parsing uses the selected current runtime's grammar.

| Rule | Examined forms | Important omissions |
|---|---|---|
| Dynamic code | Direct Python `eval`/`exec`, JS/TS/PHP `eval` calls | Aliases, wrappers, reachability and attacker control |
| Object deserialization | Selected Python object deserializers; PHP `unserialize` | Complete library configuration and data-flow interpretation |
| Constructed SQL | Python direct formatted/concatenated first arguments to query/execute calls | SQL in other languages, ORM semantics and indirect query construction |
| Literal credentials | Selected named Python and JS/TS/PHP assignments | Encoded, interpolated, split, unnamed or remotely loaded secrets |
| Session cookies | Explicit Python session-cookie disabling; JS/TS boolean options and PHP `ini_set` forms | Actual middleware, TLS, CSRF, expiry, rotation and deployment configuration |
| Sensitive logging | Selected Python logger calls using credential-named variables | Other loggers/languages and arbitrary personal-data names |

JS/TS/PHP inspection is explicitly `limited_lexical`, not a syntax parser. Template
interpolation, regular-expression literals, mixed PHP/HTML and framework behavior
can cause misses or false leads. File extension is not proof of platform identity.
Every lead stays `needs_validation`. There is no automatic vulnerability severity,
finding confirmation or control pass. Use M2 evidence/finding records to document
the actual source-to-sink path, prerequisites, customer impact and counterevidence.
No lead is a supported safe result only for the particular tested near-match;
it is never a whole-file or whole-project security verdict.

## Multi-angle review paths

Each trace names its actor, protected assets, concrete source locations, entrypoint,
untrusted input, guard, sink/effect, abuse case, counterevidence, conclusion and next
action. All seven domains remain visibly unreviewed until a valid trace is present.
A valid trace is attributed reasoning, not independently proven correctness.

| Domain | Required investigation beyond syntax leads |
|---|---|
| Architecture | Entry points, privilege boundaries, external dependencies, asset ownership and assumptions; reconcile with M2 actors/assets/flows |
| Identity | Login/recovery, session creation/rotation/expiry/revocation, CSRF, per-object and tenant authorization; anonymous, owner, non-owner and low-privilege paths |
| Data | Collection, response field allowlists, logs, caches, browser storage, exports, backups, retention/deletion and key access; inspect every copy of sensitive data |
| Application | Input to parser/query/filesystem/network/rendering sinks; distinguish validation, escaping and authorization |
| Business | State transitions, privilege ordering, price/quantity authority, idempotency and repeat/variant requests; concurrency remains M5 |
| Dependencies | Exact locked package/version, provenance/license and current advisory evidence; declarations do not prove installation |
| Secrets | Source/config/history references, log exposure, runtime access boundaries and rotation after actual exposure |

Dependency traces require an observed matching package/version in a selected
`package-lock.json`, `composer.lock`, `uv.lock` or `poetry.lock` location and a preflighted M1 data
component with an explicit maximum age. A package range or moving tag such as
`1.x`, `latest` or `dev-main` is rejected even if present in a lockfile. The adapter
recognizes concrete SemVer npm releases, normalized numeric Python releases with
pre/post/dev/local suffixes, and numeric Composer releases with optional stability
suffixes. Unsupported spellings/branch identities remain blocked. Advisory
interpretation and package-to-advisory matching remain reviewer judgments; this
is not an automatic vulnerability database client or a CVE-free certification.
Unavailable/currently stale data blocks that trace. Retain unsupported lock formats
and installed-version uncertainty. Network advisory tools are a later adapter.

WordPress/WooCommerce specialized execution remains unavailable: source markers
do not establish the actual installed version. Generic PHP leads are supported;
do not activate platform-specific assurance from a filename or framework mention.
When installed-version evidence and a reviewed compatible platform adapter become
available, route only the corresponding platform module. Do not install WordPress
or run customer code merely to fill this gap.

## Patch and retest contract

A proposal names a confirmed source finding supported by currently valid M2
evidence. Replacements bind exact old hashes, only selected existing paths and
new UTF-8 contents. The immutable private candidate contains all selected files.
No original target file is changed, no shell patch is executed, and no hooks run.
Export requires a new directory disjoint from source, package and controller state.
Review the actual candidate diff before applying it through the project's ordinary
authorized development workflow. Application/commit/deployment is never inferred
from candidate export or acceptance.

The frozen behavior contract contains one Python entrypoint and 3–24 cases.
Every contract needs legitimate, denied and distinct related-variant requests.
Each case specifies its declared actor, input, complete initial serialized state,
exact expected response/state and concrete prohibited response for denied cases.
Denied/variant expectations must preserve the entire initial state. Expectations
need an independent policy basis, not values copied from the candidate's output.
Use synthetic data only. Each request/state argument is limited to 3,072 bytes.

Run **all cases on both original and candidate** using the same contract. A crash,
timeout, failed parser or missing case cannot count as reproduced exploitation.
The baseline must preserve legitimate behavior and demonstrate at least one
prohibited response or protected-state change. Every candidate case must exactly
match, including legitimate behavior. A deny-everyone patch, deny-after-write patch
or missed related variant fails acceptance. Tests are immutable: a different fix
or new attempt gets a new proposal, preserving the failure history.

The host compares values; it accepts no target-authored `passed` flag. However,
the Python subject shares the probe interpreter and can falsify serialized results.
This adapter therefore establishes only a **declared serialized model**, and the
acceptance API requires an explicit reviewer assessment of the oracle, code and
remaining risk. It must not certify malicious target code, real database state,
actual session identity, network behavior or deployed protection. Such claims
require a separately isolated collector and applicable future runtime adapter.

Imported observations bind complete input manifests, exact worker arguments,
all shipped script resources, current-run producer identities and authenticated
output hashes. M1 checks freshness before a new/resumed run and bounds execution.
Forged output, changed dependencies/candidates, revoked authority, expired evidence
or stale advisory data cannot qualify. Reports re-evaluate validity; acceptance
does not survive a changed candidate/source or invalidated supporting finding.
The overall verdict always remains `not_established` and production verification
is always false. Historical observations do not assert current upstream freshness.

## Reports and compatibility

M3 produces private redacted JSON and standalone Markdown with lead locations,
review reasoning, fix advice, proposal files, test outcomes and remaining gaps.
Raw source, probe requests/responses and customer payloads are omitted. Redaction
is bounded pattern/literal masking, not a universal privacy classifier; inspect
free text before sharing. The output must remain private by default.

M3 cases use an engine identity covering the M2 engine plus all shipped scripts.
Create a new M3 case after code changes; existing M2 cases retain their own engine
contract and are not silently migrated. M3 scope/context refresh is rejected; create
a new case after changing roles, assets, flows or source. Use `m3_review.py observe/finding` for M2
records inside an M3 case, and `evidence-report` to inspect that ledger.

## References

- [Python AST documentation](https://docs.python.org/3/library/ast.html): parser behavior and resource caveats; the runtime must match selected syntax.
- [PHP unserialize documentation](https://www.php.net/manual/en/function.unserialize.php): untrusted object deserialization concerns.
- [OWASP authorization guidance](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html): per-request object/relationship checks and authorization tests.
- [Semantic Versioning](https://semver.org/), [Python version specifiers](https://packaging.python.org/en/latest/specifications/version-specifiers/) and [Composer versions](https://getcomposer.org/doc/articles/versions.md): concrete release identity versus moving constraints; no automatic dependency resolution is implemented.
- [Selected specialist source](https://github.com/addyosmani/agent-skills/tree/main/skills/security-and-hardening) and [license](https://github.com/addyosmani/agent-skills/blob/main/LICENSE): resolve and review current exact resources through M1 before use.

These are methodology references, not permanent runtime version pins or copies of
upstream skill content. See [M3 operations](M3-OPERATIONS.md) for the operator flow.
