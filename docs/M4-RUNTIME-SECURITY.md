# M4 runtime, infrastructure and delivery contracts

M4 implements bounded observations. It never establishes a whole-application
security verdict, approves a deployment, or changes target services. The agent
prepares the contracts and explains results; a novice should not have to select
scanner flags or author evidence records.

## Trust boundaries and available adapters

| Adapter | Actual behavior | Important boundary |
|---|---|---|
| Standard-library HTTP collector | One explicit GET/HEAD per worker, verified TLS, pinned socket, complete bounded response hashes and header predicates | No browser, crawler, form submission, login automation, arbitrary headers, query strings or mutations |
| Role comparison | Exact identity/tenant response predicates, same credential binding, complete resource-body predicates, positive and denied controls | Server assertions, not independent identity attestation; no persistent database-state assertion |
| Built-in infrastructure worker | Finite JSON configuration and Dockerfile/workflow lexical leads | Selected forms only, no cloud account discovery or complete IaC semantics |
| Trivy bundled-rule adapter | Current reviewed Linux binary in M1; secret and misconfiguration leads, private empty cache, explicit disabled target config/ignores | Current release's embedded rules only; no external check feed, vulnerability DB, Java DB, plugins or silent cached fallback |
| Local Docker observer | Exact immutable container ID and image inspect, minimized configuration and secret-presence leads | One container on an explicitly selected local Linux daemon, at the recorded time |
| Delivery correspondence | Compare declared artifact with observed container image and required role observations | Source-to-image build provenance and URL-to-container routing remain unverified |

Source analysis and source remediation use the existing M3 methods through the M4
entrypoint. A new M4 case uses its own engine identity: older entrypoints cannot
skip validation of new producer types. Recreate a case and reimport compatible
evidence when its engine or immutable scope changes. No historical record is
silently upgraded or overwritten.

The original Trivy command/normalization adapter acquires no tool automatically.
Trivy uses Apache-2.0; inspect the exact selected release's license and content
before activation or redistribution. No binary or rule content is bundled in this
MIT package. Its selected rules come from the current reviewed tool release.

## Network authority

An M2 URL declaration is not network permission. A distinct M4 authority binds an
assessment/deployment, exact methods and routes, explicitly permitted redirect
destinations, actor and credential references, complete response predicates,
address pins, optional CA digest, expiry and aggregate budgets. The owner must
authorize these read intentions; GET/HEAD alone does not prove that a poorly
designed endpoint has no side effects. Exclude action endpoints.

Only canonical ASCII HTTP(S) URLs without query, userinfo or fragment are
supported. Encoded separator/traversal ambiguity fails closed. All routes and
redirects stay inside the declared deployment origin and path. Redirects never
add a host, port, scheme or route, including for authenticated requests. Relative
redirects work when their exact resulting destination is explicitly listed.

Resolve all A/AAAA answers and require the complete set to fit the frozen literal
IP pins. Connect to one validated literal without resolving again; no retries.
Validate TLS against the original hostname with normal certificate validation,
TLS 1.2 minimum, and an optional exact operator-selected CA. Public, explicit
private, and local-only loopback classes are distinct. Link-local/metadata,
multicast, unspecified, reserved and IPv4-mapped IPv6 destinations are blocked.
Plain HTTP is limited to explicit local loopback fixtures.

CLI credentials are supplied separately from a file inside the initialized,
disjoint private control directory; other locations fail before a request intent.
They are passed to the child
through stdin, bound by private keyed digests, and never placed in arguments,
records or reports. Only Authorization and Cookie are supported. No ambient
proxy, netrc, cookie jar, client certificate or environment credential is used.
Set-Cookie values never update a session automatically. Changing credentials
requires new identity observations; compared nonanonymous actors must have
distinct credential bindings and identity predicates.

Each request intent is durable and single-use. Before every attempt, including a
redirect, reserve one request, its full timeout and maximum response-body bytes
inside the signed SQLite transaction. Failed or interrupted attempts do not refund
budgets. A worker deadline covers DNS, TLS, headers and body, including after
controller death. Cancellation stops subsequent sends and the controlling process
terminates its in-flight worker. A dead controller leaves unfinished evidence;
inspect it and use new explicit authority instead of replaying that intent.

Limits: 32 routes; 8 IP pins; 4 explicit redirect destinations per route; 100
requests; 600 reserved seconds; 15 seconds per attempt; 256 KiB per complete body;
8 MiB aggregate reserved body bytes; authority lifetime at most one hour. Headers
have separate fixed bounds. Compression, oversized/truncated bodies, ambiguous
framing, incomplete reads and unavailable transport never satisfy a predicate.

## Role and finding evidence

An authenticated resource comparison needs a complete successful identity response
with a frozen hash and the same actor/credential reference. Its observed keyed
credential binding must match the resource request. Identity must precede that
request by at most five minutes and remain within valid authority. The operator
records why the complete identity response identifies the intended user and tenant.

Compare exactly one legitimate positive control with one or more distinct denied
actors requesting the same exact URL and method. Every resource has a complete
body hash and expected status. Positive
control requires 200; denied controls use 401/403/404 plus the exact denial body.
A 200 login page cannot satisfy a 401/403/404 denial. A denied response with the
positive control's identical complete body fails even if its caller-supplied
predicate matches. Partial/transformed leakage needs independent content review;
hash equality is not general semantic leak detection. Dynamic bodies require a separately supported future
adapter; do not weaken an expected hash to manufacture a pass.

Results are observed predicate matches, mismatches or unavailable evidence. They
are not automatically confirmed vulnerabilities. Import actual HTTP operations as
the distinct `m4_web` evidence origin; bind deployment, actor, time, scope and
producer digest. Use existing finding/counterevidence, decision, coverage and link
commands for source/runtime reasoning. Source findings remain source evidence.
Revoked, expired, changed or invalidated producers retract dependent current claims.

## Infrastructure and scanner boundaries

The built-in worker recognizes selected Terraform JSON/plan, Kubernetes workload
JSON and IAM statement forms: privileged/host networking, root user, control-socket
mounts, literal sensitive environment assignments, public ACLs, wildcard Allow
permissions and worldwide management ingress. Dockerfile and GitHub workflow
lexical rules cover selected root/credential declarations, broad token permissions,
mutable action references and direct secret output. JSON parse failure is
inconclusive; unrelated files are unsupported. These finite rules do not model
interpolation, inherited policy, multi-stage build semantics or all data flows.

Both workers run through unchanged M1 offline Docker isolation. The adapter must
bind the complete selected source, actual operation/output, current reviewed worker
resources, runtime and scanner components. Trivy is acquired from its official
publisher with M1 release-asset verification and license review. It uses its exact
release-embedded rules and reports that choice explicitly; it does not call an
external rule/DB cache current. Requests for CVE or external-feed analysis remain
blocked until a compatible current data adapter exists.

Trivy receives fixed arguments with target configuration, secret configuration and
ignore-file loading disabled. Inline Trivy/tfsec suppression requires separate
review and is refused by this adapter. Target code, install hooks, scanner plugins
and arbitrary commands are not executed. Scanner excerpts and matching secrets
are removed before output leaves the isolated worker. Missing per-file results
remain `no_reported_result`, never proof that the file is safe.

The local-container observer requests only the exact authorized full container ID,
then its immutable image ID. It retains no environment values, mount source
inventory, raw inspect JSON or unrelated container listing. Configuration leads
need contextual review. No exec, host/cloud mutation or Docker socket mount into
an untrusted scanner is introduced.

## Delivery and reporting

Pre/post-release records require a running observed container matching the exact
declared artifact, the same deployment and valid successful role comparisons.
An old image, failed role comparison, changed source, wrong environment, expired
authority or revoked supporting observation blocks correspondence. A matching
application-supplied version header is not accepted as independent image evidence.

The supported result is declared correspondence for these separate observations.
It does not prove which container served a URL, all replicas, build provenance,
signed supply-chain attestations or that an M3 patch is deployed. Those gaps are
explicit even when the local image matches. Source and runtime findings can be
linked for investigation without promoting source acceptance to deployed success.

JSON and standalone Markdown reports retain IDs, locations, hashes, observed times,
authority, valid/invalid state, predicate outcomes, fixes and gaps. No raw response,
credential, cookie value, scanner match or container environment value is exported.
Review remaining operator-authored prose before sharing. Private HMAC records
detect inconsistent modification; they do not defend against a privileged writer
who controls both code and state.

## Primary technical references

- [OWASP SSRF prevention](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [Python HTTP client](https://docs.python.org/3/library/http.client.html) and [TLS contexts](https://docs.python.org/3/library/ssl.html)
- [Trivy filesystem flags](https://trivy.dev/docs/latest/references/configuration/cli/trivy_filesystem/)
- [Docker container inspect](https://docs.docker.com/reference/cli/docker/container/inspect/)

These references explain mechanisms; current selected tool identities are checked
at execution and recorded privately, not pinned in permanent skill policy.
