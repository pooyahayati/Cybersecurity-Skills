# M5 capacity, recovery and incident contracts

M5 adds bounded observations through `scripts/m5_review.py`. Its distinct
`ResilienceReview` engine retains M1–M4 methods and rejects older entrypoints for
new cases. It is a development capability, not a general capacity certification,
production approval, incident-response service or stable security release.

## Workload boundary

The agent obtains explicit authority for an exact read route, environment, data,
purpose and budgets. A public URL or an HTTP GET method is not authorization.
Exclude action routes and customer-impacting operations. Only one GET/HEAD route,
status 200 and an exact complete-body digest are supported; redirects are refused.
M4 destination classes, TLS verification, all-address DNS validation and literal
socket pinning apply. Credentials travel to the trusted collector through private
stdin, never to k6, argv, generated scripts, reports or environment variables.

The optional current official k6 native binary emits tickets to a private random
loopback broker. Only first-party generated script is executed: no user scripts,
remote modules, extensions, browser, cloud outputs, proxy inheritance, telemetry,
dashboard or REST administration listener. k6 is a reviewed **host-trusted native
program**, not an OS-isolated adversary. It has no target credentials or target
URL. A separate trusted Python collector is the only target requester. M1 remains
offline; this adapter never grants network access to M1 target code.

Before every workload, the controller resolves the current reviewed head and k6
again. Missing metadata or changed resources blocks; an old cached success is
not a fallback. Exact release assets, publisher/repository identities and bytes
are retained in private records. Archive member `{version}` expansion uses the
resolved release only and cannot introduce traversal or path collisions.

Authority is consumed atomically before native execution. The complete request,
time and maximum-body reservation is never refunded; one origin lease prevents
overlapping workloads in the same private store, including version-query startup
and independently bounded request tails. Interrupted or uncertain work
cannot be resumed or replayed. Inspect the result and obtain new explicit
authority before another test. Separate stores are not a global fleet budget.
Each generated ticket names the workload capability, phase and a unique finite
iteration index. Duplicate, noncanonical or out-of-phase tickets cause no target
send; their rejection prevents a workload pass. Restart cannot restore tickets
because the persistent whole-workload authority is already consumed.

The broker admits at most the declared total and concurrency, spaces admissions
by the phase RPS ceiling with no catch-up burst, and enforces phase and aggregate
deadlines. Rate is measured at collector admission; network scheduling can bunch
arrivals at the server. DNS, TLS, complete-body collection and failures occupy a
concurrency slot. Each request uses a separate bounded process: the smaller of
the request timeout and abort latency is an absolute wall-clock limit across DNS,
TLS, headers and complete-body collection, including trickled responses. Crossing
it stops further admissions and terminates active collection. Enforcement polls
at short intervals, so process scheduling/termination adds bounded observation
overhead; these budgets do not promise real-time scheduling on a stalled host.
Parent heartbeat loss stops further
admission within one second; already admitted reads may finish within their socket
and hard worker deadlines. The worker has an independent absolute termination
timer. Cancellation kills the collector process; a surviving k6 process has only
an expired local broker destination and its own finite scenario deadline.

Supported ceilings are deliberately small: at most 100 requests, 8 simultaneous
collectors, 20 admissions/second, 6 phases, 300 seconds and 8 MiB reserved response
bodies per authority. Individual phases are at most 120 seconds. Production only
supports baseline/load read probes, at most 30 requests/30 seconds, 2 simultaneous
collectors and 2 admissions/second. Heavy or fault-inducing production scenarios
are unsupported. Local/staging baseline, load, stress, spike, soak and breakpoint
labels require a meaningful purpose and explicitly selected phases; a short run
labelled "soak" does not establish long-duration stability.

## Interpreting a load result

The report separates the planned requests, admitted/finished work, matching
successful responses, errors, overload responses and generator completion.
Measured latency includes request-process startup and connection/TLS/body time,
excludes broker queueing and
uses nearest-rank p50/p95/p99. Successful RPS uses the whole observed run, including
generator startup. These conservative sample metrics are not k6 broker latency.
The report preserves virtual-user limits separately from measured in-flight
requests and successful RPS. A VU count is never a throughput measurement.

Incomplete work, controller/generator failure, abort thresholds or any 429/503
response prevents a passing workload result. Other permitted error ratios and
latency/throughput criteria are frozen before execution. A matching result proves
only the stated sampled read workload. Target CPU/memory/queue saturation,
transaction correctness and capacity outside that workload remain unobserved.
Collect representative infrastructure metrics through an independently authorized
adapter before diagnosing a resource bottleneck or claiming service capacity.

## Independent persisted-state and recovery artifacts

The M1-only `m5_worker.py sqlite` accepts an explicit `m5-contract.json` plus
selected standalone SQLite snapshots. It copies a backup into a new disposable
directory, checks SQLite integrity, and checks finite ordinary-table projections.
Recovery mode also restores a separate rollback snapshot into another disposable
database. Original files remain read-only and their hashes are rechecked.

Each table needs exact columns, row count, type-aware canonical row digest and
one or more unique/idempotency key projections. Duplicate or null keys fail even
when the expected row digest matches. Key equality follows SQLite numeric equality
and the declared column collation; integer `1` and real `1.0` are equal keys, while
the state digest still distinguishes their types. Missing or generated columns
are unsupported. Changed values, missing rows and unreadable
backups fail. Digests preserve SQLite null/integer/real/text/blob distinctions;
blobs are represented by SHA-256. Results contain no row values. At most 8 tables,
16 columns per table and 10,000 rows per table are supported. SQLite parsing occurs
inside bounded offline M1, never on the host for target artifacts. No target code,
SQL scripts, views, virtual tables, extensions or custom commands are executed.

Provide a consistent standalone backup/export, not a live database. Present WAL
or SHM sidecars are rejected. Omitted uncheckpointed WAL cannot be inferred from a
database file: capture consistency requires independent evidence. M2 selected-file
limits also apply, so a selected artifact is at most 1 MiB in this release.

Actual disposable restore duration is measured against its frozen objective.
The difference between declared snapshot/reference times is reported separately;
those declarations do not prove RPO. A successful file restore is not service
RTO, application usability, deployment rollback or evidence that an HTTP endpoint
uses this database. Never upgrade an artifact result to those claims. A concurrency
assessment should independently capture post-workload state and compare it with
the business oracle; the URL-to-snapshot relationship remains an explicit gap.
The artifact criterion combines readable matching restoration, matching rollback
and the restore-time ceiling. The declared loss budget is a separate reported
criterion: artifact success never changes a failed declared-loss result to pass.

A recovery plan reserves a fresh random challenge and exact acknowledgment URL
before the M1 operation. After the restore, collect an M4 GET observation of the
receiver's complete canonical challenge response. Bind its operation, time,
deployment, URL, body digest and plan; reuse, pre-exercise and unrelated receipts
fail. Missing receipt stays missing. This observes a receiver assertion, not every
intermediate notification transport. The skill sends no notification itself.
Invalidating recovery evidence or its network producer retracts dependent alert
acceptance. Artifact restoration and alert evidence are reported separately.

## Incident custody and triage

An explicit incident event selects files already in the case's source scope.
The collector copies unchanged regular-file bytes into private exclusive objects,
checks originals again and appends an authenticated sequence with the previous
event digest. It never executes the evidence, cleans up a target, rotates a key,
changes access, sends messages or starts recurring monitoring. No automatic action
follows from text contained in an artifact or an incident note.

Events distinguish observation, hypothesis, proposed containment and proposed
recovery. Claimed event time and actual collection time remain separate. Private
notes are retained for the owner; exported reports expose their digest, not text.
Evidence reports expose content/path digests and byte counts, not raw contents or
private object locations. Every report verifies preserved object bytes and chain
sequencing. Missing/tampered objects remain visible as broken custody.

Bounds: 16 incidents, 64 events per incident, 16 files per event, 1 MiB per file
and 16 MiB aggregate preserved bytes per case. The owner controls private retention;
M5 does not silently delete evidence. HMAC records assume a trusted control account
and storage. They do not prevent an attacker who controls that account from rolling
back the entire store and are not an independent forensic timestamp authority.
The complete event is validated before writes, then its full bytes and private
object names are durably reserved. Failed or interrupted captures retain that
reservation and their partial evidence; repeated failures cannot create uncharged
objects. Reports separate incomplete captures from intact prior custody. The
64-event/1024-total limits include failed capture attempts; no silent refund or
automatic retry is provided.

## Verification boundaries

Use [M5 operations](M5-OPERATIONS.md) and [the evaluation protocol](EVALUATION.md).
Unit broker fixtures use an explicitly labelled fake generator with real HTTP
listeners. The M5 integration workflow additionally executes current official k6
and actual M1 Docker workers, persists duplicate transactions under concurrent
requests, and rejects an existing corrupt backup. These checks concern synthetic
local fixtures, not a customer deployment. Independent review and final-source
security scanning remain delivery gates. M6 qualification is separate.
