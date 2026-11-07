# Current-version and integrity contract

M1 implements this contract for public GitHub components and one official Docker
runtime channel. Read [the operator guide](../docs/M1-OPERATIONS.md) for supported
schemas, explicit trust assumptions and commands. Other source/backend adapters
remain unimplemented; this policy does not grant them an execution bypass.

## Resolution

Before a new assessment, verify the head and selected skills/tools against explicit
official sources. Prefer the latest non-draft, non-prerelease stable release. If a
project has no stable release, resolve its authoritative default branch to an exact
commit and label it as a commit, not a stable release. Do not interpret a timeout,
authentication failure or malformed response as proof that no release exists.

Vulnerability databases, rule packs and templates have their own current identities
and update metadata. Checking a binary version is not checking its data. Evaluate
maintenance and known revocations separately: the newest abandoned release may
still be unsuitable.

## Acceptance and activation

Record canonical publisher/source, selected channel, version when available,
immutable revision/digest, observed time, retrieval evidence, integrity checks,
available provenance, compatibility results and any limitations. A digest detects
content change but does not authenticate a publisher by itself.

Fetch a candidate into quarantine with restricted credentials and network access.
Inspect changes to instructions, executable hooks, dependencies, permissions,
outputs and licensing before execution. Test the relevant adapter contract and
security behavior. Activate atomically after acceptance; recover safely from an
interrupted update. An updated head requires reload and repeated preflight.

Verify actual executed paths and identities. An old binary found earlier in PATH,
an old cached rule pack or a self-declared version string cannot satisfy the check
without corroborating source/artifact evidence. A source migration or publisher
change requires review rather than an automatic new trust relationship.

## Run binding

Freeze accepted resources for a bounded run. Record the exact selected set outside
the product and target repositories. Recheck at a new assessment, a materially
resumed run or first activation of another module. Define bounded receipt validity
from the source and risk; do not invent one universal cache lifetime. Known
revocation or critical advisory invalidates affected work immediately.

Policy must not hardcode permanent component versions. Exact execution pins are
required evidence, not a waiver of current-version resolution. Audited application
versions remain separate; do not auto-upgrade the application to fit the auditor.

## Failure behavior

Unavailable required metadata, insufficient source verification, incompatibility,
invalid integrity, stale data or a failed check blocks the affected module. Never
silently use a previous version and call it current. A retained previous artifact
may support recovery of the tool installation, but cannot meet the current-version
gate. Continue independent safe planning with an explicit coverage gap.

Do not let unsigned agent-written success flags authorize execution. The M1
controller signs private state with a local HMAC key and verifies it before use.
The controller, operator and OS account are trusted; an actor controlling the key
or host can forge or roll back state. Explicit revocation is implemented; automatic
advisory discovery is not. If the host cannot enforce isolation or permissions,
block affected execution and do not claim host-enforced protection.
