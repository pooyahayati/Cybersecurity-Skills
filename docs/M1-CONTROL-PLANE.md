# M1 implementation contract

M1 implements a control plane, not an application vulnerability scanner. The
supported acquisition source is public GitHub: stable releases, or an exact
default-branch commit only after absence of stable releases is established.
Selected repository files and digest-bearing release assets are supported.
Data/rule components have an additional operator-defined maximum data age.

## Trust and authority

The operator, controller code, OS account, local Docker daemon, HTTPS trust store
and explicitly enrolled publisher identities are trusted. Targets, downloaded
files, review documents, command output and imported JSON are untrusted. A local
HMAC key authenticates controller records; it is not protection against an actor
who controls this OS account, the controller, its database/key, Docker or the host.
Host tool permissions must keep those authorities away from an untrusted agent.

Control state must be outside the skill and target repositories. Private directory
permissions protect the key, SQLite records and evidence. Records are signed and
bound to their type and ID; user-authored `verified` flags are never accepted.
Transactions reserve shared execution budgets before launch. Private records are
not copied into Git, reports or container mounts.

## Acquisition, review and activation

1. Enroll a source specification with expected repository and owner numeric IDs.
2. Resolve fresh metadata in killable HTTPS workers with a 120-second wall limit
   including DNS, headers and slow bodies, no API/source redirects,
   no ambient proxy credentials and no fallback to cached success.
3. Fetch only selected files or verified release-asset members into quarantine.
   Reject links, traversal, special files, collisions, oversized or truncated data.
4. Produce a review packet containing identity, file digests and changes. The
   operator reviews instructions, dependencies, permissions, license, compatibility
   and provenance before issuing a bound acceptance through the controller.
5. Re-resolve freshness and verify bytes before atomically moving the active
   pointer. A failed update leaves the prior pointer intact but does not authorize
   its use as current. Head activation requires loading the accepted head; run
   preflight compares the executing package against its accepted resource bundle.

The package never runs candidate install hooks. Archive integrity is based on the
official release-asset digest; Git files also verify their Git blob identity.
Available commit verification metadata is retained. These checks do not claim
independent publisher-signature verification where it was not performed.

## Runs and restricted execution

A new or resumed run checks every selected component against the live source and
binds exact accepted bytes, data age, authorized arguments, input snapshots,
expiry and budgets. The head is mandatory. Failed resume invalidates the prior
run before checking; a prior successful receipt cannot restore permission.
Activating another component requires a fresh run or resume. Existing bounded
runs use their frozen resources; revocation and cancellation interrupt execution.

The initial execution backend is a local Linux Docker daemon, including a
compatible Docker Desktop Linux engine. There is no unrestricted native fallback.
The controller uses a reviewed current `python:3-slim` runtime image by immutable
digest, clears process environment, sets a non-root user, drops capabilities,
enforces no-new-privileges and explicit built-in seccomp, disables networking and health checks, mounts only
verified component/input snapshots read-only, and limits memory, CPU, processes,
scratch space, output, wall time and aggregate calls/time. An in-container deadline
also bounds work if the controller disappears. Actual create/inspect settings
must agree before start. Recovery removes only the controller's labeled containers.

The runtime image follows the official publisher's stable-major channel rather
than GitHub releases. Docker/Python on the host are prerequisites, observed and
compatibility checked, not automatically upgraded or claimed current by this
component policy. Network-enabled target tests and native host execution are
unsupported and fail closed. They require future reviewed backends; they cannot
be enabled by changing a scope flag.

## Acceptance and implementation order

- Implement strict source parsing and resolution, then private signed state.
- Implement quarantine, review binding, immutable objects and atomic activation.
- Implement head verification, run/resume, data expiry and revocation.
- Implement Docker isolation, transactional budgets, cancellation and recovery.
- Test malicious metadata, identity changes, stale/false versions, modified bytes,
  failed activation, forged records, stale feeds and permission escalation.
- Run real Linux container fixtures for protected-state preservation, no external
  network, no inherited secret, resource settings, timeout and cancellation.
- Review actual changed code independently, scan the delivery source, and observe
  the exact PR checks before merging. Record actual results in `STATUS.md`.

This boundary preserves all M1 requirements while making unsupported effects
explicit. M2-M6 assessment, remediation and production capabilities remain separate.

## Primary protocol references

- [GitHub releases API](https://docs.github.com/en/rest/releases/releases)
- [GitHub Git trees API](https://docs.github.com/en/rest/git/trees)
- [Docker execution controls](https://docs.docker.com/engine/containers/run/)
- [Docker network isolation](https://docs.docker.com/engine/network/drivers/none/)
- [Docker security options](https://docs.docker.com/reference/cli/docker/container/run/#optional-security-options---security-opt)
