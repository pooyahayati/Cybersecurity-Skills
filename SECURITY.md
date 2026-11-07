# Security policy

This project is a development control plane. No stable application-auditor version
is currently supported, and repository checks do not certify target security.
M1 supports public GitHub acquisition and offline local Linux Docker execution;
see `docs/M1-CONTROL-PLANE.md` and `docs/M1-OPERATIONS.md` for the exact boundaries.

## Reporting a vulnerability

Do not put credentials, customer records, private endpoints, raw exploit output
or unredacted scanner artifacts in a public issue. Use GitHub private vulnerability
reporting if it is enabled on this repository. If no private reporting channel is
available, request one from the maintainer without disclosing sensitive details.

Include the affected project revision, supported environment, minimum safe
reproduction, expected and observed behavior, impact and any proposed correction.
Use synthetic data. Do not test unrelated systems to demonstrate a project issue.

## Project threat boundaries

Important boundaries include malicious target instructions, compromised upstream
skills/tools, path escape, forged or stale evidence, excessive tool authority,
private-data disclosure and unsafe production testing. Changes to these controls
need relevant regression evidence before an operational release.

The operator, controller, local OS account, Docker daemon and initial trust setup
are trusted. The private HMAC key does not defend against those authorities or
whole-state rollback. Keep control-state access and unrestricted host tools away
from untrusted agents. Container isolation depends on the host kernel/daemon;
this package does not claim resistance to their compromise. Explicit revocation
is implemented; automatic advisory ingestion and production scanning are not.

Publishing this repository does not authorize target testing, production changes,
security-research campaigns, or automatic uploads of private reports.
