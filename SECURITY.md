# Security policy

This project is a development foundation. No stable operational version is
currently supported, and repository checks do not certify target security.

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

Publishing this repository does not authorize target testing, production changes,
security-research campaigns, or automatic uploads of private reports.
