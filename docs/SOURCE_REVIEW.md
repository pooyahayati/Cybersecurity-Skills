# Upstream source review

Initial research: 2026-11-07. Candidate-health follow-up: 2026-11-09.
This is a review of published instructions and declared
capabilities, not an empirical ranking of vulnerability-detection accuracy. Recheck
the current source, adopted paths and licenses before any integration.

| Source | Best use | Integration constraint |
|---|---|---|
| [briiirussell/cybersecurity-skills](https://github.com/briiirussell/cybersecurity-skills) | Broad application/API assessment, business logic, finding triage, secrets, dependencies, cloud/container/CI reviews | Adapt evidence paths, scope and authorization defaults; review individual skills rather than importing the collection |
| [trailofbits/skills](https://github.com/trailofbits/skills) | Deep source context, differential review, false-positive checks, variant analysis and post-patch validation | Review CC-BY-SA-4.0 obligations; adapt heavy workflow assumptions and retain unresolved findings rather than forcing binary outcomes |
| [cloudflare/security-audit-skill](https://github.com/cloudflare/security-audit-skill) | Evidence quality, refutation and source-bound coverage | Its source-oriented, sandboxed workflow is not a drop-in runtime testing or patching workflow |
| [addyosmani/agent-skills](https://github.com/addyosmani/agent-skills) | Secure-development baseline and focused hardening guidance | The security-auditor persona is not a complete assessment lifecycle; reconcile composition and approval defaults |
| [openai/skills](https://github.com/openai/skills) | Historical reference only | Upstream declares this catalog deprecated; disabled and unsuitable for new enrollment |
| [openai/plugins](https://github.com/openai/plugins/tree/main/plugins/codex-security) | Selected threat-model, source-review and validation resources | Current successor candidate, not a drop-in independent runtime; review host/protocol requirements and exact resource licensing |
| [WordPress/agent-skills](https://github.com/WordPress/agent-skills) | Version-aware WordPress plugin and REST guidance | Activate only on platform evidence; distinguish capabilities from nonces; inspect GPL-2.0-or-later obligations before redistribution |
| [getsentry/skills](https://github.com/getsentry/skills) | Targeted source-review patterns | Do not inherit blanket exclusions for authenticated paths; authorized-user abuse is in scope |
| [mukul975/Anthropic-Cybersecurity-Skills](https://github.com/mukul975/Anthropic-Cybersecurity-Skills) | Individually reviewed niche references | Community project, not proof of affiliation or accuracy; large catalog size is not validation |

All candidates remain disabled. `config/sources.json` records the reviewed short
list, not an install queue. MIT applies to this project's original content only.
See `THIRD_PARTY_NOTICES.md` for adoption records and license handling.

## Checklist-driven candidate decisions

Use [C1-C6](CHECKLIST-ROADMAP.md) for implementation order and acceptance gates.
The 36-item catalog is an original operational interpretation, not copied upstream
skill content. No new third-party implementation or rules are vendored in C1.

- ASVS and WSTG supply requirements and test methodology. Their published stable
  editions differ from moving development content; chapter references are not
  complete mappings. Review CC-BY-SA-4.0 obligations before adopting text.
- Prefer completing the selected Trivy dependency/data adapter before adding
  [OSV-Scanner](https://github.com/google/osv-scanner) for a demonstrated gap.
  Binary freshness does not prove advisory-data freshness, and network queries
  can disclose package names/versions. Automatic fixes may invoke package scripts.
- [Semgrep licensing](https://docs.semgrep.dev/licensing) distinguishes its CE
  engine from maintained and third-party rules. Do not treat LGPL engine licensing
  as permission to redistribute every rule set or use proprietary capabilities.
- [ZAP](https://github.com/zaproxy/zaproxy) needs a separately reviewed runtime,
  add-ons and network/effect authority. [testssl.sh](https://github.com/testssl/testssl.sh)
  is conditional TLS coverage, not a browser or application-logic audit.
- [Prowler](https://github.com/prowler-cloud/prowler),
  [Checkov](https://github.com/bridgecrewio/checkov) and
  [Cosign](https://github.com/sigstore/cosign) address distinct cloud, IaC and
  publisher/attestation questions. Select them from an observed target need.
- [Gitleaks](https://github.com/gitleaks/gitleaks) states that future releases are
  security patches only and directs new feature development to
  [Betterleaks](https://github.com/betterleaks/betterleaks). This is not evidence
  that existing Gitleaks releases are unsafe. Betterleaks is a disabled candidate;
  inspect its actual stable channel, environment flags, outbound credential
  validation/analysis and optional revocation before any adoption.

These are dated research observations, not continuously refreshed health claims.
Exact resource review and current-source preflight remain required at use time.

## Standards and tools

- [OWASP ASVS](https://asvs.owasp.org/) supplies a versioned application-verification
  baseline. Top Ten awareness lists are not a complete test specification.
- [OWASP cheat sheets](https://cheatsheetseries.owasp.org/) supply specific controls,
  including session, secrets and AI-agent guidance. Resolve current guidance and
  apply it to the actual threat model rather than copying every example.
- [Trivy](https://github.com/aquasecurity/trivy) is a scanner for supported artifacts,
  dependencies, secrets and configuration; it is not an application-logic auditor.
- [Semgrep documentation](https://semgrep.dev/docs/) describes source-analysis
  capabilities. Distinguish community and paid features when choosing adapters.
- [ZAP documentation](https://www.zaproxy.org/docs/) supports scoped runtime checks.
  Crawling still sends requests; active testing requires an appropriate scope.
- [k6 test types](https://grafana.com/docs/k6/latest/testing-guides/test-types/)
  inform capacity scenarios. Define workload and protected-state outcomes first.

Nuclei or other template-based tools are optional later adapters, with reviewed
templates and explicit scope. No tool is mandatory merely because it is listed.
Security tooling itself is a supply-chain dependency; verify source, integrity,
instructions and permissions instead of trusting a newest-version label.
