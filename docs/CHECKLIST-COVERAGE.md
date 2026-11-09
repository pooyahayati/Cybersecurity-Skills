# Security checklist coverage

This profile translates the 36 items under **Security Audit** in the
[service checklist](https://pooyahayati.com/services/software-audit-security/checklist/)
into original English operational requirements. Review date: 2026-11-09.
The authoritative maintained inventory is [security-checklist.json](../config/security-checklist.json).
Read the [implementation roadmap](CHECKLIST-ROADMAP.md) for missing capabilities.

## Three independent questions

1. **Capability:** what this skill can currently do, with its support limits.
2. **Applicability:** whether an item applies to the selected system, based on evidence.
3. **Outcome:** what the actual review or test established for that system and revision.

These questions must not be merged. All generated target outcomes are `unverified`
and applicability is `unknown`. Existing helpers have bounded support; none of the
12 broad domains is universally qualified. The original 11 guidance modules and
12 M2 control templates are retained. They are not 36 independently completed
checks, and a broad template cannot automatically close its finer items.

## Prepare a plan

Run from a trusted checkout or verified installed package:

```sh
python -I -B /trusted/cybersecurity-skills/scripts/security_checklist.py validate
python -I -B /trusted/cybersecurity-skills/scripts/security_checklist.py plan
python -I -B /trusted/cybersecurity-skills/scripts/security_checklist.py plan --format markdown
```

The command reads packaged resources and prints a plan. It contacts no service,
imports no target code, activates no tool and writes no assessment state. Save
its output in the owner's private assessment area outside this and the target
repository. Keep credentials and customer values out of the plan. It is not a
completed assessment, signed receipt or new M2 state format.

For an actual assessment, bind each selected item to exact assets, actors,
environment, source/deployed revision and allowed effects. Record observations
through the applicable M1-M5 methods and M2 evidence ledger. Reference those
records separately for each checklist item, with reviewer, observation/expiry
times and outcome rationale. Preserve missing access, inconclusive results and
unsupported surfaces. A not-applicable decision needs concrete evidence.

The catalog's minimum evidence, legitimate case and prohibited-effect case are
requirements and proposed tests, not observations that those tests were run.
Its legacy-control mapping is a routing aid. Existing ASVS chapter references are
not complete requirement-level mappings or a certification claim. Adopt actual
versioned ASVS/WSTG requirements during the selected phase and retain the mapping
and any exceptions with the assessment.

## Per-item matrix

`C1` supplies planning and evidence requirements. `C2` through `C6` are future
implementation/qualification phases. A row's phase does not change its current
target outcome, which remains unverified until supported by actual assessment.

<!-- checklist-matrix:start -->
| Item | Required check | Existing bounded support | Remaining gap | Phase |
|---|---|---|---|---|
| audit-01 | Identify protected assets and trust crossings | m2-evidence, m3-source | No automatic complete architecture discovery or proof of the actual deployed topology. | C1 |
| audit-02 | Derive system-specific abuse scenarios | m2-evidence, m3-source | Threat completeness and prioritization require project-specific reasoning and review. | C1 |
| audit-03 | Evaluate prevention and impact-limiting controls | m2-evidence, m3-model | The model probe cannot prove deployed or persistent-state protection. | C4 |
| audit-04 | Review account creation, recovery and stronger authentication | m3-source | No generic login, recovery or MFA execution adapter. | C4 |
| audit-05 | Verify the complete session and token lifecycle | m3-source, m4-web | Cookie leads and exact reads do not execute or verify the complete lifecycle. | C4 |
| audit-06 | Check account-abuse resistance | m3-source | The auditor's own request budget is not proof of target authentication throttling. | C4 |
| audit-07 | Check operation, object, file and field permissions | m3-source, m3-model, m4-web | Actual write effects and all alternate endpoints require a project-specific runtime harness. | C4 |
| audit-08 | Verify isolation between customers and organizations | m3-source, m3-model, m4-web | Current hash-based comparisons do not establish semantic isolation of dynamic responses or deployed databases. | C4 |
| audit-09 | Check privileged and service identities | m3-source, m4-infrastructure | Finite IAM declarations do not prove effective remote permissions or account revocation. | C5 |
| audit-10 | Verify protection in storage and transport | m3-source, m4-web, m4-infrastructure | No complete cryptographic, TLS-configuration or storage-encryption assessment adapter. | C4 |
| audit-11 | Verify secret access, rotation and revocation | m3-source, m4-trivy | No provider-specific rotation executor or complete repository-history scanner. | C4 |
| audit-12 | Verify collection, sharing, retention and deletion | m2-evidence, m3-source | No end-to-end data-copy or deletion verification adapter; no legal compliance conclusion. | C4 |
| audit-13 | Trace untrusted data to dangerous effects | m3-source, m3-model | Six finite rule families do not provide interprocedural or framework-wide analysis. | C4 |
| audit-14 | Verify upload, processing and download boundaries | m3-source | No generic file-upload or server-side-fetch execution adapter. | C4 |
| audit-15 | Verify browser trust, request intent and safe errors | m3-source, m4-web | Header-presence flags do not prove effective CSP, CORS, CSRF or browser behavior. | C3 |
| audit-16 | Enforce ordered sensitive workflows | m3-source, m3-model | Serialized model results do not prove real service or database transitions. | C4 |
| audit-17 | Protect amounts, quantities and quotas | m3-source, m3-model | No general payment, inventory or quota test harness. | C4 |
| audit-18 | Prevent duplicate and concurrent state violations | m3-model, m5-load, m5-artifact | Read-load generation and detached SQLite checks are not an end-to-end write/concurrency test. | C4 |
| audit-19 | Inventory exposed API versions and privileged routes | m2-evidence, m3-source, m4-web | No comprehensive runtime crawler or automatic route/version inventory. | C3 |
| audit-20 | Validate external responses and inbound message authenticity | m3-source, m3-model | No provider-specific webhook/signature or response-validation runtime adapter. | C4 |
| audit-21 | Check API consumption limits and replay controls | m3-source, m5-load | Auditor admission limits do not validate target replay defense, resource cost or distributed throttling. | C4 |
| audit-22 | Identify vulnerable, unsupported or untrusted components | m3-source | No automatic current vulnerability-feed adapter or complete shipped-component inventory. | C2 |
| audit-23 | Verify package integrity and publisher/build provenance | m4-infrastructure | M1/M6 protect the assessor's own components; target artifact attestation and build provenance need a separate adapter. | C5 |
| audit-24 | Review build permissions, isolation and approval controls | m3-source, m4-infrastructure, m4-trivy | Lexical workflow leads do not observe hosted settings, effective permissions or runner behavior. | C5 |
| audit-25 | Inspect selected platform security configuration | m4-infrastructure, m4-trivy | Finite local configuration rules do not establish effective remote platform posture. | C5 |
| audit-26 | Check exposed services, defaults and debugging surfaces | m4-infrastructure, m4-web | No network-port discovery or general administrative-route enumeration adapter. | C5 |
| audit-27 | Verify environment and administrative-network separation | m4-infrastructure | No remote segmentation or effective cloud-permission collector. | C5 |
| audit-28 | Verify useful and protected security-event logging | m3-source, m5-incident | The assessor's own evidence ledger does not verify the application's log pipeline. | C6 |
| audit-29 | Test the security-alert ownership and escalation path | m5-incident | Existing challenge acknowledgments do not prove all detection and notification transports. | C6 |
| audit-30 | Exercise incident decision and response procedures | m2-evidence, m5-incident | No automatic containment, notification sending or whole-service incident-response execution. | C6 |
| audit-31 | Verify backup confidentiality and resistance to tampering | m3-source, m4-infrastructure, m5-artifact | SQLite integrity does not prove encryption, object immutability, off-site separation or backup account independence. | C6 |
| audit-32 | Measure representative restoration against recovery goals | m5-artifact | Current small SQLite restores do not prove service RTO, actual RPO or other database engines. | C6 |
| audit-33 | Exercise recovery responsibilities after a security incident | m5-artifact, m5-incident | No automatic rebuild, deployed rollback, credential rotation or service cutover adapter. | C6 |
| audit-34 | Run only scoped, supported assessment methods | m2-evidence, m3-source, m4-web, m4-trivy | General dynamic scans and several candidate adapters are not connected. | C3 |
| audit-35 | Validate findings and retain counterevidence | m2-evidence, m3-source, m3-model | Review correctness and detection quality still need broader held-out application cases. | C4 |
| audit-36 | Map each selected obligation to evidence and an explicit outcome | m2-evidence | Existing M2 templates are broad; standards require requirement-level mapping and evidence beyond this planning catalog. | C1 |
<!-- checklist-matrix:end -->

## Related service sections

The source page also includes secure code review, penetration testing, remediation,
infrastructure changes, delivery, monitoring and incident handling. They are not
additional items hidden inside this 36-control denominator.

- M3 has finite source leads and declared-model correction tests. It does not
  automatically implement all secure-code or remediation services in the page.
- M4 exact reads and role comparisons do not qualify general active penetration
  testing, browser attacks, network service tests, cloud exploitation or attack
  chaining. Linking findings is not executing a chain.
- M5 bounded reads and detached data artifacts do not qualify business-write load,
  service recovery or a live alert pipeline.
- Real containment, host changes, deployment, external notification and recurring
  monitoring require their own capability, target scope and authorization.
- The AI-security guidance module remains available when the target uses models
  or agents. Its absence from this particular 36-item source section does not
  remove its relevance to such a target.

## Evidence of the skill itself

Current execution limits are documented in [M3](M3-SOURCE-REMEDIATION.md),
[M4](M4-RUNTIME-SECURITY.md), [M5](M5-RESILIENCE.md) and
[release readiness](RELEASE-READINESS.md). Their implementation tests are evidence
about these bounded helpers, not evidence that a customer application passed.
The project validator checks inventory and references only. Its result never
establishes current upstream versions, vulnerability-detection quality or a
target security verdict.
