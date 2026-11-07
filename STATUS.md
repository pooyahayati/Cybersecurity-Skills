# Project status

Updated: 2026-11-07

## Current stage

M0 development foundation, version `0.1.0-dev`. Initial implementation and local
review are complete; GitHub integration verification is pending. This is not an
operational security release.

## Present in the foundation

- Independent skill entrypoint and eleven domain guidance modules.
- Architecture, module, freshness, authorization and evidence contracts.
- Candidate upstream source catalog; no external module is enabled or vendored.
- Roadmap, evaluation protocol, reporting templates and contribution instructions.
- Offline repository validation and focused regression tests.

## Not implemented

Automatic freshness resolution, verified component activation, target discovery,
assessment execution, scanner adapters, patch execution, production/load testing,
evidence authentication, installation/update tooling and scheduled monitoring.
Behavioral vulnerability-detection performance has not been established.

## Next bounded task

Implement M1 freshness resolution and its failure fixtures first. Define official
source adapters and the receipt trust boundary before adding automatic downloads
or activation. Preserve the strict no-silent-stale-fallback rule and independence
from all development skills.

## Verification record

- Repository validation: passed; 11 guidance modules and 10 disabled candidate
  sources. The result explicitly makes no operational or freshness-verification claim.
- Skill frontmatter validation: passed with the skill-creator validator.
- Local Python 3.14 regression run: 19 tests, 18 passed, one skipped because the
  Windows host could not create the symlink fixture. Hosted Linux must run it.
- Independent review: no required foundation blocker; a vacuous CI whitespace
  check was identified and corrected to inspect the committed revision.
- Final exported-source secret scan and GitHub CI: pending before integration.
- Operational and detection-quality evaluations: not performed; later milestones.
