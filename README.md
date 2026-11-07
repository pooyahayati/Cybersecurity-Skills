# Cybersecurity Skills

An independent, modular security skill for developers who need understandable
findings, practical fixes, and evidence that a fix works. The intended scope
extends from source code and customer data to infrastructure, pre-release
testing, production verification, capacity, and recovery.

**Status: development foundation, `0.1.0-dev`.** This repository currently provides
the skill contract, domain guidance, module and source catalogs, an implementation
roadmap, report templates, and an offline project validator. It does **not** yet
provide an automated assessment runner, enforced version resolver, installed
specialist integrations, or demonstrated vulnerability-detection accuracy.

## Start here

- Read [the roadmap](ROADMAP.md) for milestones and acceptance criteria.
- Read [current status](STATUS.md) before continuing implementation.
- Read [the architecture](docs/ARCHITECTURE.md) for boundaries and decisions.
- Read [the skill entrypoint](SKILL.md) for the future assessment workflow and
  current foundation limits.
- Read [development instructions](CONTRIBUTING.md) to validate a change.

The package has no runtime dependency on `vibe-coding-skill` or any other skill.
Vibe is used to develop this repository, not to operate the eventual security
skill. Upstream specialists are candidates until explicitly reviewed and adapted.

## Validate the foundation

Use Python 3.11 or newer. No third-party Python packages are required:

```bash
python scripts/validate_project.py
python -m unittest discover -s tests -v
```

These commands validate this repository, not another application. They do not
contact targets, install software, resolve current upstream versions, or establish
that an application is secure. A successful result is `foundation_valid`, never
an audit or release-readiness verdict.

## Intended user experience

A developer supplies a project path, a deployed URL, or both and describes the
goal. The skill discovers available evidence, asks only for missing consequential
information, selects relevant modules, and reports what was and was not checked.
Findings explain customer impact, location, prerequisites, evidence, a concrete
fix, and how to verify it. Source, staging, and production results remain distinct.

The first implementation milestone is the freshness and execution-control layer.
Until its acceptance criteria pass, use this foundation for planning and project
development only. There is no stable installable release yet.

## Project policy

All maintained skill instructions and documentation are written in English.
Private target information, credentials, raw scanner output, and customer data
must stay outside this repository. Only synthetic evaluation fixtures belong here.
Original project content uses the [MIT license](LICENSE). See
[third-party notices](THIRD_PARTY_NOTICES.md) before adopting upstream material.
