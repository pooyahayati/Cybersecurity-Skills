# Architecture and threat model

Map actors, valuable assets, entrypoints, external services, trust boundaries,
deployment environments and sensitive data flows. Corroborate documentation with
source/configuration and runtime evidence when available; mark uncertainty.

Examine anonymous, authenticated non-owner, low-privilege, cross-tenant, service
integration and compromised-dependency perspectives as applicable. Trace complete
paths from actor-controlled input to a sensitive read, mutation or resource cost.
Look for excessive trust in browser state, internal networks, signed-but-unscoped
tokens, background jobs and supposedly trusted stored data.

Select applicable versioned ASVS controls and platform guidance. Top Ten categories
help discovery but are not a coverage checklist. Review architectural interactions
that individual scanners miss; correlate chains without inflating finding counts.

Return the asset/trust map, explicit assumptions, applicable module plan and coverage
gaps. A source-only map does not establish deployed configuration. A URL-only view
does not establish source correctness. Use the shared evidence contract for findings.
