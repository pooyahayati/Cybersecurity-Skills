# Dependencies, secrets and supply chain

Inventory direct/transitive packages, lockfiles, build/deploy tools, images and
third-party services. Determine actual shipped and build-time versions. Inspect
untrusted install hooks before execution and avoid ambient developer credentials.

Check current advisories, affected ranges, reachability, maintenance, provenance,
publisher changes and applicable licenses. A clean advisory lookup does not prove
a new package benign. A scanner version check does not prove its database is current.

Review secret handling in source, relevant history, configs, artifacts, logs and
pipelines without printing live values. An exposed secret needs scoped revocation
and impact assessment; removing the string alone does not invalidate a credential.

Use Trivy or another reviewed adapter only for its supported surfaces. Match
findings to the actual component and explain unsupported coverage. Do not upgrade
dependencies across compatibility boundaries automatically to silence a scanner.
Treat the auditor's own tools, skills and rules as supply-chain dependencies too.
