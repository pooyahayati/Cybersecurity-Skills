# CI/CD, release and post-release verification

Trace source revision through build, dependency resolution, artifact creation,
storage and deployment. Record immutable artifact identity and observed deployed
revision; a merged patch is not evidence that production uses it.

Review pipeline permissions, third-party Actions, untrusted pull-request execution,
secret exposure, artifact provenance, environment credentials, migration ordering,
release controls and rollback behavior. Do not run untrusted contributions with
privileged release credentials or auto-publish their artifacts.

Before release, verify relevant application controls, artifact/configuration scans,
core flows and required recovery evidence in the intended pre-release environment.
After release, perform only authorized bounded checks of deployed identity, critical
flows, exposure, logs/alerts and regression behavior. Keep staging and production
outcomes separate.

Report unknowns and required actions by owner. A healthy process is not proof of
correct permissions, durable state, alert delivery or recovery. Creating the skill
does not schedule ongoing monitoring or authorize deployment of a proposed fix.
