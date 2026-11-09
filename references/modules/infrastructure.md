# Infrastructure and configuration

M4 implements [selected configuration and local-container observations](../../docs/M4-RUNTIME-SECURITY.md).
Its finite JSON/Dockerfile/workflow leads and reviewed Trivy embedded-rule adapter
do not establish remote host/cloud account posture or actual public exposure.
Use [M4 operations](../../docs/M4-OPERATIONS.md); broader methods below remain guidance.

Map owned hosts, network exposure, cloud identities, containers, databases,
storage/CDN resources and administrative access. Separate observed configuration
from assumptions about the provider or managed service.

Review least privilege, network segmentation, public storage, service bindings,
transport security, database access, metadata-service exposure, container privileges,
mounted secrets, IaC defaults and environment separation. Inspect resource limits
and backup access where relevant. Correlate configuration with actual exposure.

Use read-only configuration inspection first. Testing a discovered address or
changing IAM, firewall, DNS, storage permissions or credentials requires the
corresponding authorized scope. Avoid locking out the operator or replacing a
working server configuration wholesale.

Return exact affected resources, safe correction steps, owner responsibilities,
verification and recovery requirements. Missing administrative access leaves the
relevant controls unverified even when the public site responds normally.

## Optional checklist execution

Use the [C2-C6 execution guide](../../docs/CHECKLIST-EXECUTION.md) only when its
selected profile and explicit authority match this project. Require independent
business expectations and actual attributed observations; preserve unsupported
requirements and all per-item checklist outcomes. A tool lead or historical
profile result cannot self-approve a finding, correction or deployment.
