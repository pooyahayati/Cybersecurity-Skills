# Infrastructure and configuration

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
