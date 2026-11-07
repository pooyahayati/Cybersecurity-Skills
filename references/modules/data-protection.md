# Sensitive data and customer privacy

Inventory data classes, purpose, owners, readers, writers, retention and deletion
paths. Trace collection through transport, processing, storage, sharing and disposal.
Include credentials and session material as well as personal/customer records.

Inspect copies in logs, error reports, traces, analytics, browser storage, caches,
search indexes, queues, exports, downloads, backups, support tools and AI prompts.
Verify field-level minimization and output authorization; database encryption does
not prevent an authorized process from returning the wrong customer's records.

Review encryption where appropriate, password hashing, key custody, least privilege,
secret creation/rotation/revocation and exposure response. Check backup confidentiality
and deletion/retention behavior, including delayed copies and third-party services.
Do not claim legal compliance merely from a technical checklist.

Use synthetic identifiers and minimum necessary evidence. Redact the auditor's
own reports, logs and tool inputs. Verify the proposed fix covers each affected
copy without breaking legitimate access or destroying required recoverability.
