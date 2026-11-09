# Identity, authorization and sessions

Map login, registration, recovery, multi-factor flows, service identities and
privilege changes. Check both identity and permission on the specific resource
and operation; a valid session, nonce or signed token is not ownership proof.

Compare owner and non-owner, allowed and denied roles, and tenant boundaries using
synthetic records. Review object/property/function authorization, invitations,
admin delegation, bulk/export endpoints, background jobs and service credentials.
For denied writes, inspect protected state as well as the response.

Inspect session creation, renewal, fixation resistance, cookie scope/attributes,
token storage, expiry, logout, password reset and role-change behavior. Validate
server-side invalidation against the actual policy. Consider concurrent sessions,
refresh-token reuse and account enumeration without generating uncontrolled traffic.

Use the actual framework and current applicable guidance. Do not prescribe one
timeout, hash cost or cookie setting without checking workload and integration
requirements. Preserve intentional login and recovery flows after a fix.

## Optional checklist execution

Use the [C2-C6 execution guide](../../docs/CHECKLIST-EXECUTION.md) only when its
selected profile and explicit authority match this project. Require independent
business expectations and actual attributed observations; preserve unsupported
requirements and all per-item checklist outcomes. A tool lead or historical
profile result cannot self-approve a finding, correction or deployment.
