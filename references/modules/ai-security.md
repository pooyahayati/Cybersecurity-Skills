# AI application and agent security

Activate only when the target uses model-generated output, retrieval, tools,
memory or model-directed actions. Map trusted instructions, untrusted content,
sensitive context, tool permissions and external data destinations.

Review prompt injection, data exfiltration, unsafe output handling, excessive tool
authority, retrieval/memory poisoning, cross-user context and unbounded cost or
resource use. A model's approval statement is not action authorization.

Validate consequential actions in an execution component against the current actor,
exact operation and resource, allowed parameters, scope and expiry. Use real host
isolation where required; text labels do not enforce a sandbox. Avoid one universal
approval prompt for every low-impact step; preserve already-authorized scope.

Test with synthetic adversarial content and bounded tools. Verify both refusal of
prohibited effects and completion of legitimate tasks. Keep model/version/tool
identities and uncertainty in the evidence, and do not upload private target data
to an evaluation service without appropriate authorization.
