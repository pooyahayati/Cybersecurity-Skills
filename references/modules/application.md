# Application code and input boundaries

Discover the actual language, framework, entrypoints and reachable operations.
Trace untrusted input through validation, transformations and output/execution
sinks. Inspect framework protections and configuration before reporting a pattern.

Consider injection, unsafe output, path traversal, file upload/execution, server-side
fetches, deserialization, parser ambiguity, resource exhaustion and memory/lifetime
errors where the language makes them relevant. Include stored and third-party data;
the storage location does not make input trusted.

Review API schemas, output fields, request limits, error behavior and client/server
trust. Separate authentication from authorization and request-intent protection.
Do not exclude generated, dependency or authenticated code categorically; assess
reachability and ownership of the actual defect.

For PHP/WordPress, use actual platform versions and public APIs; capabilities and
nonces serve different purposes, as do input sanitization and context-specific
output escaping. Activate a platform adapter only on observed platform evidence.

Propose the smallest root-cause fix. Check malicious and legitimate boundary inputs,
related variants and protected state. Running target builds/tests is separate from
reading source and requires the corresponding execution scope.
