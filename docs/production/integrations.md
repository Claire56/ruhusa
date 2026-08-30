# Trusted integration boundary

Ruhusa authorization relies on provenance observed by trusted orchestration
infrastructure rather than supplied by an executing agent.

`TrustedInvocationFactory` provides a framework-neutral helper for constructing
that provenance consistently.

Use the factory only in infrastructure that can truthfully observe the
authenticated invoking principal, executing principal, task, operation, exact
arguments, and resolved tool identity.

The canonical `InvocationRecord` is registered before the authorization request
is returned. Store failures therefore do not produce an unregistered request.

The returned request contains the `invocation_id` but deliberately omits the
self-asserted `invoking_principal_id`, `tool_id`, and `implementation_id`. In
strong provenance mode those values come from the trusted invocation record.

An invocation may never outlive its task.

This helper does not execute side effects or hide uncertain outcomes. Continue
to use `ExecutionController.begin()`, `revalidate_before_execution()`,
`complete()`, and `mark_unknown()` explicitly.
