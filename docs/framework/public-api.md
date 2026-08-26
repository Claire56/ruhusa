# Ruhusa Public Python API

**Milestone:** v0.7-A  
**Released baseline:** v0.6.0

The top-level `ruhusa` namespace is now intentional. Anything in
`ruhusa.__all__` is treated as a supported SDK symbol for the v0.7 development
line.

## Core runtime

```python
Ruhusa
ExecutionController
```

## Dependency interfaces

```python
PolicyStore
AuditLog
GrantStore
RevocationStore
InvocationStore
ToolRegistry
ExecutionStore
```

These are structural Python `Protocol` contracts. Custom backends do not need
to subclass Ruhusa implementation classes.

## Reference implementations

```python
StaticPolicyStore
InMemoryAuditLog
InMemoryGrantStore
InMemoryRevocationStore
InMemoryInvocationStore
InMemoryToolRegistry
InMemoryExecutionStore
```

These are bundled reference/default implementations, not the required backend
types for production.

## Canonicalization helper

```python
compute_arguments_digest
```

This helper remains public deliberately.

Trusted orchestration code constructs `InvocationRecord` values and must bind
them to the same canonical argument digest Ruhusa later recomputes. Requiring
applications to independently duplicate the serialization algorithm would
create compatibility and security risk.

## Compatibility rule

New symbols are not added to `ruhusa.__all__` merely because they exist in the
package. The public-API contract test must be updated intentionally.
