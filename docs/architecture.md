# Ruhusa v0.1 Architecture

```text
Agent / Workflow
      |
      | proposed action
      v
AuthorizationRequest
      |
      v
+-----------------------------+
| Ruhusa Authorization Core   |
|                             |
| 1. Task validity            |
| 2. Delegation validation    |
| 3. Scope attenuation        |
| 4. Resource validation      |
| 5. Argument validation      |
| 6. Policy evaluation        |
| 7. Audit                    |
+---------------+-------------+
                |
        +-------+--------+
        |       |        |
      ALLOW    DENY   APPROVAL
        |
        v
     Tool/API
```

## Design rule

The LLM may propose an action, but it never decides whether that action is authorized.

## Current policy model

The v0.1 `StaticPolicyStore` is intentionally small and deterministic. It exists to make experiments easy to inspect. Future adapters can call external PDPs without changing the core request/decision model.
