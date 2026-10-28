# MCP enforcement boundary (v0.9-C, experimental)

**Unreleased development, not part of stable Ruhusa v0.8.0.**

The transport-neutral `RuhusaMCPGuard` is a small `tools/call` enforcement
building block. It is **not** an MCP SDK server, MCP protocol implementation,
or execution controller. Integrators must invoke it from a trusted MCP server
entry point before the protected tool handler.

## Trust boundary

The MCP client/model can choose tool arguments. The server, **not the model**,
must supply an authenticated `TrustedMCPContext` (invoker, executing principal,
task and delegation chain) and a fixed, server-owned `MCPToolBinding` mapping
MCP tool name to action, resource and registered implementation identity.
Never populate these from client-supplied `_meta`, prompt content or argument
fields. The adapter creates a canonical immutable invocation record using
`TrustedInvocationFactory`, then calls `Ruhusa.authorize` before invoking the
handler. Only `ALLOW` executes. `DENY`, `REQUIRE_APPROVAL`, registration failures,
and audit/backend failures block execution.

## Example (transport-neutral)

```python
from datetime import UTC, datetime, timedelta
from ruhusa import Principal, TaskContext
from ruhusa.integrations.mcp import MCPToolBinding, RuhusaMCPGuard, TrustedMCPContext
from ruhusa.integrations.trusted import TrustedInvocationFactory

# `ruhusa` must be constructed with a trusted invocation store and tool registry.
# Registry registration and transport authentication happen in trusted setup.
guard = RuhusaMCPGuard(
    ruhusa,
    invocation_factory=TrustedInvocationFactory(invocation_store),
)

binding = MCPToolBinding(
    name="issue_credit",
    action="issue_credit",
    tool_id="credit-tool",
    implementation_id="credit-tool@v1",
    resource="customer:123",  # from trusted server-side lookup
)

trusted = TrustedMCPContext(
    invoking_principal_id="billing-agent",  # established by host authenticator
    executing_principal=Principal("billing-agent"),
    task=TaskContext("task-1", "billing-agent", "credit", datetime.now(UTC) + timedelta(hours=1)),
)


async def issue_credit(args):
    return {"simulated_credit": args["amount"]}


result = await guard.call(
    binding=binding,
    trusted=trusted,
    arguments={"amount": 20},  # untrusted MCP tool arguments
    handler=issue_credit,
)
```

## Known limitations / next gates

- The guard does not implement MCP SDK registration or session handling. The
  caller must ensure that the registered `binding` corresponds to the actual
  incoming tool name; never let a model pick the binding object.
- The guard assumes the host has established trusted identities and task state.
- Authorization before a handler is **not** an atomic transaction spanning an
  external side effect. Integrate Ruhusa's execution fencing/idempotency
  primitives for real side effects, including concurrent/retry behavior.
- No distributed/PostgreSQL MCP execution tests have been run for this adapter.
- `REQUIRE_APPROVAL` is blocked here, not converted to a live approval workflow.
- Do not expose raw internal error details to an MCP client.
