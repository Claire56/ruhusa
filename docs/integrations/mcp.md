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

## MCP SDK v2 server integration (v0.9-C2 prototype)

`ruhusa.integrations.mcp_sdk` exposes `ProtectedMCPTool`,
`RuhusaMCPToolRouter`, and `create_mcp_sdk_server`. This uses the MCP Python
SDK v2 **low-level `Server(on_list_tools=..., on_call_tool=...)` interface**.
Its handler routes every `tools/call` through the C1 guard before executing a
protected handler. The MCP SDK is optional and is imported only when constructing
the server. Install SDK v2 separately (for example `uv pip install 'mcp>=2,<3'`
in your environment) and pin an exact compatible version in deployments.

Minimal handler construction after configuring the `RuhusaMCPGuard` and trusted
`Ruhusa` stores shown earlier:

```python
from ruhusa.integrations.mcp_sdk import (
    ProtectedMCPTool,
    RuhusaMCPToolRouter,
    create_mcp_sdk_server,
)


# This resolver MUST inspect authenticated server-side session state (e.g. a
# verified OIDC token or trusted workload identity). Never read principal,
# task, grants, or tool implementation from model-supplied tool arguments.
async def resolve_authenticated_context(server_request_context):
    raise NotImplementedError("Integrate your host's trusted authentication")


async def simulated_credit(arguments):
    return {"simulated_credit": arguments["amount"]}


router = RuhusaMCPToolRouter(
    guard,
    tools=(
        ProtectedMCPTool(
            binding=binding,  # fixed, server-owned MCPToolBinding
            description="Simulate customer credit (no real ledger change)",
            input_schema={
                "type": "object",
                "properties": {"amount": {"type": "integer", "minimum": 0}},
                "required": ["amount"],
                "additionalProperties": False,
            },
            handler=simulated_credit,
        ),
    ),
    trusted_context=resolve_authenticated_context,
)
server = create_mcp_sdk_server(router)
# Host must configure authenticated transport, lifecycle, and deployment.
# app = server.streamable_http_app()  # SDK v2; secure the transport first
```

**Security limitations:** This is an SDK handler integration, not a complete
HTTP identity provider or production-safe side-effect engine. Advertised
`input_schema` does not guarantee validation in the low-level SDK, so handlers
must validate argument shapes and never assume the client obeyed the schema.
The C1 guard enforces the modeled credit limit, but future integrations must
validate all action-specific data before reaching side-effect handlers.
The adapter intentionally returns a generic authorization error; it does not
leak a denial's internal policy details. Other execution failures propagate.

Before production deployment, add an authenticated transport resolver, real
MCP client/server integration tests against the pinned SDK version, durable
execution claims/fencing, replay tests, and PostgreSQL concurrency coverage.
The SDK's middleware API is provisional; this implementation deliberately uses
its low-level tool-call handler instead.
