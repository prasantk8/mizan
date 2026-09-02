# Mizan MCP Governance Gateway

Put any MCP tool server behind a governance control plane by changing one line of client
configuration. The client points at `mizan-mcp-gateway` instead of the tool server; the gateway
holds the tool server open and forwards to it **only** once Mizan has recorded a decision that
permits the call.

```
MCP client ──stdio──▶ mizan-mcp-gateway ──stdio──▶ your tool server
                            │
                            └──mTLS──▶ Mizan control plane
```

## What it changes about a tool call

`tools/list` passes through unchanged. A governed tool is the same tool, and rewriting the
descriptions would change what the model is being asked to reason about.

`tools/call` takes exactly one of five paths:

| Control plane says | The tool server | The client gets |
|---|---|---|
| `ALLOW` | runs, under an execution lease | the result, plus `mizan.decision_id` and `mizan.lease_id` |
| `REQUIRE_APPROVAL` | does not run until a human votes | the result once approved; `approval_pending` if the caller's timeout expires first |
| `DENY` | never hears about the call | an error result naming `denied` and the recorded reasons |
| refuses the capability | never hears about the call | an error result naming `execution_binding_unavailable` |
| cannot be reached | never hears about the call | an error result naming `authorization_unavailable` |

There is no local cache and no fast path: "the control plane was unreachable" is not a permission.
Every refusal is a tool *result*, not an exception, so the model can explain to the person what
happened instead of the agent loop crashing.

## Memtara proof metadata

An MCP client can attach a Memtara proof to `tools/call` through request metadata:

```json
{
  "x-memtara-proof": "<proof token>",
  "x-memtara-chain-head": "<chain head>"
}
```

The gateway forwards those values as same-named headers on `/v1/authorize`. It does not decode,
validate, log, add them to tool arguments, or pass them to the upstream tool server. Calls without
either metadata key send neither header.

## Configure

```toml
[upstream]
command = "npx"
args = ["-y", "@modelcontextprotocol/server-filesystem", "/data"]

[mizan]
url = "https://mizan.internal"
agent_id = "agt_wealth-advisor"
agent_token = "..."               # or MIZAN_AGENT_TOKEN
ca_file = "/etc/mizan/ca.pem"
client_certificate_file = "/etc/mizan/gateway.pem"
client_key_file = "/etc/mizan/gateway.key"
executor_spiffe_id = "spiffe://mizan/executor/mcp-gateway"

[tools.write_file]
risk_tier = "HIGH"
action_type = "write"
data_classification = "confidential"
resource_owner = "document-store"
```

See [`example.toml`](example.toml) for every key with its default.

Two properties of that file are deliberate:

* **The declared risk tier is a request, not a setting.** If the registry already governs the
  tool, the registry's tier wins and nothing in this file can lower it. A tool server that renames
  or re-describes a tool cannot talk its way down a tier.
* **The gateway cannot grant itself permission to call anything.** `register_unknown_tools` needs
  a separate *operator* credential, because registry writes are closed to agent identities
  (ADR-001 Amendment E) — and registering a tool still does not permit this agent to call it.
  That grant is a deliberate, separate act by a human.

## Run

```bash
uv sync --extra mcp
mizan-mcp-gateway --config gateway.toml
```

In an MCP client, replace the tool server's entry with this command. Nothing else changes.

## Executor identity

Set `executor_spiffe_id` and the gateway becomes the ADR-008 executor for the calls it forwards:
it redeems the execution token, holds the lease while the tool runs, and closes the lease with the
result hash. The control plane reads the authorized executor off the verified peer certificate,
never off the request body, so an executor identity without `client_certificate_file` is refused
at startup rather than at the first high-risk call.

Leave `executor_spiffe_id` unset and the gateway still governs — the decision is recorded, the
refusal or allow is real — but the execution is not bound, and the result says so.
