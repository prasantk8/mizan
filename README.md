# Mizan

Mizan is a governance control plane for autonomous agents operating in regulated banking environments.

The implementation contract is [SPEC_v1.md](SPEC_v1.md). Architectural decisions live in [docs/adr](docs/adr), lane ownership is defined by [AGENT_ALLOCATION.md](AGENT_ALLOCATION.md), and all work is coordinated through [WORK_LOG.md](WORK_LOG.md).

Production execution endpoints require the [in-process mTLS deployment contract](docs/deployment/mtls.md).

## Repository boundaries

| Path | Responsibility | Lane |
|---|---|---|
| `control-plane/` | Registries, authorization, policy, approval, execution, and evidence services | Mixed; see each boundary README |
| `security/` | Redaction, identity, prompt-security, threat, and isolation primitives | CLAUDE |
| `integrations/` | Transport and external-system adapters | CURSOR, except security-sensitive internals |
| `sdk/` | Generated and ergonomic clients | CURSOR |
| `ui/` | Operator and approver experience | CURSOR |
| `examples/` | Demonstration agents and workflows | CURSOR |
| `tests/` | Contract, invariant, integration, and performance suites | TEST |

## Development contract

Before changing files:

1. Read `WORK_LOG.md` and claim a `READY` task.
2. Confirm the path belongs to your lane in `AGENT_ALLOCATION.md`.
3. Treat `SPEC_v1.md` as authoritative; contract changes require an ADR delta.
4. Run `make check` before handing work off.
5. Update and release the claim in `WORK_LOG.md` as the final act.

No service runtime has been selected by this scaffold. Runtime and dependency choices belong to the owning implementation task and must remain compatible with the frozen contracts.
