"""Auto-registration of upstream tools the registry has never seen.

Off by default. When an operator turns it on, the gateway registers each unknown upstream tool
under an operator credential — never under the agent's own identity, which cannot write to the
registry at all — with the declared risk tier as a *request*. If the tool already exists, the
registry's version wins and nothing is overwritten: a tool server that renames or re-describes a
tool must not be able to lower the tier it is governed at.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

import httpx

from .config import GatewayConfig, ToolDeclaration
from .transport import http_client

LOGGER = logging.getLogger("mizan.mcp.registration")


def tool_document(
    config: GatewayConfig,
    tool_name: str,
    declaration: ToolDeclaration,
    tenant_id: str,
    schema: dict[str, Any] | None,
) -> dict[str, Any]:
    tool_id = config.tool_id(tool_name)
    bound = declaration.bound_pointers or _pointers_from_schema(schema)
    return {
        "schema_version": "1.2",
        "tool_id": tool_id,
        "tenant_id": tenant_id,
        "name": tool_name[:120],
        "owner": "mcp-gateway",
        "risk_tier": declaration.risk_tier,
        "action_type": declaration.action_type,
        "resource_owner": declaration.resource_owner,
        "data_classification": declaration.data_classification,
        "binding_profile": {
            "profile_id": f"bp_{tool_id.removeprefix(config.tenant_prefix)}-v1",
            "profile_version": 1,
            "canonicalization": "RFC8785",
            "bound_pointers": bound,
            "volatile_pointers": declaration.volatile_pointers,
            "unknown_pointer_policy": "reject",
        },
        "execution": {
            "executor_spiffe_ids": [config.executor_spiffe_id or "spiffe://mizan/mcp-gateway"],
            "token_ttl_seconds": 300,
            "lease_ttl_seconds": 900,
            "heartbeat_interval_seconds": 60,
            "max_lease_extensions": 24,
        },
        "created_at": datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z"),
    }


def _pointers_from_schema(schema: dict[str, Any] | None) -> list[str]:
    """Every top-level property is bound unless the operator says otherwise.

    Binding everything is the conservative default: an argument nobody classified may well be the
    one that decides whether the call is safe, and an over-bound profile fails closed on drift
    rather than letting a changed argument through on an old capability.
    """
    properties = (schema or {}).get("properties") or {}
    return sorted(
        f"/{name.replace('~', '~0').replace('/', '~1')}" for name in properties
    ) or ["/"]


class RegistrySync:
    """Registers unknown tools under an operator credential, once, at startup."""

    def __init__(self, config: GatewayConfig, transport: httpx.Client | None = None) -> None:
        self.config = config
        self.client = transport or http_client(config)
        self.client.headers["Authorization"] = f"Bearer {config.operator_token}"
        self.registered: list[str] = []
        self.skipped: list[str] = []

    def close(self) -> None:
        self.client.close()

    def ensure(self, tools: list[dict[str, Any]], tenant_id: str) -> None:
        for tool in tools:
            name = tool["name"]
            tool_id = self.config.tool_id(name)
            existing = self.client.get(f"/v1/tools/{tool_id}")
            if existing.status_code == 200:
                self.skipped.append(tool_id)
                continue
            document = tool_document(
                self.config, name, self.config.declaration(name), tenant_id, tool.get("inputSchema")
            )
            created = self.client.post("/v1/tools", json=document)
            if created.status_code == 201:
                self.registered.append(tool_id)
            else:
                # A tool that could not be registered is not silently ungoverned: it stays
                # unknown, and every call to it is refused when authorization asks for it.
                LOGGER.error(
                    "tool %s was not registered (%s): calls to it will be refused",
                    tool_id,
                    created.status_code,
                )
