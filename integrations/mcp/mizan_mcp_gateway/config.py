"""What an operator has to say to put a tool server behind Mizan.

One TOML file, or environment variables. Nothing here changes a decision — it says which upstream
server to wrap, which control plane to ask, and what to declare about tools the registry has never
seen. The declared risk tier is a *floor request*: the registry's own floor always wins.
"""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

RISK_TIERS = ("LOW", "MEDIUM", "HIGH", "CRITICAL")
ACTION_TYPES = (
    "read",
    "write",
    "financial_read",
    "financial_write",
    "communicate",
    "export",
    "delete",
    "delegate",
)


class ConfigurationError(ValueError):
    """Configuration that would run, but not with the guarantees the gateway claims."""


@dataclass(frozen=True, slots=True)
class ToolDeclaration:
    """What the operator asserts about one upstream tool before the registry has an opinion."""

    risk_tier: str = "HIGH"
    action_type: str = "write"
    data_classification: str = "confidential"
    resource_owner: str = "external-tool-server"
    resource_type: str = "external"
    bound_pointers: list[str] = field(default_factory=list)
    volatile_pointers: list[str] = field(default_factory=list)

    def validated(self, name: str) -> ToolDeclaration:
        if self.risk_tier not in RISK_TIERS:
            raise ConfigurationError(f"tool {name}: risk_tier must be one of {RISK_TIERS}")
        if self.action_type not in ACTION_TYPES:
            raise ConfigurationError(f"tool {name}: action_type must be one of {ACTION_TYPES}")
        if set(self.bound_pointers) & set(self.volatile_pointers):
            raise ConfigurationError(f"tool {name}: bound and volatile pointers overlap")
        return self


@dataclass(frozen=True, slots=True)
class GatewayConfig:
    upstream_command: str
    upstream_args: list[str] = field(default_factory=list)
    upstream_env: dict[str, str] = field(default_factory=dict)
    mizan_url: str = ""
    agent_token: str = ""
    agent_id: str = ""
    agent_version: str = "1.0.0"
    operator_token: str = ""
    tenant_prefix: str = "tool_"
    environment: str = "production"
    executor_spiffe_id: str = ""
    ca_file: str = ""
    client_certificate_file: str = ""
    client_key_file: str = ""
    principal_id: str = "prn_mcp-client"
    principal_type: str = "application"
    principal_auth_strength: str = "federated"
    approval_timeout_seconds: float = 900.0
    approval_poll_seconds: float = 3.0
    execution_binding_retry_seconds: float = 15.0
    register_unknown_tools: bool = False
    default_declaration: ToolDeclaration = field(default_factory=ToolDeclaration)
    tools: dict[str, ToolDeclaration] = field(default_factory=dict)
    server_name: str = "mizan-governed"

    def declaration(self, tool_name: str) -> ToolDeclaration:
        return self.tools.get(tool_name, self.default_declaration)

    def tool_id(self, tool_name: str) -> str:
        """A registry id an operator can read back to the upstream tool it governs."""
        slug = "".join(character if character.isalnum() else "-" for character in tool_name.lower())
        slug = "-".join(part for part in slug.split("-") if part)
        return f"{self.tenant_prefix}{slug}"

    def validated(self) -> GatewayConfig:
        if not self.upstream_command:
            raise ConfigurationError("an upstream MCP server command is required")
        if not self.mizan_url or not self.agent_token or not self.agent_id:
            raise ConfigurationError(
                "mizan_url, agent_token and agent_id are required: the gateway cannot govern "
                "calls it cannot submit for authorization"
            )
        if bool(self.client_certificate_file) != bool(self.client_key_file):
            raise ConfigurationError(
                "a client certificate and its private key must be configured together"
            )
        if (
            self.executor_spiffe_id
            and self.mizan_url.lower().startswith("https")
            and not self.client_certificate_file
        ):
            raise ConfigurationError(
                "an executor identity is redeemed over mutual TLS: configure "
                "client_certificate_file and client_key_file, or clear executor_spiffe_id and "
                "run without execution binding"
            )
        if self.register_unknown_tools and not self.operator_token:
            raise ConfigurationError(
                "registering unknown tools needs an operator credential; registry writes are not "
                "open to the gateway's agent identity"
            )
        self.default_declaration.validated("<default>")
        for name, declaration in self.tools.items():
            declaration.validated(name)
        return self


def _declaration(document: dict[str, Any]) -> ToolDeclaration:
    known = {field_name for field_name in ToolDeclaration.__slots__}
    unknown = set(document) - known
    if unknown:
        raise ConfigurationError(f"unknown tool declaration keys: {sorted(unknown)}")
    return ToolDeclaration(**document)


def load(path: Path | None = None, environ: dict[str, str] | None = None) -> GatewayConfig:
    environ = dict(os.environ if environ is None else environ)
    document: dict[str, Any] = {}
    if path is not None:
        document = tomllib.loads(path.read_text(encoding="utf-8"))
    upstream = document.get("upstream", {})
    mizan = document.get("mizan", {})
    tools = {
        name: _declaration(value) for name, value in (document.get("tools") or {}).items()
    }
    defaults = _declaration(document.get("defaults", {}))
    config = GatewayConfig(
        upstream_command=upstream.get("command", environ.get("MIZAN_MCP_UPSTREAM_COMMAND", "")),
        upstream_args=list(upstream.get("args", [])),
        upstream_env=dict(upstream.get("env", {})),
        mizan_url=mizan.get("url", environ.get("MIZAN_API_URL", "")),
        agent_token=mizan.get("agent_token", environ.get("MIZAN_AGENT_TOKEN", "")),
        agent_id=mizan.get("agent_id", environ.get("MIZAN_AGENT_ID", "")),
        agent_version=mizan.get("agent_version", "1.0.0"),
        operator_token=mizan.get("operator_token", environ.get("MIZAN_OPERATOR_TOKEN", "")),
        tenant_prefix=mizan.get("tool_id_prefix", "tool_"),
        environment=mizan.get("environment", environ.get("MIZAN_ENV", "production")),
        executor_spiffe_id=mizan.get(
            "executor_spiffe_id", environ.get("MIZAN_EXECUTOR_SPIFFE_ID", "")
        ),
        ca_file=mizan.get("ca_file", environ.get("MIZAN_CA_FILE", "")),
        client_certificate_file=mizan.get(
            "client_certificate_file", environ.get("MIZAN_CLIENT_CERTIFICATE_FILE", "")
        ),
        client_key_file=mizan.get("client_key_file", environ.get("MIZAN_CLIENT_KEY_FILE", "")),
        principal_id=mizan.get("principal_id", "prn_mcp-client"),
        principal_type=mizan.get("principal_type", "application"),
        principal_auth_strength=mizan.get("principal_auth_strength", "federated"),
        approval_timeout_seconds=float(mizan.get("approval_timeout_seconds", 900.0)),
        approval_poll_seconds=float(mizan.get("approval_poll_seconds", 3.0)),
        execution_binding_retry_seconds=float(
            mizan.get("execution_binding_retry_seconds", 15.0)
        ),
        register_unknown_tools=bool(mizan.get("register_unknown_tools", False)),
        default_declaration=defaults,
        tools=tools,
        server_name=document.get("server", {}).get("name", "mizan-governed"),
    )
    return config.validated()
