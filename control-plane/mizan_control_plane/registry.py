from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Literal

from psycopg.errors import ForeignKeyViolation, UniqueViolation

from .canonical import canonical_hash
from .problems import Problem
from .repository import PostgresAuthorizationRepository

ResourceKind = Literal["agents", "tools", "policies"]


@dataclass(frozen=True, slots=True)
class Page:
    items: list[dict[str, Any]]
    next_cursor: str | None


def encode_cursor(created_at: datetime, identifier: str) -> str:
    raw = json.dumps([created_at.isoformat(), identifier], separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def decode_cursor(value: str) -> tuple[datetime, str]:
    try:
        padded = value + "=" * (-len(value) % 4)
        timestamp, identifier = json.loads(base64.urlsafe_b64decode(padded))
        return datetime.fromisoformat(timestamp), str(identifier)
    except (ValueError, TypeError, json.JSONDecodeError) as exc:
        raise Problem(400, "invalid_cursor", "Pagination cursor is malformed") from exc


class RegistryRepository(PostgresAuthorizationRepository):
    _RESOURCE_MAP = {
        "agents": ("agents", "agent_id"),
        "tools": ("tools", "tool_id"),
        "policies": ("policies", "policy_id"),
    }

    def create_agent(self, tenant_id: str, document: dict[str, Any]) -> dict[str, Any]:
        self._require_tenant(tenant_id, document)
        try:
            with self.pool.connection() as connection, connection.transaction():
                self._scope(connection, tenant_id)
                connection.execute(
                    """INSERT INTO mizan.agents(
                         tenant_id,agent_id,version,lifecycle_state,parent_agent_id,document,created_at,updated_at
                       ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s)""",
                    (
                        tenant_id,
                        document["agent_id"],
                        document["version"],
                        document["lifecycle_state"],
                        document.get("parent_agent_id"),
                        json.dumps(document),
                        document["created_at"],
                        document["updated_at"],
                    ),
                )
                for tool_id in document["tools"]:
                    connection.execute(
                        "INSERT INTO mizan.agent_tools(tenant_id,agent_id,tool_id) VALUES (%s,%s,%s)",
                        (tenant_id, document["agent_id"], tool_id),
                    )
                for policy_id in document["policies"]:
                    version = connection.execute(
                        "SELECT max(version) FROM mizan.policies WHERE tenant_id=%s AND policy_id=%s",
                        (tenant_id, policy_id),
                    ).fetchone()[0]
                    if version is None:
                        raise ForeignKeyViolation("referenced policy is absent")
                    connection.execute(
                        "INSERT INTO mizan.agent_policies(tenant_id,agent_id,policy_id,policy_version) VALUES (%s,%s,%s,%s)",
                        (tenant_id, document["agent_id"], policy_id, version),
                    )
            return document
        except UniqueViolation as exc:
            raise Problem(409, "agent_exists", "agent_id already exists") from exc
        except ForeignKeyViolation as exc:
            raise Problem(
                422, "registry_reference_missing", "Agent references an unknown object"
            ) from exc

    def create_tool(self, tenant_id: str, document: dict[str, Any]) -> dict[str, Any]:
        self._require_tenant(tenant_id, document)
        profile = document["binding_profile"]
        if set(profile["bound_pointers"]) & set(profile["volatile_pointers"]):
            raise Problem(400, "binding_pointer_overlap", "Bound and volatile pointers overlap")
        profile_hash = canonical_hash(profile)
        try:
            with self.pool.connection() as connection, connection.transaction():
                self._scope(connection, tenant_id)
                connection.execute(
                    """INSERT INTO mizan.binding_profiles(
                         tenant_id,profile_id,profile_version,canonicalization,bound_pointers,
                         volatile_pointers,content_hash
                       ) VALUES (%s,%s,%s,%s,%s,%s,%s)""",
                    (
                        tenant_id,
                        profile["profile_id"],
                        profile["profile_version"],
                        profile["canonicalization"],
                        json.dumps(profile["bound_pointers"]),
                        json.dumps(profile["volatile_pointers"]),
                        profile_hash,
                    ),
                )
                connection.execute(
                    """INSERT INTO mizan.tools(
                         tenant_id,tool_id,profile_id,profile_version,document,created_at,updated_at
                       ) VALUES (%s,%s,%s,%s,%s,clock_timestamp(),clock_timestamp())""",
                    (
                        tenant_id,
                        document["tool_id"],
                        profile["profile_id"],
                        profile["profile_version"],
                        json.dumps(document),
                    ),
                )
                for agent_id in document.get("permitted_agents", []):
                    connection.execute(
                        "INSERT INTO mizan.agent_tools(tenant_id,agent_id,tool_id) VALUES (%s,%s,%s)",
                        (tenant_id, agent_id, document["tool_id"]),
                    )
            return document
        except UniqueViolation as exc:
            raise Problem(
                409, "tool_exists", "tool or binding-profile version already exists"
            ) from exc

    def create_policy(self, tenant_id: str, document: dict[str, Any]) -> dict[str, Any]:
        self._require_tenant(tenant_id, document)
        self._validate_policy(document)
        expected_hash = canonical_hash(
            {key: value for key, value in document.items() if key != "content_hash"}
        )
        if document["content_hash"] != expected_hash:
            raise Problem(
                400, "content_hash_mismatch", "Policy content_hash is not canonical source hash"
            )
        try:
            with self.pool.connection() as connection, connection.transaction():
                self._scope(connection, tenant_id)
                connection.execute(
                    """INSERT INTO mizan.policies(
                         tenant_id,policy_id,version,status,effective_from,decision,content_hash,document,created_at
                       ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                    (
                        tenant_id,
                        document["policy_id"],
                        document["version"],
                        document["status"],
                        document.get("effective_from"),
                        document["decision"],
                        document["content_hash"],
                        json.dumps(document),
                        document["created_at"],
                    ),
                )
            return document
        except UniqueViolation as exc:
            raise Problem(409, "policy_version_exists", "Policy version already exists") from exc

    def get(
        self, tenant_id: str, kind: ResourceKind, identifier: str, version: int | None = None
    ) -> dict:
        table, id_column = self._RESOURCE_MAP[kind]
        version_clause = " AND version=%s" if kind == "policies" and version is not None else ""
        params: tuple[Any, ...] = (
            (tenant_id, identifier, version) if version_clause else (tenant_id, identifier)
        )
        order = " ORDER BY version DESC" if kind == "policies" else ""
        with self.pool.connection() as connection, connection.transaction():
            self._scope(connection, tenant_id)
            row = connection.execute(
                f"SELECT document FROM mizan.{table} WHERE tenant_id=%s AND {id_column}=%s{version_clause}{order} LIMIT 1",
                params,
            ).fetchone()
        if not row:
            raise Problem(404, "registry_object_not_found", "Registry object was not found")
        return row[0]

    def list(self, tenant_id: str, kind: ResourceKind, limit: int, cursor: str | None) -> Page:
        table, id_column = self._RESOURCE_MAP[kind]
        created_column = "created_at"
        predicate, params = "", [tenant_id]
        if cursor:
            created_at, identifier = decode_cursor(cursor)
            predicate = f" AND ({created_column},{id_column}) > (%s,%s)"
            params.extend([created_at, identifier])
        params.append(limit + 1)
        source = f"mizan.{table}"
        if kind == "policies":
            source = (
                "(SELECT DISTINCT ON (tenant_id,policy_id) * FROM mizan.policies "
                "ORDER BY tenant_id,policy_id,version DESC) latest_policies"
            )
        with self.pool.connection() as connection, connection.transaction():
            self._scope(connection, tenant_id)
            rows = connection.execute(
                f"SELECT document,{created_column},{id_column} FROM {source} "
                f"WHERE tenant_id=%s{predicate} ORDER BY {created_column},{id_column} LIMIT %s",
                params,
            ).fetchall()
        next_cursor = (
            encode_cursor(rows[limit - 1][1], rows[limit - 1][2]) if len(rows) > limit else None
        )
        return Page(items=[row[0] for row in rows[:limit]], next_cursor=next_cursor)

    @staticmethod
    def _require_tenant(tenant_id: str, document: dict[str, Any]) -> None:
        if document.get("tenant_id") != tenant_id:
            raise Problem(403, "tenant_mismatch", "Registry document tenant differs from token")

    @staticmethod
    def _validate_policy(document: dict[str, Any]) -> None:
        if document["status"] in {"APPROVED", "ACTIVE", "SUPERSEDED"} and (
            not document.get("approver") or document["approver"] == document["author"]
        ):
            raise Problem(422, "policy_dual_control_required", "Policy author cannot approve it")
        requirements = document.get("approval_requirements")
        if not requirements:
            return
        escalation = requirements.get("escalation")
        if escalation is not None and not {"pool_mode", "carry_forward_votes"} <= escalation.keys():
            raise Problem(
                422, "escalation_semantics_missing", "Escalation semantics must be explicit"
            )
        mode = requirements["rejection_mode"]
        count = requirements.get("rejection_quorum_count")
        if (mode == "rejection_quorum") != (count is not None):
            raise Problem(
                422, "rejection_quorum_invalid", "Rejection count must match rejection mode"
            )
