from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Literal
from uuid import uuid4

from psycopg.errors import ForeignKeyViolation, UniqueViolation

from .canonical import canonical_hash
from .models import AuthenticatedPrincipal, EvaluationContext
from .policy_engine import compile_policy
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
                if document.get("parent_agent_id"):
                    parent = connection.execute(
                        "SELECT document FROM mizan.agents WHERE tenant_id=%s AND agent_id=%s",
                        (tenant_id, document["parent_agent_id"]),
                    ).fetchone()
                    if (
                        not parent
                        or document["agent_id"] not in parent[0]["delegation"]["allowed_agent_ids"]
                    ):
                        raise ForeignKeyViolation("parent has not authorized this delegation edge")
                    connection.execute(
                        "INSERT INTO mizan.agent_delegations(tenant_id,parent_agent_id,child_agent_id) "
                        "VALUES (%s,%s,%s)",
                        (tenant_id, document["parent_agent_id"], document["agent_id"]),
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
        if document["status"] != "DRAFT":
            raise Problem(422, "policy_create_requires_draft", "New policies must begin in DRAFT")
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

    def update_agent(
        self,
        tenant_id: str,
        agent_id: str,
        document: dict[str, Any],
        actor: AuthenticatedPrincipal,
        second_actor: AuthenticatedPrincipal | None,
    ) -> dict[str, Any]:
        self._require_tenant(tenant_id, document)
        if document["agent_id"] != agent_id:
            raise Problem(409, "agent_identity_immutable", "Agent identifier cannot be changed")
        if actor.identity_kind != "human" or actor.auth_strength not in {"mfa", "hardware"}:
            raise Problem(
                403, "registry_admin_auth_insufficient", "Agent changes require strong human auth"
            )
        with self.pool.connection() as connection, connection.transaction():
            self._scope(connection, tenant_id)
            row = connection.execute(
                "SELECT document FROM mizan.agents WHERE tenant_id=%s AND agent_id=%s FOR UPDATE",
                (tenant_id, agent_id),
            ).fetchone()
            if not row:
                raise Problem(404, "registry_object_not_found", "Agent was not found")
            old = row[0]
            self._validate_agent_transition(old["lifecycle_state"], document["lifecycle_state"])
            protected = document["environment"] == "production" and document["risk_tier"] in {
                "HIGH",
                "CRITICAL",
            }
            if protected and (
                second_actor is None
                or second_actor.principal_id == actor.principal_id
                or second_actor.identity_kind != "human"
                or second_actor.auth_strength not in {"mfa", "hardware"}
            ):
                raise Problem(
                    403,
                    "agent_dual_control_required",
                    "A distinct strongly authenticated second approver is required",
                )
            connection.execute(
                "UPDATE mizan.agents SET version=%s,lifecycle_state=%s,parent_agent_id=%s,"
                "document=%s,updated_at=%s WHERE tenant_id=%s AND agent_id=%s",
                (
                    document["version"],
                    document["lifecycle_state"],
                    document.get("parent_agent_id"),
                    json.dumps(document),
                    document["updated_at"],
                    tenant_id,
                    agent_id,
                ),
            )
            connection.execute(
                "DELETE FROM mizan.agent_tools WHERE tenant_id=%s AND agent_id=%s",
                (tenant_id, agent_id),
            )
            for tool_id in document["tools"]:
                connection.execute(
                    "INSERT INTO mizan.agent_tools(tenant_id,agent_id,tool_id) VALUES (%s,%s,%s)",
                    (tenant_id, agent_id, tool_id),
                )
            connection.execute(
                "INSERT INTO mizan.outbox(tenant_id,aggregate_type,aggregate_id,event_type,payload) "
                "VALUES (%s,'agent',%s,'mizan.agent.updated',%s)",
                (
                    tenant_id,
                    agent_id,
                    json.dumps(
                        {
                            "agent_id": agent_id,
                            "updated_by": actor.principal_id,
                            "second_approver": second_actor.principal_id
                            if protected and second_actor
                            else None,
                        }
                    ),
                ),
            )
        return document

    def publish_binding_profile(
        self, tenant_id: str, tool_id: str, profile: dict[str, Any]
    ) -> dict[str, Any]:
        if not profile.get("bound_pointers") or set(profile["bound_pointers"]) & set(
            profile.get("volatile_pointers", [])
        ):
            raise Problem(
                400, "binding_profile_invalid", "Bound pointers must be non-empty and disjoint"
            )
        with self.pool.connection() as connection, connection.transaction():
            self._scope(connection, tenant_id)
            row = connection.execute(
                "SELECT document,profile_version FROM mizan.tools WHERE tenant_id=%s AND tool_id=%s FOR UPDATE",
                (tenant_id, tool_id),
            ).fetchone()
            if not row:
                raise Problem(404, "registry_object_not_found", "Tool was not found")
            if profile["profile_version"] <= row[1]:
                raise Problem(
                    409, "binding_profile_version_conflict", "Profile version must increase"
                )
            content_hash = canonical_hash(profile)
            try:
                connection.execute(
                    "INSERT INTO mizan.binding_profiles(tenant_id,profile_id,profile_version,canonicalization,"
                    "bound_pointers,volatile_pointers,content_hash) VALUES (%s,%s,%s,%s,%s,%s,%s)",
                    (
                        tenant_id,
                        profile["profile_id"],
                        profile["profile_version"],
                        profile["canonicalization"],
                        json.dumps(profile["bound_pointers"]),
                        json.dumps(profile.get("volatile_pointers", [])),
                        content_hash,
                    ),
                )
            except UniqueViolation as exc:
                raise Problem(
                    409, "binding_profile_version_exists", "Binding profile version exists"
                ) from exc
            document = row[0] | {"binding_profile": profile}
            connection.execute(
                "UPDATE mizan.tools SET profile_id=%s,profile_version=%s,document=%s,updated_at=clock_timestamp() "
                "WHERE tenant_id=%s AND tool_id=%s",
                (
                    profile["profile_id"],
                    profile["profile_version"],
                    json.dumps(document),
                    tenant_id,
                    tool_id,
                ),
            )
            return document

    def simulate_policy(
        self,
        tenant_id: str,
        policy_id: str,
        context: EvaluationContext,
        simulated_by: str,
        version: int | None = None,
    ) -> dict[str, Any]:
        document = self.get(tenant_id, "policies", policy_id, version)
        compilable = document | {"status": "ACTIVE"}
        compiled = compile_policy(json.dumps(compilable, sort_keys=True, separators=(",", ":")))
        matched = compiled.matches(context)
        result = {
            "simulation_id": str(uuid4()),
            "policy_id": policy_id,
            "version": document["version"],
            "matched": matched,
            "decision": document["decision"] if matched else "DENY",
            "explanation": ["conditions matched"] if matched else ["conditions did not match"],
        }
        with self.pool.connection() as connection, connection.transaction():
            self._scope(connection, tenant_id)
            connection.execute(
                "INSERT INTO mizan.policy_simulations(tenant_id,simulation_id,policy_id,policy_version,"
                "context_hash,matched,result,simulated_by) VALUES (%s,%s,%s,%s,%s,%s,%s,%s)",
                (
                    tenant_id,
                    result["simulation_id"],
                    policy_id,
                    document["version"],
                    canonical_hash(context.model_dump(mode="json")),
                    matched,
                    json.dumps(result),
                    simulated_by,
                ),
            )
        return result

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

    @staticmethod
    def _validate_agent_transition(current: str, target: str) -> None:
        allowed = {
            "PROPOSED": {"ASSESSED", "RETIRED"},
            "ASSESSED": {"DESIGNED", "RETIRED"},
            "DESIGNED": {"SECURITY_REVIEW", "RETIRED"},
            "SECURITY_REVIEW": {"APPROVED", "RETIRED"},
            "APPROVED": {"REGISTERED", "RETIRED"},
            "REGISTERED": {"ACTIVE", "RETIRED"},
            "ACTIVE": {"MONITORED", "SUSPENDED", "RETIRED"},
            "MONITORED": {"ACTIVE", "SUSPENDED", "RETIRED"},
            "SUSPENDED": {"REVIEWED", "RETIRED"},
            "REVIEWED": {"ACTIVE", "RETIRED"},
            "RETIRED": set(),
        }
        if target != current and target not in allowed.get(current, set()):
            raise Problem(
                409, "illegal_agent_transition", f"Agent cannot transition {current} → {target}"
            )
