from __future__ import annotations

import copy
import json
from collections.abc import Iterable
from threading import Lock

import psycopg
from psycopg_pool import ConnectionPool

from .canonical import canonical_hash
from .models import (
    AuthorizationResponse,
    EvaluationContext,
    PersistedDecision,
    PolicyMatch,
    RegistryAgent,
    RegistryTool,
)
from .policy_engine import CedarPolicyEvaluator
from .ports import DuplicateRequestIdError, EvidenceWriteError


class PostgresAuthorizationRepository:
    def __init__(self, database_url: str) -> None:
        self.pool = ConnectionPool(database_url, min_size=1, max_size=10, open=True)
        self.policy_evaluator = CedarPolicyEvaluator()

    @staticmethod
    def _scope(connection: psycopg.Connection, tenant_id: str) -> None:
        connection.execute("SELECT set_config('app.tenant_id', %s, true)", (tenant_id,))

    def get_agent(self, tenant_id: str, agent_id: str) -> RegistryAgent | None:
        with self.pool.connection() as connection, connection.transaction():
            self._scope(connection, tenant_id)
            row = connection.execute(
                """SELECT a.tenant_id, a.agent_id, a.version, a.lifecycle_state,
                          coalesce(array_agg(at.tool_id::text) FILTER (WHERE at.tool_id IS NOT NULL), '{}')
                          ,a.parent_agent_id,a.document
                     FROM mizan.agents a LEFT JOIN mizan.agent_tools at
                       ON at.tenant_id=a.tenant_id AND at.agent_id=a.agent_id
                    WHERE a.tenant_id=%s AND a.agent_id=%s
                    GROUP BY a.tenant_id,a.agent_id,a.version,a.lifecycle_state,a.parent_agent_id,a.document""",
                (tenant_id, agent_id),
            ).fetchone()
            if not row:
                return None
            delegation = row[6].get("delegation", {})
            return RegistryAgent(
                tenant_id=row[0],
                agent_id=row[1],
                version=row[2],
                lifecycle_state=row[3],
                permitted_tools=set(row[4]),
                parent_agent_id=row[5],
                allowed_agent_ids=set(delegation.get("allowed_agent_ids", [])),
                max_delegation_depth=delegation.get("max_delegation_depth", 0),
            )

    def get_tool(self, tenant_id: str, tool_id: str) -> RegistryTool | None:
        with self.pool.connection() as connection, connection.transaction():
            self._scope(connection, tenant_id)
            row = connection.execute(
                """SELECT t.tenant_id,t.tool_id,t.profile_id,t.profile_version,
                          bp.bound_pointers,bp.volatile_pointers,t.document
                     FROM mizan.tools t JOIN mizan.binding_profiles bp
                       ON bp.tenant_id=t.tenant_id AND bp.profile_id=t.profile_id
                      AND bp.profile_version=t.profile_version
                    WHERE t.tenant_id=%s AND t.tool_id=%s AND t.status='ACTIVE'""",
                (tenant_id, tool_id),
            ).fetchone()
            if not row:
                return None
            doc = row[6]
            return RegistryTool(
                tenant_id=row[0],
                tool_id=row[1],
                profile_id=row[2],
                profile_version=row[3],
                bound_pointers=row[4],
                volatile_pointers=row[5],
                risk_tier=doc["risk_tier"],
                resource_owner=doc["resource_owner"],
                data_classification=doc["data_classification"],
                executor_spiffe_ids=doc["execution"]["executor_spiffe_ids"],
            )

    def matching_policies(
        self, tenant_id: str, context: EvaluationContext, risk_level: str | None = None
    ) -> list[PolicyMatch]:
        with self.pool.connection() as connection, connection.transaction():
            self._scope(connection, tenant_id)
            documents = [
                row[0]
                for row in connection.execute(
                    "SELECT document FROM mizan.policies WHERE tenant_id=%s AND status='ACTIVE' "
                    "AND (effective_from IS NULL OR effective_from <= clock_timestamp())",
                    (tenant_id,),
                ).fetchall()
            ]
        return self.policy_evaluator.evaluate(documents, context, risk_level)

    def find_decision_by_request(self, tenant_id: str, request_id: str) -> PersistedDecision | None:
        with self.pool.connection() as connection, connection.transaction():
            self._scope(connection, tenant_id)
            row = connection.execute(
                "SELECT decision_id,context_hash,document,created_at FROM mizan.adr_records "
                "WHERE tenant_id=%s AND request_id=%s",
                (tenant_id, request_id),
            ).fetchone()
            if not row:
                return None
            doc = row[2]
            response = AuthorizationResponse(
                decision_id=row[0],
                decision=doc["decision"],
                risk=doc["risk"],
                policies=doc["policies"],
                reasons=doc["reasons"],
                constraints=doc.get("constraints"),
                degraded=doc["degraded"],
            )
            return PersistedDecision(
                decision_id=row[0],
                request_id=request_id,
                response=response,
                context_hash=row[1],
                created_at=row[3],
            )

    def persist_decision(
        self, decision: PersistedDecision, adr_document: dict, normalized_context: dict
    ) -> None:
        doc = copy.deepcopy(adr_document)
        with self.pool.connection() as connection, connection.transaction():
            self._scope(connection, doc["tenant_id"])
            connection.execute(
                "INSERT INTO mizan.evidence_chain_heads(tenant_id,stream_id) VALUES (%s,%s) "
                "ON CONFLICT DO NOTHING",
                (doc["tenant_id"], doc["stream_id"]),
            )
            head = connection.execute(
                "SELECT next_sequence,last_hash FROM mizan.evidence_chain_heads "
                "WHERE tenant_id=%s AND stream_id=%s FOR UPDATE",
                (doc["tenant_id"], doc["stream_id"]),
            ).fetchone()
            doc["sequence_number"], doc["prev_hash"] = head
            doc["record_hash"] = canonical_hash(
                {key: value for key, value in doc.items() if key != "record_hash"}
            )
            allocated = connection.execute(
                "SELECT mizan.reserve_evidence_sequence(%s,%s,%s,%s)",
                (doc["tenant_id"], doc["stream_id"], doc["prev_hash"], doc["record_hash"]),
            ).fetchone()[0]
            if allocated != doc["sequence_number"]:
                raise RuntimeError("evidence sequence allocation mismatch")
            connection.execute(
                """INSERT INTO mizan.adr_records(
                     tenant_id,decision_id,request_id,trace_id,context_hash,agent_id,tool_id,stream_id,
                     sequence_number,prev_hash,record_hash,decision,immutable_receipt_ref,document,created_at
                   ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                (
                    doc["tenant_id"],
                    doc["decision_id"],
                    decision.request_id,
                    doc["trace_id"],
                    doc["context_hash"],
                    doc["agent"]["id"],
                    doc["tool"]["id"],
                    doc["stream_id"],
                    doc["sequence_number"],
                    doc["prev_hash"],
                    doc["record_hash"],
                    doc["decision"],
                    doc["immutable_receipt_ref"],
                    json.dumps(doc),
                    decision.created_at,
                ),
            )
            connection.execute(
                "INSERT INTO mizan.outbox(tenant_id,aggregate_type,aggregate_id,event_type,payload) "
                "VALUES (%s,'decision',%s,'mizan.decision.created',%s)",
                (doc["tenant_id"], doc["decision_id"], json.dumps(doc)),
            )
            connection.execute(
                "INSERT INTO mizan.authorization_contexts(tenant_id,decision_id,context_hash,document) "
                "VALUES (%s,%s,%s,%s)",
                (
                    doc["tenant_id"],
                    doc["decision_id"],
                    doc["context_hash"],
                    json.dumps(normalized_context),
                ),
            )


class InMemoryAuthorizationRepository:
    def __init__(
        self,
        agents: Iterable[RegistryAgent] = (),
        tools: Iterable[RegistryTool] = (),
        policies: Iterable[PolicyMatch] = (),
    ) -> None:
        self.agents = {(x.tenant_id, x.agent_id): x for x in agents}
        self.tools = {(x.tenant_id, x.tool_id): x for x in tools}
        self.policies = list(policies)
        self.decisions: dict[tuple[str, str], PersistedDecision] = {}
        self.adr_documents: list[dict] = []
        self.normalized_contexts: dict[tuple[str, str], dict] = {}
        self.fail_writes = False
        self._decision_lock = Lock()

    def get_agent(self, tenant_id: str, agent_id: str) -> RegistryAgent | None:
        return self.agents.get((tenant_id, agent_id))

    def get_tool(self, tenant_id: str, tool_id: str) -> RegistryTool | None:
        return self.tools.get((tenant_id, tool_id))

    def matching_policies(
        self, tenant_id: str, context: EvaluationContext, risk_level: str | None = None
    ) -> list[PolicyMatch]:
        return self.policies

    def find_decision_by_request(self, tenant_id: str, request_id: str) -> PersistedDecision | None:
        return self.decisions.get((tenant_id, request_id))

    def persist_decision(
        self, decision: PersistedDecision, adr_document: dict, normalized_context: dict
    ) -> None:
        if self.fail_writes:
            raise EvidenceWriteError("injected evidence failure")
        key = (adr_document["tenant_id"], str(decision.request_id))
        with self._decision_lock:
            if key in self.decisions:
                raise DuplicateRequestIdError("request_id was committed concurrently")
            self.decisions[key] = decision
            self.adr_documents.append(adr_document)
            self.normalized_contexts[(adr_document["tenant_id"], decision.decision_id)] = (
                copy.deepcopy(normalized_context)
            )
