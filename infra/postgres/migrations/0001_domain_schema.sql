BEGIN;

CREATE SCHEMA IF NOT EXISTS mizan;
REVOKE ALL ON SCHEMA mizan FROM PUBLIC;

DO $$ BEGIN
  CREATE ROLE mizan_app NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

CREATE DOMAIN mizan.tenant_id AS text CHECK (VALUE ~ '^tnt_[a-z0-9-]{4,64}$');
CREATE DOMAIN mizan.agent_id AS text CHECK (VALUE ~ '^agt_[a-z0-9-]{6,64}$');
CREATE DOMAIN mizan.tool_id AS text CHECK (VALUE ~ '^tool_[a-z0-9_.-]{3,64}$');
CREATE DOMAIN mizan.policy_id AS text CHECK (VALUE ~ '^pol_[a-z0-9-]{4,64}$');
CREATE DOMAIN mizan.decision_id AS text CHECK (VALUE ~ '^adr_[a-z0-9-]{8,64}$');
CREATE DOMAIN mizan.approval_id AS text CHECK (VALUE ~ '^apr_[a-z0-9-]{8,64}$');
CREATE DOMAIN mizan.epoch_id AS text CHECK (VALUE ~ '^epo_[a-z0-9-]{8,64}$');
CREATE DOMAIN mizan.vote_id AS text CHECK (VALUE ~ '^vot_[a-z0-9-]{8,64}$');
CREATE DOMAIN mizan.lease_id AS text CHECK (VALUE ~ '^lse_[a-z0-9-]{8,64}$');
CREATE DOMAIN mizan.audit_id AS text CHECK (VALUE ~ '^aud_[a-z0-9-]{8,64}$');
CREATE DOMAIN mizan.decision_event_id AS text CHECK (VALUE ~ '^dev_[a-z0-9-]{8,64}$');
CREATE DOMAIN mizan.binding_profile_id AS text CHECK (VALUE ~ '^bp_[a-z0-9_.-]{3,64}$');
CREATE DOMAIN mizan.projection_id AS text CHECK (VALUE ~ '^prj_[a-z0-9_.-]{3,64}$');
CREATE DOMAIN mizan.degraded_grant_id AS text CHECK (VALUE ~ '^dgr_[a-z0-9-]{8,64}$');
CREATE DOMAIN mizan.principal_id AS text CHECK (VALUE ~ '^prn_[A-Za-z0-9-]{2,64}$');
CREATE DOMAIN mizan.sha256_hex AS text CHECK (VALUE ~ '^[0-9a-f]{64}$');
CREATE DOMAIN mizan.trace_id AS text CHECK (VALUE ~ '^[0-9a-f]{32}$');

CREATE FUNCTION mizan.current_tenant_id() RETURNS mizan.tenant_id
LANGUAGE sql STABLE PARALLEL SAFE
AS $$ SELECT NULLIF(current_setting('app.tenant_id', true), '')::mizan.tenant_id $$;

CREATE TABLE mizan.tenants (
  tenant_id mizan.tenant_id PRIMARY KEY,
  region text NOT NULL,
  status text NOT NULL CHECK (status IN ('ACTIVE', 'SUSPENDED', 'OFFBOARDED')),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE mizan.agents (
  tenant_id mizan.tenant_id NOT NULL REFERENCES mizan.tenants(tenant_id),
  agent_id mizan.agent_id NOT NULL,
  version text NOT NULL,
  lifecycle_state text NOT NULL,
  parent_agent_id mizan.agent_id,
  document jsonb NOT NULL CHECK (jsonb_typeof(document) = 'object'),
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, agent_id),
  FOREIGN KEY (tenant_id, parent_agent_id) REFERENCES mizan.agents(tenant_id, agent_id),
  CHECK (document->>'tenant_id' = tenant_id::text),
  CHECK (document->>'agent_id' = agent_id::text)
);

CREATE TABLE mizan.binding_profiles (
  tenant_id mizan.tenant_id NOT NULL REFERENCES mizan.tenants(tenant_id),
  profile_id mizan.binding_profile_id NOT NULL,
  profile_version integer NOT NULL CHECK (profile_version > 0),
  canonicalization text NOT NULL CHECK (canonicalization = 'RFC8785'),
  bound_pointers jsonb NOT NULL CHECK (jsonb_typeof(bound_pointers) = 'array'),
  volatile_pointers jsonb NOT NULL CHECK (jsonb_typeof(volatile_pointers) = 'array'),
  content_hash mizan.sha256_hex NOT NULL,
  PRIMARY KEY (tenant_id, profile_id, profile_version)
);

CREATE TABLE mizan.tools (
  tenant_id mizan.tenant_id NOT NULL REFERENCES mizan.tenants(tenant_id),
  tool_id mizan.tool_id NOT NULL,
  profile_id mizan.binding_profile_id NOT NULL,
  profile_version integer NOT NULL,
  status text NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'SUSPENDED', 'RETIRED')),
  document jsonb NOT NULL CHECK (jsonb_typeof(document) = 'object'),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, tool_id),
  FOREIGN KEY (tenant_id, profile_id, profile_version)
    REFERENCES mizan.binding_profiles(tenant_id, profile_id, profile_version),
  CHECK (document->>'tenant_id' = tenant_id::text),
  CHECK (document->>'tool_id' = tool_id::text)
);

CREATE TABLE mizan.policies (
  tenant_id mizan.tenant_id NOT NULL REFERENCES mizan.tenants(tenant_id),
  policy_id mizan.policy_id NOT NULL,
  version integer NOT NULL CHECK (version > 0),
  status text NOT NULL CHECK (status IN ('DRAFT','TESTED','APPROVED','ACTIVE','SUPERSEDED','RETIRED')),
  decision text NOT NULL CHECK (decision IN ('ALLOW','DENY','REQUIRE_APPROVAL','CONSTRAIN','REDACT','ESCALATE')),
  content_hash mizan.sha256_hex NOT NULL,
  document jsonb NOT NULL CHECK (jsonb_typeof(document) = 'object'),
  created_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, policy_id, version),
  UNIQUE (tenant_id, policy_id, content_hash),
  UNIQUE (tenant_id, policy_id, version, content_hash),
  CHECK (document->>'tenant_id' = tenant_id::text),
  CHECK (document->>'policy_id' = policy_id::text),
  CHECK ((document->>'version')::integer = version)
);

CREATE TABLE mizan.agent_tools (
  tenant_id mizan.tenant_id NOT NULL,
  agent_id mizan.agent_id NOT NULL,
  tool_id mizan.tool_id NOT NULL,
  PRIMARY KEY (tenant_id, agent_id, tool_id),
  FOREIGN KEY (tenant_id, agent_id) REFERENCES mizan.agents(tenant_id, agent_id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id, tool_id) REFERENCES mizan.tools(tenant_id, tool_id) ON DELETE RESTRICT
);

CREATE TABLE mizan.agent_policies (
  tenant_id mizan.tenant_id NOT NULL,
  agent_id mizan.agent_id NOT NULL,
  policy_id mizan.policy_id NOT NULL,
  policy_version integer NOT NULL,
  PRIMARY KEY (tenant_id, agent_id, policy_id, policy_version),
  FOREIGN KEY (tenant_id, agent_id) REFERENCES mizan.agents(tenant_id, agent_id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id, policy_id, policy_version) REFERENCES mizan.policies(tenant_id, policy_id, version)
);

CREATE TABLE mizan.agent_delegations (
  tenant_id mizan.tenant_id NOT NULL,
  parent_agent_id mizan.agent_id NOT NULL,
  child_agent_id mizan.agent_id NOT NULL,
  PRIMARY KEY (tenant_id, parent_agent_id, child_agent_id),
  FOREIGN KEY (tenant_id, parent_agent_id) REFERENCES mizan.agents(tenant_id, agent_id),
  FOREIGN KEY (tenant_id, child_agent_id) REFERENCES mizan.agents(tenant_id, agent_id),
  CHECK (parent_agent_id <> child_agent_id)
);

CREATE TABLE mizan.evidence_chain_heads (
  tenant_id mizan.tenant_id NOT NULL REFERENCES mizan.tenants(tenant_id),
  stream_id text NOT NULL CHECK (stream_id ~ '^tnt_[a-z0-9-]{4,64}:(adr|audit):[a-z0-9-]{1,32}$'),
  next_sequence bigint NOT NULL DEFAULT 0 CHECK (next_sequence >= 0),
  last_hash mizan.sha256_hex NOT NULL DEFAULT repeat('0', 64)::mizan.sha256_hex,
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, stream_id),
  CHECK (split_part(stream_id, ':', 1) = tenant_id::text)
);

CREATE TABLE mizan.adr_records (
  tenant_id mizan.tenant_id NOT NULL REFERENCES mizan.tenants(tenant_id),
  decision_id mizan.decision_id NOT NULL,
  request_id uuid NOT NULL,
  trace_id mizan.trace_id NOT NULL,
  context_hash mizan.sha256_hex NOT NULL,
  agent_id mizan.agent_id NOT NULL,
  tool_id mizan.tool_id NOT NULL,
  stream_id text NOT NULL,
  sequence_number bigint NOT NULL CHECK (sequence_number >= 0),
  prev_hash mizan.sha256_hex NOT NULL,
  record_hash mizan.sha256_hex NOT NULL,
  decision text NOT NULL CHECK (decision IN ('ALLOW','DENY','REQUIRE_APPROVAL','CONSTRAIN','REDACT','ESCALATE')),
  immutable_receipt_ref text,
  document jsonb NOT NULL CHECK (jsonb_typeof(document) = 'object'),
  created_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, decision_id),
  UNIQUE (tenant_id, request_id),
  UNIQUE (tenant_id, stream_id, sequence_number),
  UNIQUE (tenant_id, decision_id, record_hash),
  FOREIGN KEY (tenant_id, agent_id) REFERENCES mizan.agents(tenant_id, agent_id),
  FOREIGN KEY (tenant_id, tool_id) REFERENCES mizan.tools(tenant_id, tool_id),
  FOREIGN KEY (tenant_id, stream_id) REFERENCES mizan.evidence_chain_heads(tenant_id, stream_id),
  CHECK (document->>'tenant_id' = tenant_id::text),
  CHECK (document->>'decision_id' = decision_id::text)
);

CREATE TABLE mizan.adr_record_policies (
  tenant_id mizan.tenant_id NOT NULL,
  decision_id mizan.decision_id NOT NULL,
  policy_id mizan.policy_id NOT NULL,
  policy_version integer NOT NULL,
  content_hash mizan.sha256_hex NOT NULL,
  PRIMARY KEY (tenant_id, decision_id, policy_id, policy_version),
  FOREIGN KEY (tenant_id, decision_id) REFERENCES mizan.adr_records(tenant_id, decision_id),
  FOREIGN KEY (tenant_id, policy_id, policy_version, content_hash)
    REFERENCES mizan.policies(tenant_id, policy_id, version, content_hash)
);

CREATE TABLE mizan.approvals (
  tenant_id mizan.tenant_id NOT NULL REFERENCES mizan.tenants(tenant_id),
  approval_id mizan.approval_id NOT NULL,
  decision_id mizan.decision_id NOT NULL,
  state text NOT NULL,
  active_epoch_id mizan.epoch_id,
  document jsonb NOT NULL CHECK (jsonb_typeof(document) = 'object'),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, approval_id),
  UNIQUE (tenant_id, decision_id),
  FOREIGN KEY (tenant_id, decision_id) REFERENCES mizan.adr_records(tenant_id, decision_id),
  CHECK (document->>'tenant_id' = tenant_id::text),
  CHECK (document->>'approval_id' = approval_id::text)
);

CREATE TABLE mizan.approval_epochs (
  tenant_id mizan.tenant_id NOT NULL,
  epoch_id mizan.epoch_id NOT NULL,
  approval_id mizan.approval_id NOT NULL,
  epoch_number integer NOT NULL CHECK (epoch_number > 0),
  state text NOT NULL CHECK (state IN ('OPEN','CLOSED_APPROVED','CLOSED_REJECTED','CLOSED_EXPIRED','CLOSED_ESCALATED','CLOSED_OVERRIDDEN','CLOSED_WITHDRAWN')),
  eligibility_snapshot jsonb NOT NULL CHECK (jsonb_typeof(eligibility_snapshot) = 'object'),
  opened_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL CHECK (expires_at > opened_at),
  closed_at timestamptz,
  PRIMARY KEY (tenant_id, epoch_id),
  UNIQUE (tenant_id, approval_id, epoch_number),
  FOREIGN KEY (tenant_id, approval_id) REFERENCES mizan.approvals(tenant_id, approval_id)
);

ALTER TABLE mizan.approvals ADD CONSTRAINT approvals_active_epoch_fk
  FOREIGN KEY (tenant_id, active_epoch_id) REFERENCES mizan.approval_epochs(tenant_id, epoch_id)
  DEFERRABLE INITIALLY DEFERRED;

CREATE TABLE mizan.approval_votes (
  tenant_id mizan.tenant_id NOT NULL,
  vote_id mizan.vote_id NOT NULL,
  approval_id mizan.approval_id NOT NULL,
  epoch_id mizan.epoch_id NOT NULL,
  approver_id mizan.principal_id NOT NULL,
  control_domain text NOT NULL,
  vote text NOT NULL CHECK (vote IN ('APPROVE','REJECT')),
  voted_at timestamptz NOT NULL,
  document jsonb NOT NULL CHECK (jsonb_typeof(document) = 'object'),
  PRIMARY KEY (tenant_id, vote_id),
  UNIQUE (tenant_id, epoch_id, approver_id),
  FOREIGN KEY (tenant_id, approval_id) REFERENCES mizan.approvals(tenant_id, approval_id),
  FOREIGN KEY (tenant_id, epoch_id) REFERENCES mizan.approval_epochs(tenant_id, epoch_id)
);

CREATE TABLE mizan.execution_leases (
  tenant_id mizan.tenant_id NOT NULL REFERENCES mizan.tenants(tenant_id),
  lease_id mizan.lease_id NOT NULL,
  redeemed_jti uuid NOT NULL,
  decision_id mizan.decision_id NOT NULL,
  agent_id mizan.agent_id NOT NULL,
  tool_id mizan.tool_id NOT NULL,
  principal_id mizan.principal_id NOT NULL,
  state text NOT NULL CHECK (state IN ('LEASED','EXECUTING','EXECUTED','FAILED','EXPIRED')),
  document jsonb NOT NULL CHECK (jsonb_typeof(document) = 'object'),
  expires_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, lease_id),
  UNIQUE (tenant_id, redeemed_jti),
  FOREIGN KEY (tenant_id, decision_id) REFERENCES mizan.adr_records(tenant_id, decision_id),
  FOREIGN KEY (tenant_id, agent_id) REFERENCES mizan.agents(tenant_id, agent_id),
  FOREIGN KEY (tenant_id, tool_id) REFERENCES mizan.tools(tenant_id, tool_id)
);

CREATE TABLE mizan.decision_events (
  tenant_id mizan.tenant_id NOT NULL REFERENCES mizan.tenants(tenant_id),
  event_id mizan.decision_event_id NOT NULL,
  decision_id mizan.decision_id NOT NULL,
  decision_sequence bigint NOT NULL CHECK (decision_sequence > 0),
  event_type text NOT NULL,
  previous_event_hash mizan.sha256_hex NOT NULL,
  event_hash mizan.sha256_hex NOT NULL,
  immutable_receipt_ref text,
  document jsonb NOT NULL CHECK (jsonb_typeof(document) = 'object'),
  occurred_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, event_id),
  UNIQUE (tenant_id, decision_id, decision_sequence),
  UNIQUE (tenant_id, decision_id, event_hash),
  FOREIGN KEY (tenant_id, decision_id) REFERENCES mizan.adr_records(tenant_id, decision_id),
  CHECK (document->>'tenant_id' = tenant_id::text),
  CHECK (document->>'event_id' = event_id::text)
);

CREATE TABLE mizan.decision_event_heads (
  tenant_id mizan.tenant_id NOT NULL,
  decision_id mizan.decision_id NOT NULL,
  next_sequence bigint NOT NULL DEFAULT 1 CHECK (next_sequence > 0),
  last_hash mizan.sha256_hex NOT NULL DEFAULT repeat('0', 64)::mizan.sha256_hex,
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, decision_id),
  FOREIGN KEY (tenant_id, decision_id) REFERENCES mizan.adr_records(tenant_id, decision_id)
);

CREATE TABLE mizan.audit_trails (
  tenant_id mizan.tenant_id NOT NULL REFERENCES mizan.tenants(tenant_id),
  audit_id mizan.audit_id NOT NULL,
  stream_id text NOT NULL,
  sequence_number bigint NOT NULL CHECK (sequence_number >= 0),
  prev_hash mizan.sha256_hex NOT NULL,
  record_hash mizan.sha256_hex NOT NULL,
  document jsonb NOT NULL CHECK (jsonb_typeof(document) = 'object'),
  occurred_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, audit_id),
  UNIQUE (tenant_id, stream_id, sequence_number),
  FOREIGN KEY (tenant_id, stream_id) REFERENCES mizan.evidence_chain_heads(tenant_id, stream_id)
);

CREATE TABLE mizan.external_payload_envelopes (
  tenant_id mizan.tenant_id NOT NULL REFERENCES mizan.tenants(tenant_id),
  envelope_id uuid NOT NULL,
  projection_id mizan.projection_id NOT NULL,
  projection_version integer NOT NULL CHECK (projection_version > 0),
  raw_hash mizan.sha256_hex NOT NULL,
  disposition text NOT NULL CHECK (disposition IN ('discarded_after_projection','encrypted_evidence','redacted_payload')),
  document jsonb NOT NULL CHECK (jsonb_typeof(document) = 'object'),
  received_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, envelope_id)
);

CREATE TABLE mizan.degraded_mode_grants (
  tenant_id mizan.tenant_id NOT NULL REFERENCES mizan.tenants(tenant_id),
  grant_id mizan.degraded_grant_id NOT NULL,
  nonce uuid NOT NULL,
  not_before timestamptz NOT NULL,
  expires_at timestamptz NOT NULL CHECK (expires_at > not_before),
  revoked_at timestamptz,
  document jsonb NOT NULL CHECK (jsonb_typeof(document) = 'object'),
  PRIMARY KEY (tenant_id, grant_id),
  UNIQUE (tenant_id, nonce)
);

CREATE TABLE mizan.outbox (
  tenant_id mizan.tenant_id NOT NULL REFERENCES mizan.tenants(tenant_id),
  outbox_id bigint GENERATED ALWAYS AS IDENTITY,
  aggregate_type text NOT NULL,
  aggregate_id text NOT NULL,
  event_type text NOT NULL,
  payload jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  published_at timestamptz,
  attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
  PRIMARY KEY (tenant_id, outbox_id)
);

CREATE FUNCTION mizan.reject_evidence_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'immutable evidence table % does not permit %', TG_TABLE_NAME, TG_OP
    USING ERRCODE = '55000';
END $$;

CREATE TRIGGER adr_records_immutable BEFORE UPDATE OR DELETE ON mizan.adr_records
FOR EACH ROW EXECUTE FUNCTION mizan.reject_evidence_mutation();
CREATE TRIGGER decision_events_immutable BEFORE UPDATE OR DELETE ON mizan.decision_events
FOR EACH ROW EXECUTE FUNCTION mizan.reject_evidence_mutation();
CREATE TRIGGER audit_trails_immutable BEFORE UPDATE OR DELETE ON mizan.audit_trails
FOR EACH ROW EXECUTE FUNCTION mizan.reject_evidence_mutation();
CREATE TRIGGER approval_votes_immutable BEFORE UPDATE OR DELETE ON mizan.approval_votes
FOR EACH ROW EXECUTE FUNCTION mizan.reject_evidence_mutation();

CREATE FUNCTION mizan.reserve_evidence_sequence(
  requested_tenant mizan.tenant_id,
  requested_stream text,
  expected_previous_hash mizan.sha256_hex,
  new_hash mizan.sha256_hex
) RETURNS bigint LANGUAGE plpgsql SECURITY INVOKER AS $$
DECLARE allocated bigint;
BEGIN
  IF requested_tenant IS DISTINCT FROM mizan.current_tenant_id() THEN
    RAISE EXCEPTION 'tenant context mismatch' USING ERRCODE = '42501';
  END IF;
  UPDATE mizan.evidence_chain_heads
     SET next_sequence = next_sequence + 1,
         last_hash = new_hash,
         updated_at = clock_timestamp()
   WHERE tenant_id = requested_tenant
     AND stream_id = requested_stream
     AND last_hash = expected_previous_hash
   RETURNING next_sequence - 1 INTO allocated;
  IF allocated IS NULL THEN
    RAISE EXCEPTION 'chain head conflict' USING ERRCODE = '40001';
  END IF;
  RETURN allocated;
END $$;

CREATE FUNCTION mizan.reserve_decision_event_sequence(
  requested_tenant mizan.tenant_id,
  requested_decision mizan.decision_id,
  expected_previous_hash mizan.sha256_hex,
  new_hash mizan.sha256_hex
) RETURNS bigint LANGUAGE plpgsql SECURITY INVOKER AS $$
DECLARE allocated bigint;
BEGIN
  IF requested_tenant IS DISTINCT FROM mizan.current_tenant_id() THEN
    RAISE EXCEPTION 'tenant context mismatch' USING ERRCODE = '42501';
  END IF;
  UPDATE mizan.decision_event_heads
     SET next_sequence = next_sequence + 1,
         last_hash = new_hash,
         updated_at = clock_timestamp()
   WHERE tenant_id = requested_tenant
     AND decision_id = requested_decision
     AND last_hash = expected_previous_hash
   RETURNING next_sequence - 1 INTO allocated;
  IF allocated IS NULL THEN
    RAISE EXCEPTION 'decision event head conflict' USING ERRCODE = '40001';
  END IF;
  RETURN allocated;
END $$;

DO $$
DECLARE table_name text;
BEGIN
  FOREACH table_name IN ARRAY ARRAY[
    'tenants','agents','binding_profiles','tools','policies','agent_tools','agent_policies',
    'agent_delegations','evidence_chain_heads','adr_records','adr_record_policies','approvals',
    'approval_epochs','approval_votes','execution_leases','decision_events','decision_event_heads','audit_trails',
    'external_payload_envelopes','degraded_mode_grants','outbox'
  ] LOOP
    EXECUTE format('ALTER TABLE mizan.%I ENABLE ROW LEVEL SECURITY', table_name);
    EXECUTE format('ALTER TABLE mizan.%I FORCE ROW LEVEL SECURITY', table_name);
    EXECUTE format(
      'CREATE POLICY tenant_isolation ON mizan.%I USING (tenant_id = mizan.current_tenant_id()) WITH CHECK (tenant_id = mizan.current_tenant_id())',
      table_name
    );
  END LOOP;
END $$;

GRANT USAGE ON SCHEMA mizan TO mizan_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA mizan TO mizan_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA mizan TO mizan_app;
GRANT EXECUTE ON FUNCTION mizan.current_tenant_id() TO mizan_app;
GRANT EXECUTE ON FUNCTION mizan.reserve_evidence_sequence(mizan.tenant_id, text, mizan.sha256_hex, mizan.sha256_hex) TO mizan_app;
GRANT EXECUTE ON FUNCTION mizan.reserve_decision_event_sequence(mizan.tenant_id, mizan.decision_id, mizan.sha256_hex, mizan.sha256_hex) TO mizan_app;

COMMIT;
