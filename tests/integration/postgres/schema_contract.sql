\set ON_ERROR_STOP on

DO $$
DECLARE missing_count integer;
BEGIN
  SELECT count(*) INTO missing_count
  FROM (VALUES
    ('tenants'),('agents'),('binding_profiles'),('tools'),('policies'),('agent_tools'),
    ('agent_policies'),('agent_delegations'),('policy_simulations'),('evidence_chain_heads'),('adr_records'),
    ('adr_record_policies'),('authorization_contexts'),('approvals'),('role_authority_versions'),('approval_epochs'),('approval_votes'),
    ('execution_tokens'),('execution_leases'),('decision_events'),('decision_event_heads'),('audit_trails'),('external_payload_envelopes'),
    ('degraded_mode_grants'),('outbox'),('evidence_receipts'),('evidence_anchors'),
    ('anchor_attestations')
  ) expected(name)
  LEFT JOIN pg_class c ON c.relname = expected.name
  LEFT JOIN pg_namespace n ON n.oid = c.relnamespace AND n.nspname = 'mizan'
  WHERE n.oid IS NULL;
  IF missing_count <> 0 THEN RAISE EXCEPTION '% required tables missing', missing_count; END IF;
END $$;

DO $$
DECLARE unprotected_count integer;
BEGIN
  SELECT count(*) INTO unprotected_count
  FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
  WHERE n.nspname = 'mizan' AND c.relkind = 'r'
    AND (NOT c.relrowsecurity OR NOT c.relforcerowsecurity);
  IF unprotected_count <> 0 THEN RAISE EXCEPTION '% tables lack forced RLS', unprotected_count; END IF;
END $$;

DO $$
DECLARE table_name text;
BEGIN
  FOREACH table_name IN ARRAY ARRAY[
    'adr_records','authorization_contexts','decision_events','audit_trails','approval_votes','evidence_receipts','evidence_anchors','anchor_attestations'
  ] LOOP
    IF has_table_privilege('mizan_app', 'mizan.' || table_name, 'UPDATE')
       OR has_table_privilege('mizan_app', 'mizan.' || table_name, 'DELETE') THEN
      RAISE EXCEPTION 'runtime role can mutate immutable table %', table_name;
    END IF;
  END LOOP;
END $$;

INSERT INTO mizan.tenants(tenant_id, region, status)
VALUES ('tnt_bank-a', 'ae-dubai-1', 'ACTIVE'), ('tnt_bank-b', 'ae-dubai-1', 'ACTIVE'),
       -- Owned by tests/integration/test_approval_expiry_postgres.py. Both fixture
       -- tenants above already carry a test that asserts an exact tenant-wide drain
       -- count, so a file that seeds decisions of its own needs a tenant of its own.
       -- `mizan_app` cannot create one: `mizan.tenants` is FORCE RLS and there is no
       -- SECURITY DEFINER path, which is the same fact B-27 is about.
       ('tnt_expiry-sweep', 'ae-dubai-1', 'ACTIVE');

SET ROLE mizan_app;
BEGIN;
SELECT set_config('app.tenant_id', 'tnt_bank-a', true);
DO $$
BEGIN
  IF (SELECT count(*) FROM mizan.tenants) <> 1 THEN
    RAISE EXCEPTION 'RLS exposed another tenant';
  END IF;
END $$;
COMMIT;
RESET ROLE;

INSERT INTO mizan.binding_profiles(
  tenant_id, profile_id, profile_version, canonicalization,
  bound_pointers, volatile_pointers, content_hash
) VALUES (
  'tnt_bank-a', 'bp_transfer-v1', 1, 'RFC8785', '["/amount"]', '["/request_time"]', repeat('1', 64)
);
INSERT INTO mizan.tools(tenant_id, tool_id, profile_id, profile_version, document)
VALUES ('tnt_bank-a', 'tool_transfer', 'bp_transfer-v1', 1,
  '{"tenant_id":"tnt_bank-a","tool_id":"tool_transfer","risk_tier":"HIGH","owner":"wealth-team","resource_owner":"core-banking","data_classification":"financial","binding_profile":{"profile_id":"bp_transfer-v1","profile_version":1,"canonicalization":"RFC8785","bound_pointers":["/amount"],"volatile_pointers":["/request_time"],"unknown_pointer_policy":"reject"},"execution":{"executor_spiffe_ids":["spiffe://mizan/executor/wealth","spiffe://mizan/executor/settlement"],"token_ttl_seconds":300,"lease_ttl_seconds":900,"heartbeat_interval_seconds":60,"max_lease_extensions":24}}');
INSERT INTO mizan.agents(
  tenant_id, agent_id, version, lifecycle_state, document, created_at, updated_at
) VALUES (
  'tnt_bank-a', 'agt_wealth-01', '1.0.0', 'ACTIVE',
  '{"tenant_id":"tnt_bank-a","agent_id":"agt_wealth-01"}', now(), now()
);
INSERT INTO mizan.evidence_chain_heads(tenant_id, stream_id)
VALUES ('tnt_bank-a', 'tnt_bank-a:adr:0');
INSERT INTO mizan.agent_tools(tenant_id, agent_id, tool_id)
VALUES ('tnt_bank-a', 'agt_wealth-01', 'tool_transfer');
INSERT INTO mizan.policies(
  tenant_id, policy_id, version, status, effective_from, decision, content_hash, document, created_at
) VALUES (
  'tnt_bank-a', 'pol_blocked-intent', 1, 'ACTIVE', now() - interval '1 minute', 'ALLOW', repeat('4', 64),
  '{"schema_version":"1.2","policy_id":"pol_blocked-intent","tenant_id":"tnt_bank-a","name":"Allow fixture","version":1,"status":"ACTIVE","author":"risk-team","applies_to":{"tool_ids":["tool_transfer"]},"conditions":{"field":"action.type","op":"eq","value":"financial_write"},"decision":"ALLOW","priority":100,"content_hash":"4444444444444444444444444444444444444444444444444444444444444444","created_at":"2026-08-25T00:00:00Z"}',
  now() - interval '1 minute'
);
INSERT INTO mizan.role_authority_versions(tenant_id,mapping_version,status,document,approved_at)
VALUES (
  'tnt_bank-a', 1, 'APPROVED',
  '{"members":[{"principal_id":"prn_alice","roles":["manager"],"control_domain":"business.ops"},{"principal_id":"prn_bob","roles":["manager"],"control_domain":"risk.control"},{"principal_id":"prn_compliance","roles":["compliance"],"control_domain":"compliance.control"}]}',
  now()
);
INSERT INTO mizan.degraded_mode_grants(
  tenant_id,grant_id,nonce,not_before,expires_at,document
) VALUES (
  'tnt_bank-a','dgr_fixture-0001','dgn_0123456789abcdef',now(),now()+interval '5 minutes',
  '{"tenant_id":"tnt_bank-a","grant_id":"dgr_fixture-0001","nonce":"dgn_0123456789abcdef"}'
);

SET ROLE mizan_app;
BEGIN;
SELECT set_config('app.tenant_id', 'tnt_bank-a', true);
DO $$
DECLARE allocated bigint;
BEGIN
  allocated := mizan.reserve_evidence_sequence(
    'tnt_bank-a', 'tnt_bank-a:adr:0', repeat('0', 64), repeat('2', 64)
  );
  IF allocated <> 0 THEN RAISE EXCEPTION 'first sequence was %', allocated; END IF;
  BEGIN
    PERFORM mizan.reserve_evidence_sequence(
      'tnt_bank-a', 'tnt_bank-a:adr:0', repeat('0', 64), repeat('3', 64)
    );
    RAISE EXCEPTION 'stale chain head accepted';
  EXCEPTION WHEN serialization_failure THEN NULL;
  END;
END $$;

INSERT INTO mizan.adr_records(
  tenant_id, decision_id, request_id, trace_id, context_hash, agent_id, tool_id, stream_id,
  sequence_number, prev_hash, record_hash, decision, document, created_at
) VALUES (
  'tnt_bank-a', 'adr_decision-0001', '018f47a6-7b42-7c00-8000-000000000001',
  repeat('a', 32), repeat('c', 64), 'agt_wealth-01', 'tool_transfer', 'tnt_bank-a:adr:0', 0,
  repeat('0', 64), repeat('2', 64), 'ALLOW',
  '{"tenant_id":"tnt_bank-a","decision_id":"adr_decision-0001"}', now()
);
INSERT INTO mizan.decision_event_heads(tenant_id, decision_id)
VALUES ('tnt_bank-a', 'adr_decision-0001');
DO $$
BEGIN
  BEGIN
    UPDATE mizan.adr_records SET decision = 'DENY'
    WHERE tenant_id = 'tnt_bank-a' AND decision_id = 'adr_decision-0001';
    RAISE EXCEPTION 'immutable ADR accepted update';
  EXCEPTION WHEN object_not_in_prerequisite_state OR insufficient_privilege THEN NULL;
  END;
END $$;
ROLLBACK;
RESET ROLE;

DO $$
BEGIN
  BEGIN
    INSERT INTO mizan.tenants(tenant_id, region, status) VALUES ('pol_wrong-family', 'x', 'ACTIVE');
    RAISE EXCEPTION 'typed ID domain accepted wrong prefix';
  EXCEPTION WHEN check_violation THEN NULL;
  END;
END $$;

SELECT 'schema contract passed' AS result;
