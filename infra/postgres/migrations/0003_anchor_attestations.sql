BEGIN;

CREATE TABLE mizan.anchor_attestations (
  tenant_id mizan.tenant_id NOT NULL,
  anchor_id uuid NOT NULL,
  authority text NOT NULL,
  attestation_type text NOT NULL CHECK (attestation_type IN ('rfc3161','customer_countersignature')),
  document jsonb NOT NULL CHECK (jsonb_typeof(document) = 'object'),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, anchor_id, authority, attestation_type),
  FOREIGN KEY (tenant_id, anchor_id) REFERENCES mizan.evidence_anchors(tenant_id, anchor_id)
);

CREATE TRIGGER anchor_attestations_immutable BEFORE UPDATE OR DELETE ON mizan.anchor_attestations
FOR EACH ROW EXECUTE FUNCTION mizan.reject_evidence_mutation();
ALTER TABLE mizan.anchor_attestations ENABLE ROW LEVEL SECURITY;
ALTER TABLE mizan.anchor_attestations FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON mizan.anchor_attestations
  USING (tenant_id = mizan.current_tenant_id())
  WITH CHECK (tenant_id = mizan.current_tenant_id());
GRANT SELECT, INSERT ON mizan.anchor_attestations TO mizan_app;
REVOKE UPDATE, DELETE ON mizan.anchor_attestations FROM mizan_app;

COMMIT;
