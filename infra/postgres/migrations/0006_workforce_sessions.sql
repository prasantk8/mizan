BEGIN;

-- Browser credentials are opaque, short-lived server-side sessions. The tenant prefix carried
-- by a cookie or OIDC state selects only the RLS scope; possession of the random secret is still
-- required, and only its SHA-256 digest is persisted.
CREATE TABLE mizan.workforce_login_transactions (
  tenant_id mizan.tenant_id NOT NULL REFERENCES mizan.tenants(tenant_id),
  state_digest mizan.sha256_hex NOT NULL,
  nonce text NOT NULL,
  pkce_verifier text NOT NULL,
  return_to text NOT NULL,
  requested_acr text,
  prior_session_id uuid,
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, state_digest)
);

CREATE TABLE mizan.workforce_sessions (
  tenant_id mizan.tenant_id NOT NULL REFERENCES mizan.tenants(tenant_id),
  session_id uuid NOT NULL,
  secret_digest mizan.sha256_hex NOT NULL,
  principal_id mizan.principal_id NOT NULL,
  idp_subject text NOT NULL,
  roles jsonb NOT NULL CHECK (jsonb_typeof(roles) = 'array'),
  control_domains jsonb NOT NULL CHECK (jsonb_typeof(control_domains) = 'object'),
  auth_strength text NOT NULL CHECK (auth_strength IN ('mfa','hardware')),
  step_up_at timestamptz,
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  last_seen_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, session_id),
  UNIQUE (tenant_id, secret_digest)
);

DO $$
DECLARE table_name text;
BEGIN
  FOREACH table_name IN ARRAY ARRAY['workforce_login_transactions','workforce_sessions'] LOOP
    EXECUTE format('ALTER TABLE mizan.%I ENABLE ROW LEVEL SECURITY', table_name);
    EXECUTE format('ALTER TABLE mizan.%I FORCE ROW LEVEL SECURITY', table_name);
    EXECUTE format(
      'CREATE POLICY tenant_isolation ON mizan.%I USING (tenant_id = mizan.current_tenant_id()) WITH CHECK (tenant_id = mizan.current_tenant_id())',
      table_name
    );
  END LOOP;
END $$;

GRANT SELECT, INSERT, UPDATE, DELETE ON mizan.workforce_login_transactions,
  mizan.workforce_sessions TO mizan_app;

COMMIT;
