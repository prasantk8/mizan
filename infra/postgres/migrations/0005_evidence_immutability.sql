BEGIN;

-- The policy citations and normalized context are part of the immutable authorization snapshot.
-- A mutable citation can change which policy appears to have produced a signed ADR_Record; a mutable
-- context can change what the decision appears to have evaluated. Give both the same two independent
-- database controls as every other evidence table: the runtime role cannot issue the statements, and
-- an owner/migration-role statement that reaches the table is refused by the trigger with SQLSTATE
-- 55000 rather than silently rewriting history.
CREATE TRIGGER adr_record_policies_immutable
BEFORE UPDATE OR DELETE ON mizan.adr_record_policies
FOR EACH ROW EXECUTE FUNCTION mizan.reject_evidence_mutation();

CREATE TRIGGER authorization_contexts_immutable
BEFORE UPDATE OR DELETE ON mizan.authorization_contexts
FOR EACH ROW EXECUTE FUNCTION mizan.reject_evidence_mutation();

REVOKE UPDATE, DELETE ON mizan.adr_record_policies, mizan.authorization_contexts FROM mizan_app;

COMMIT;
