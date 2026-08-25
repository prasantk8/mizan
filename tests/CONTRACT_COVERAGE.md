# SPEC v1.2 Contract Coverage

This is the executable-suite index. A row is not considered covered merely because it appears here;
the referenced test must be collected by pytest and assert the named behavior. PostgreSQL rows run in
`make test-postgres`. B-7 and B-8 are explicit contract blockers in `WORK_LOG.md`.

| Contract | Primary executable evidence |
|---|---|
| I-1 | `integration/test_authorize_postgres.py::test_authorize_persists_adr_and_outbox_atomically` |
| I-2 | `unit/test_invariant_properties.py::test_i2_property_hash_chain_is_contiguous` |
| I-3 | `unit/test_authorization.py::test_tenant_is_derived_from_identity` |
| I-4, I-5 | `unit/test_authorization.py::test_delegation_requires_registered_edge_depth_and_parent_tool_permission` |
| I-6 | `unit/test_invariant_properties.py::test_i6_i15_approval_state_machine_fuzzer` |
| I-7 | `unit/test_degraded.py::test_degraded_path_fails_closed` |
| I-8 | `unit/test_authorization.py::test_no_matching_policy_is_recorded_default_deny` |
| I-9, I-10 | `integration/test_authorize_postgres.py::test_authorize_persists_adr_and_outbox_atomically` (B-8 limits caller-argument recomputation) |
| I-11 | `unit/test_evidence.py::test_checkpointed_parallel_verifier_detects_corruption` + `integration/postgres/schema_contract.sql` |
| I-12 | `unit/test_redaction.py::test_redaction_hashes_stored_payload_and_commits_to_source` |
| I-13 | `unit/test_invariant_properties.py::test_i13_property_valid_enriched_context_is_always_recordable` |
| I-14 | `unit/test_authorization.py::test_i14_volatile_retry_fields_do_not_change_binding_hash` (B-8 limits request shape) |
| I-15 | `unit/test_approval.py::test_stale_epoch_vote_loses_escalation_race` |
| I-16 | `unit/test_invariant_properties.py::test_i16_property_wrong_id_family_is_schema_error` + typed SQL domains |
| I-17 | `unit/test_external_payload.py::test_projects_only_allowlisted_scalars_and_reports_drift` |
| I-18, I-19 | `unit/test_redaction.py` + `integration/test_authorize_postgres.py::test_redacted_audit_write_is_chained_without_raw_pii` |
| I-20 | `integration/postgres/schema_contract.sql` rollback/dense-head assertion |
| I-21, I-26 | `unit/test_degraded.py::test_i21_i26_degraded_allow_requires_all_gates_and_fsynced_receipt` |
| I-22 | `unit/test_approval.py::test_override_requires_fresh_votes_and_justification` |
| I-23, I-25 | `integration/test_authorize_postgres.py::test_authorize_persists_adr_and_outbox_atomically` |
| I-24 | same integration lifecycle; immutable trigger assertions in `schema_contract.sql` |
| V-1 | `unit/test_registry.py::test_v1_policy_author_cannot_be_approver` |
| V-2, V-4 | `unit/test_invariant_properties.py::test_v2_v4_unsatisfiable_epoch_configuration_is_rejected` |
| V-3 | `unit/test_registry.py::test_v3_v4_policy_escalation_and_rejection_semantics_are_explicit` |
| V-5 | `unit/test_approval.py::test_override_requires_fresh_votes_and_justification` |
| V-6 | `unit/test_policy_engine.py::test_applies_to_empty_selector_matches_nothing` |
| V-7, V-9 | authorization enrichment tests + live registry/profile integration |
| V-8 | `unit/test_authorization.py::test_unknown_argument_without_binding_class_is_rejected` + registry profile checks |
| V-10 | delegation test above |
| V-11, V-12 | PostgreSQL rollback test + redaction failure tests |
| V-13, V-17, V-20, V-21 | live execution lifecycle integration + `unit/test_execution.py` |
| V-14 | `unit/test_invariant_properties.py::test_g6_escalation_supersedes_original_epoch_and_stale_votes_fail` |
| V-15 | ADR representability property test and exact JSON Schema validation |
| V-16 | `unit/test_degraded.py::test_caller_supplied_unknown_key_never_establishes_trust` |
| V-18 | hostile gzip/JSON/budget/disposition tests in `unit/test_external_payload.py` |
| V-19 | live DecisionEvent identical-retry assertion in `integration/test_authorize_postgres.py` |

The independently-controlled `review_required` epoch remains B-7; no green test pretends an authority
model exists where the schema supplies none.
