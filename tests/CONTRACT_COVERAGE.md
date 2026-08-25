# SPEC v1.3 Contract Coverage

This is the executable-suite index. A row is not considered covered merely because it appears here;
the referenced test must be collected by pytest and assert the named behavior. PostgreSQL rows run in
`make test-postgres`. Ratified R-003 closes former blockers B-7/B-8/B-9 with executable review,
argument-revalidation, and semantic-policy-hash coverage.

| Contract | Primary executable evidence |
|---|---|
| I-1 | `integration/test_authorize_postgres.py::test_i1_authorization_commits_one_adr_and_outbox` |
| I-2 | `unit/test_invariant_properties.py::test_i2_property_hash_chain_is_contiguous` |
| I-3 | `unit/test_authorization.py::test_tenant_is_derived_from_identity` |
| I-4, I-5 | `unit/test_authorization.py::test_delegation_requires_registered_edge_depth_and_parent_tool_permission` |
| I-6 | `unit/test_invariant_properties.py::test_i6_i15_approval_state_machine_fuzzer` |
| I-7 | `unit/test_degraded.py::test_degraded_path_fails_closed` |
| I-8 | `unit/test_authorization.py::test_i8_risk_engine_failure_persists_system_fail_closed_deny` |
| I-9 | `integration/test_authorize_postgres.py::test_i9_bound_argument_change_is_rejected_at_redemption` |
| I-10 | `integration/test_authorize_postgres.py::test_i10_redeemed_capability_cannot_create_a_second_lease` |
| I-11 | `unit/test_evidence.py::test_checkpointed_parallel_verifier_detects_corruption` + `integration/postgres/schema_contract.sql` |
| I-12 | `unit/test_redaction.py::test_redaction_hashes_stored_payload_and_commits_to_source` |
| I-13 | `unit/test_invariant_properties.py::test_i13_property_valid_enriched_context_is_always_recordable` |
| I-14 | `unit/test_authorization.py::test_i14_volatile_retry_fields_do_not_change_binding_hash` |
| I-15 | `unit/test_approval.py::test_stale_epoch_vote_loses_escalation_race` |
| I-16 | `unit/test_invariant_properties.py::test_i16_property_wrong_id_family_is_schema_error` |
| I-17 | `unit/test_external_payload.py::test_projects_only_allowlisted_scalars_and_reports_drift` |
| I-18 | `unit/test_redaction.py::test_array_drops_are_applied_in_numeric_descending_order` |
| I-19 | `unit/test_redaction.py::test_scan_failure_rejects_write` |
| I-20 | `unit/test_authorization.py::test_i13_in_memory_repository_assigns_persisted_chain_fields` |
| I-21, I-26 | `unit/test_degraded.py::test_i21_i26_degraded_allow_requires_all_gates_and_fsynced_receipt` |
| I-22 | `unit/test_approval.py::test_override_requires_fresh_votes_and_justification` |
| I-23 | `integration/test_authorize_postgres.py::test_i23_second_registered_executor_redeems_its_own_token` |
| I-25 | `integration/test_authorize_postgres.py::test_i25_financial_execution_waits_for_immutable_receipt` |
| I-24 | `unit/test_evidence.py::test_receipt_signatures_detect_mutation` |
| V-1 | `unit/test_registry.py::test_v1_policy_author_cannot_be_approver` |
| V-2, V-4 | `unit/test_invariant_properties.py::test_v2_v4_unsatisfiable_epoch_configuration_is_rejected` |
| V-3 | `unit/test_registry.py::test_v3_v4_policy_escalation_and_rejection_semantics_are_explicit` |
| V-5 | `unit/test_approval.py::test_override_requires_fresh_votes_and_justification` |
| V-6 | `unit/test_policy_engine.py::test_applies_to_empty_selector_matches_nothing` |
| V-7, V-9 | `unit/test_authorization.py::test_no_matching_policy_is_recorded_default_deny` |
| V-8 | `unit/test_authorization.py::test_unknown_argument_without_binding_class_is_rejected` |
| V-10 | `unit/test_authorization.py::test_delegation_requires_registered_edge_depth_and_parent_tool_permission` |
| V-11, V-12 | `unit/test_invariant_properties.py::test_i2_property_hash_chain_is_contiguous` |
| V-13, V-17, V-20, V-21 | `unit/test_execution.py::test_second_registered_executor_is_selected_and_outsider_fails_both_boundaries` |
| V-14 | `unit/test_approval.py::test_stale_epoch_vote_loses_escalation_race` |
| V-15 | `unit/test_authorization.py::test_v15_policy_engine_failure_persists_system_fail_closed_deny` |
| V-16 | `unit/test_degraded.py::test_caller_supplied_unknown_key_never_establishes_trust` |
| V-18 | `unit/test_external_payload.py::test_streaming_gzip_enforces_decompressed_limit_before_parse` |
| V-19 | `integration/test_authorize_postgres.py::test_v19_identical_decision_event_retry_returns_same_event` |
| R-003/B-9 | `unit/test_registry.py::test_ratified_policy_hash_excludes_only_lifecycle_fields` plus live lifecycle transitions preserving the ADR-referenced hash |
