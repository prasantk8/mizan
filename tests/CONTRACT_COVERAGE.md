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
| I-25 | `integration/test_authorize_postgres.py::test_i25_financial_execution_waits_for_immutable_receipt` + `unit/test_mcp_gateway.py::test_an_executor_that_arrives_before_the_publisher_waits_rather_than_refusing` + `unit/test_mcp_gateway.py::test_waiting_for_the_publisher_is_bounded_and_then_the_call_is_refused` |
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
| V-22 | `integration/test_authorize_postgres.py::test_one_operator_cannot_downgrade_a_production_critical_agent` + `integration/test_authorize_postgres.py::test_an_agent_token_cannot_register_a_tool_that_permits_itself` + `integration/test_authorize_postgres.py::test_a_production_critical_agent_cannot_be_created_by_one_operator` + `integration/test_authorize_postgres.py::test_patch_cannot_attach_an_agent_to_a_parent_that_did_not_authorize_it` |
| V-23 | `integration/test_closed_loop_postgres.py::test_an_agent_pauses_for_two_approvers_and_then_executes` |
| V-14 | `unit/test_approval.py::test_stale_epoch_vote_loses_escalation_race` |
| V-15 | `unit/test_authorization.py::test_v15_policy_engine_failure_persists_system_fail_closed_deny` |
| V-16 | `unit/test_degraded.py::test_caller_supplied_unknown_key_never_establishes_trust` |
| V-18 | `unit/test_external_payload.py::test_streaming_gzip_enforces_decompressed_limit_before_parse` |
| V-19 | `integration/test_authorize_postgres.py::test_v19_identical_decision_event_retry_returns_same_event` |
| R-003/B-9 | `unit/test_registry.py::test_ratified_policy_hash_excludes_only_lifecycle_fields` plus live lifecycle transitions preserving the ADR-referenced hash |
| §8.1 / ADR-008 Amd. (executor obligations) | `integration/test_mcp_gateway_postgres.py::test_an_mcp_client_reaches_tools_only_through_a_recorded_decision` + `unit/test_mcp_gateway.py::test_an_authorized_call_whose_capability_is_refused_is_never_performed` + `unit/test_mcp_gateway.py::test_the_documented_example_configuration_is_one_the_gateway_accepts` |
| ADR-009 decision-context replay read | `integration/test_policy_studio_postgres.py::test_policy_studio_replay_returns_exactly_the_seeded_flip_set` |
| ADR-007 `EXPIRED` reached at rest (T-074) | `integration/test_approval_expiry_postgres.py::test_an_elapsed_epoch_is_closed_at_rest_with_its_section_4_event` + `unit/test_drain_worker.py::test_enforced_expiry_closes_an_elapsed_epoch_at_rest` |
| §8 `MIZAN_APPROVAL_EPOCH_EXPIRY` — both modes are real (H-7) | `integration/test_approval_expiry_postgres.py::test_an_advisory_deployment_reports_the_overdue_epoch_and_writes_nothing` + `unit/test_approval.py::test_a_late_vote_is_accepted_when_the_deployment_does_not_expire_epochs` + `unit/test_runtime.py::test_the_approval_expiry_mode_defaults_to_enforced_and_refuses_anything_else` |
| §4 events with subscribers and no receipt are delivered (T-074) | `unit/test_drain_worker.py::test_events_that_never_become_receipts_are_delivered_and_marked_published` + `unit/test_drain_worker.py::test_a_relayed_row_is_marked_published_only_after_the_sink_accepted_it` |
| ADR-004 G.22 `trace_id` is the caller's W3C trace (T-073) | `unit/test_trace_contract.py::test_the_trace_id_recorded_is_the_callers_trace_and_not_a_hash_of_the_request_id` + `unit/test_trace_contract.py::test_the_recorded_span_is_the_span_that_decided_rather_than_null` |
| Cross-tenant metrics never reach the tenant API (T-073) | `unit/test_app_routes.py::test_the_tenant_api_does_not_serve_metrics` + `unit/test_observability.py::test_the_metrics_listener_serves_the_exposition_and_nothing_else` |
| B-18 / ADR-004 G.1 — a KMS backend that boots and never re-signs history (T-102) | `integration/test_vault_transit_live.py::test_the_product_boots_with_a_key_backend_that_is_not_development` + `integration/test_vault_transit_live.py::test_rotating_the_key_in_vault_does_not_change_who_signed_history` |
| A signature that does not verify is never emitted (T-102) | `unit/test_vault_transit.py::test_a_signature_that_does_not_verify_is_refused_rather_than_returned` + `unit/test_vault_transit.py::test_a_signature_from_a_different_key_version_is_refused` |
| §8 `MIZAN_KEY_CUSTODY_MODE` names a backend that exists (B-20) | `unit/test_runtime.py::test_a_custody_mode_that_names_no_built_backend_is_refused_at_startup` + `unit/test_runtime.py::test_production_refuses_to_start_without_a_real_key_backend` |
