BEGIN;

ALTER TABLE mizan.evidence_anchors
  ADD COLUMN prev_anchor_hash mizan.sha256_hex,
  ADD COLUMN anchor_number bigint CHECK (anchor_number >= 0),
  ADD COLUMN covered_record_count bigint CHECK (covered_record_count > 0);

ALTER TABLE mizan.evidence_anchors
  ADD CONSTRAINT evidence_anchor_chain_fields_together CHECK (
    (prev_anchor_hash IS NULL AND anchor_number IS NULL AND covered_record_count IS NULL)
    OR
    (prev_anchor_hash IS NOT NULL AND anchor_number IS NOT NULL AND covered_record_count IS NOT NULL)
  ),
  ADD CONSTRAINT evidence_anchor_declared_density CHECK (
    covered_record_count IS NULL OR covered_record_count = to_sequence - from_sequence + 1
  );

CREATE UNIQUE INDEX evidence_anchors_dense_number
  ON mizan.evidence_anchors(tenant_id, stream_id, anchor_number)
  WHERE anchor_number IS NOT NULL;

COMMIT;
