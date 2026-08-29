BEGIN;

-- A drain worker that cannot set a row aside has two options when a row will never publish:
-- retry it forever, or skip it silently. The first blocks every later row in the stream; the
-- second is this repository's documented failure mode -- a result nobody can reproduce. Neither
-- is acceptable for the queue whose emptiness makes `execution.py` refuse every financial write,
-- so a poisoned row is set aside explicitly, with the reason it was set aside and the time.
--
-- `attempts` already exists and already counts, but only on the success path
-- (`record_publication` increments it in the same statement that sets `published_at`), so it has
-- never recorded a failure. `failed_at` is what makes the retry budget observable.

ALTER TABLE mizan.outbox ADD COLUMN quarantined_at timestamptz;
ALTER TABLE mizan.outbox ADD COLUMN failed_at timestamptz;
ALTER TABLE mizan.outbox ADD COLUMN last_error text;

-- A quarantined row is not a published row. Keeping the two states distinct is what lets the lag
-- SLO stay honest: quarantined rows are excluded from the drain queue but remain visible, and
-- `published_at` continues to mean exactly one thing.
ALTER TABLE mizan.outbox ADD CONSTRAINT outbox_quarantine_is_not_publication
  CHECK (quarantined_at IS NULL OR published_at IS NULL);

-- The drain queue is read on every cycle and is almost always short, while the table it lives in
-- grows without bound. Partial, so the index stays the size of the backlog rather than the size
-- of history.
CREATE INDEX outbox_drain_queue ON mizan.outbox (tenant_id, outbox_id)
  WHERE published_at IS NULL AND quarantined_at IS NULL;

COMMIT;
