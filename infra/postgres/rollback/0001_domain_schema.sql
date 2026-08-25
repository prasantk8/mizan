BEGIN;

DROP SCHEMA IF EXISTS mizan CASCADE;

DO $$ BEGIN
  DROP ROLE IF EXISTS mizan_app;
EXCEPTION WHEN dependent_objects_still_exist THEN
  RAISE EXCEPTION 'mizan_app still owns objects or privileges outside the mizan schema';
END $$;

COMMIT;
