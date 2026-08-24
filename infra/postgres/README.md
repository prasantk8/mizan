# PostgreSQL storage

Migrations are applied in lexical order. The application role is `mizan_app`; request middleware must begin a transaction and execute:

```sql
SELECT set_config('app.tenant_id', '<validated token tenant_id>', true);
```

The third argument is deliberately `true`, limiting tenancy to the current transaction. The application role does not own tables and cannot bypass forced RLS.

Canonical SPEC documents are stored in `document jsonb`. Security-critical identifiers, lifecycle fields, foreign keys, hashes, and sequence numbers are also extracted into typed columns so the database—not naming convention in application code—enforces I-3, I-16, and I-20.

