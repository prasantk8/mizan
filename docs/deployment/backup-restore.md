# PostgreSQL and evidence-store backup/restore

Mizan continuity is a paired recovery. PostgreSQL holds indices, receipts, anchors and key
references; the Object Lock bucket holds the authoritative evidence objects. Restoring only one
side must fail reconciliation and is not recovery.

## Production procedure

1. Record the recovery point, deployed image digest, migration set, Vault key references and S3
   bucket/versioning inventory. Preserve the Vault key versions that signed the retained evidence.
2. Take a PostgreSQL physical/PITR backup or `pg_dump --format=custom` under the database operator's
   established backup control. Encrypt and custody it outside the database failure domain.
3. Replicate Object Lock versions into a separately administered bucket with Object Lock enabled
   and COMPLIANCE retention at least as long as the source objects. Do not interpret a successful
   `CopyObject` as proof; inventory and hash every restored body.
4. Restore into a fresh database and a fresh bucket. Apply no new migrations until the restored
   release has passed its own readiness and evidence reconciliation checks.
5. Export an evidence range from the restored database and restored objects. Run
   `scripts/verify_evidence_export.py` and `verifier-two/bin/mizan-verify-two.js` offline with the
   operator's TSA trust roots. Both must return the same clean verdict.
6. Record the recovery point, object/record/anchor counts, verifier outputs, exceptions and owners.

Never delete a production bucket to rehearse failure: COMPLIANCE mode exists precisely to prevent
that. The drill restores to fresh targets and then proves the restored pair independently.

## Executable CI drill

The nightly `continuity` workflow starts isolated PostgreSQL and MinIO services and runs:

```sh
MIZAN_CONTINUITY_DRILL_EPHEMERAL=true \
MIZAN_S3_ACCESS_KEY_ID=mizan-drill-access \
MIZAN_S3_SECRET_ACCESS_KEY=mizan-drill-secret \
uv run --frozen python scripts/backup_restore_drill.py \
  --admin-database-url postgresql://postgres:password@127.0.0.1:5432/postgres \
  --s3-endpoint-url http://127.0.0.1:9000 \
  --report var/continuity/backup-restore-report.json
```

When the isolated host has Docker but no PostgreSQL client package, pass
`--postgres-tools-container <the-disposable-postgres-container>`; the drill streams the custom
dump through that container's version-matched `pg_dump` and `pg_restore` binaries.

The safety flag and reserved `mizan_restore_drill_*` database names are mandatory. The script
creates source evidence, backs up both stores, restores into fresh targets, exports from only the
restored pair, and requires both verifiers to emit `VALID`. The JSON report is uploaded by CI.
