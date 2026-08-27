# CODEX work order — CP-F

**Read first:** `docs/handoff/CP-F-STAGE-PLAN.md`, then `docs/handoff/PR-PROTOCOL.md`.
Standing rules 6-12 and `CODEX-STAGE-3.md` §2 non-negotiables 1-9 apply unchanged. H-1 claim before
work. H-2's completion report is the PR body. One task, one branch, one PR opened on day one.

The framing from your CP-E order stands: you are not the UI engineer, and the split is by what the
work needs. What changed is that the hardest cryptographic tasks — T-038 and T-039 — are **deferred to
CP-G**, and not for lack of confidence in you. You cannot add a field to a format that has three
incompatible definitions of itself. Reconciling that (T-110) is yours, and the proofs follow it.

---

## T-062 — the independent second verifier. **Still first. Still sealed. Fresh session.**

Nothing in CP-F weakens the seal. Start here, before you read another line of `control-plane/`.

`verifier-two/` exists in the working tree as **eleven untracked files** — `package.json`,
`bin/mizan-verify-two.js`, `lib/{jcs,oid,der,codec,verify,verdict,rfc3161,ed25519}.js`,
`test/jcs.test.js`. Around three thousand lines. **The highest-value artifact in this repository is
sitting uncommitted, on one machine, and `git ls-files` cannot see it.**

Land it as a PR before you touch anything else, in whatever state it is in. A draft PR with a failing
test is infinitely more durable than finished work in an untracked directory, and if that machine dies
tonight the sealed property is unrecoverable without a third party.

Rules unchanged: the implementer may not have read `verify_evidence_export.py` or `evidence.py`;
CLAUDE is permanently disqualified; write from `docs/spec/EVIDENCE-BUNDLE-FORMAT.md` alone; if you need
a constant it comes from the spec, or the spec is incomplete and that finding is worth more than the
constant. Run both verifiers over `tests/fixtures/conformance/`. **Every disagreement is a defect** in
the spec or in one implementation and must be named, classified and fixed. A disagreement quietly
reconciled by patching the new verifier to match the Python defeats the exercise and I will look for
that specifically.

Expect the spec to be wrong in at least two places. Canonicalisation and the core-projection exclusion
set are where I would look first.

## T-098 — Every declared console script starts from an installation

```
$ .venv/bin/mizan-mcp-gateway --help
ModuleNotFoundError: No module named 'mizan_mcp_gateway'
```

The MCP Governance Gateway is Track B's declared **headline** — the thing that wraps any MCP server,
is the ADR-008 executor, and is on the stranger's path at CP-F step 2. It runs only under pytest, where
the source tree happens to be on `sys.path`. Installed, it does not start.

This is the same defect as everything else in this stage: it works where its author is standing and
nowhere else. Fix the packaging, then gate it — **CI installs the wheel into a clean environment and
runs `--help` on every `[project.scripts]` entry.** Rule 9: the gate must reject today's tree.

Do this before T-099, because T-099 adds a sixth console script and there is no point adding one to a
packaging configuration that does not deliver the five it already declares.

## T-099 — `mizan-drain-outbox` exists, and stops being optional

**This is the task that makes the product work at all, and it is yours.**

Five console scripts in `pyproject.toml:18-23`. `mizan-drain-outbox` is not among them. It is the
entrypoint at `compose.production.yaml:83` and `charts/mizan/templates/drainer-deployment.yaml:30`.
**It does not exist.**

Trace what follows, because it is worse than a missing worker. Nothing drains, so
`mizan.evidence_receipts` is never written — the only writer is `evidence.py:875` `record_publication`,
reachable only from `OutboxPublisher.drain` at `evidence.py:847`, and every caller of that today is a
test or a benchmark. `execution.py:410-411` requires a receipt for `financial_write`.
`execution.py:812-820` raises 403 `immutable_receipt_missing`.

**So Mizan pauses the payment for a human, the human approves it, and Mizan refuses it anyway,
permanently.** And no receipts means no anchors, no anchors means no RFC 3161 timestamps, and
`mizan-export-evidence` then raises "cannot export an empty evidence range" — **there is no bundle for
your second verifier to check.** T-062's artifact cannot be produced by a running system.

Ship T-074's worker as the console script the manifests already name: drain cadence, anchor cadence,
backpressure, poison handling, lag SLO against `MIZAN_EVIDENCE_MAX_UNPUBLISHED_SECONDS`, signals.

And move the service out of `profiles: ["drainer"]` into `production`. Every other service in that
file is `profiles: ["production"]`. A component without which every high-risk financial write is
refused is not an optional profile — shipping it as one is how it stayed invisible.

Rule 8: the pre-fix demonstration is the 403, quoted verbatim.

## T-100 — The packaging gate resolves what the manifests launch

`tests/unit/test_packaging.py:70-97`, `test_production_packaging_contract_is_complete`, reads
Dockerfile, compose, `values.yaml`, the migration job and `ci.yml` **as text** and asserts substrings.
Including this one:

```python
assert 'profiles: ["drainer"]' in compose
```

That assertion passes today. It asserts the presence of the service that points at the binary that
does not exist. **The gate named "the production packaging contract is complete" is the reason nobody
noticed the production packaging contract is broken.** No `helm lint` or `helm template` runs anywhere
in this repository.

Third instance of the documented failure mode, after R-008 F-2 (an assertion that cannot fail) and F-3
(a fault injected into the harness) — and the most expensive of the three, because it guards the
artifact a customer installs.

Replace it: `helm lint`, `helm template` into rendered manifests, assertions against the rendered
objects, entrypoint resolution from T-098. Credit where due — the digest-pinned base *and*
digest-pinned syft and trivy are genuinely first-rate, and none of it is what this gate fails to check.

## T-102 — One key backend that boots. **[B-18 stamped: Vault Transit]**

T-076's delivery, and the single dependency the whole deployment lane sits behind.

`KmsHsmKeyProvider` exists at `keys.py:129` with no backend anywhere. Meanwhile in development mode
`keys.py:76` derives every signing key as `Ed25519PrivateKey.from_private_bytes(sha256(key_id))` — and
the `key_id` ships in every bundle manifest. Every development-signed bundle is forgeable by anyone who
reads it. That is TM-001 R-4, it is why the repository is private, and it is why B-22 option (b) is
blocked until T-065.

HashiCorp Vault Transit, native Ed25519, `custody=kms`. **Integration-tested against a real Vault in
CI, not a mock.** A mocked key backend in a stage whose thesis is "the gate must reproduce the result"
would be self-refuting; I would rather the job be slow. PKCS#11 is not in CP-F, and AWS/GCP/Azure stay
rejected — none sign Ed25519, and choosing one reopens bundle format 1.0.

CLAUDE's T-101 makes the two startup guards agree that `kms` boots. Yours makes `kms` mean something.
Neither is done until `MIZAN_ENV=production` reaches a listening socket.

## T-104 — Evidence survives a pod, and the drainer can write it. **[B-21: object store + Object Lock]**

```yaml
# charts/mizan/templates/deployment.yaml:84-85
- name: evidence
  emptyDir: {}          # mounted at /app/var/evidence, with values.yaml:6 replicaCount: 2
```

No PVC, no StatefulSet, anywhere in the chart. Export reads the same local path
(`evidence_export.py:60`), so **a bundle served by pod A cannot read segments written by pod B**, and a
rollout destroys the corpus. The evidence plane — the entire product thesis — is on ephemeral storage
behind a load balancer.

And the drainer pod receives only `MIZAN_ENV` and `MIZAN_DATABASE_URL` under
`readOnlyRootFilesystem: true` (`drainer-deployment.yaml:31-41`) — no evidence mount, no key
references, no TLS. Even once the binary exists it cannot do its job.

B-21 is stamped as **S3-compatible object storage with Object Lock**, because that is what
`MIZAN_AUDIT_ANCHOR_BUCKET` was specified as in SPEC §8 (marked *required*, read nowhere) and what
`evidence.py:361`'s embedded `"retention_class": "regulatory_7y"` already claims to a reader of our
records. Prove it, do not configure it: written through replica A, exported and verified through
replica B, surviving deletion of both pods.

Chart completeness rides here — ServiceAccount, NetworkPolicy, PodDisruptionBudget, real `resources`
(`values.yaml:35` is `{}`), probes on the drainer — gated by T-100's `helm template` assertions so it
cannot silently regress.

## T-108 — Expiry happens at rest

`"EXPIRED"` appears only inside membership sets — `approval.py:11 TERMINAL_STATES`,
`sdk/python/mizan/client.py:29` — never in a write, though it is legal in the schema at
`0001_domain_schema.sql:210`. `LEASE_EXPIRED` is written only at `execution.py:566-582`, inside
`_transition_lease`, reached only by an inbound call **from the lease's own holder**. A crashed
executor's lease never expires; an approval whose SLA passes stays pending forever.

The cause is structural: **there is no background task of any kind in this process.** Zero hits for
`sweep`, `sweeper`, `scheduler`, `cron`, `periodic`, `asyncio.create_task`, `threading.Thread`.

Ship the outbox-transactional sweeper with its §4 events. Test at rest, not in-band: kill the holder,
advance the clock, assert the state. Rule 11 — if the test can pass by calling an endpoint, it is
testing the wrong thing.

## T-110 — One bundle grammar. **This is why the proofs are deferred.**

Three refs define bundle 1.0 three incompatible ways:

```
$ git show <ref>:docs/spec/EVIDENCE-BUNDLE-FORMAT.md | grep -c custody
main 0    track-b/ui 2    t-091-tsa-lifetime 0
```

`track-b/ui` requires `custody` on every key document; the others do not mention it. This is what
happens when a normative spec is edited on two branches that never merge, and it is the reason T-038
and T-039 wait: **you cannot add an inclusion-proof field to a format that has three definitions of
itself.**

After the merge train, reconcile to one normative grammar and one conformance corpus, by ADR delta
(H-3 fires). Then T-111 makes it enforceable.

## T-111 — Both verifiers gate the corpus

Once `verifier-two/` is tracked and the grammar is one thing, run **both** verifiers over
`tests/fixtures/conformance/` in CI and fail on any disagreement in verdict, assurance line, or NOT
COVERED list.

This is the difference between "verify it yourself" as a claim and as a fact, and it is the only gate
in this repository that a second implementation can enforce. Rule 12 at product scale.

## T-097, T-109, T-113, T-114 — the parts that make it someone else's product

**T-097 — `WORK_LOG.md` stops serializing every merge.** PR-PROTOCOL §7 calls it correct that this is
the most frequently conflicting file. It is not. With one PR per task it makes every pair of concurrent
tasks conflict on a file neither task is about, which is a tax on exactly the parallelism the protocol
exists to enable. Split the queue into per-task fragments with a generated index, or install a union
merge driver. Pick one and say why in the PR.

**T-109 — config reconciliation, and a refusal.** Supersedes T-080, whose premise is wrong in both
directions. SPEC §8 carries **57** unique keys, not 48; **21** are never read, not 30 — including
`MIZAN_AUDIT_ANCHOR_BUCKET`, all five `MIZAN_DEGRADED_WAL_*`, `MIZAN_EXECUTION_TOKEN_KEYSET_REF`,
`MIZAN_APPROVAL_LEASE_SECONDS` and `MIZAN_DLP_FAIL_MODE`. Conversely **16** keys used in shipped
artifacts are unregistered, including all three `MIZAN_HEALTH_*`. The failure that matters is not the
count: `config.py:47-153` never inspects the environment for unknown `MIZAN_*` names, so **an operator
who sets a control we do not read gets silence** — they believe DLP fails closed, and it does not. Read
or dated-waive each key, then refuse to start on an unknown `MIZAN_*`. Settle B-20's vocabulary: SPEC
§8 `kms_hsm`, `keys.py:13` `Literal["development-derived","kms","hsm"]`, `compose.production.yaml:7`
`kms`.

**T-113 — backup, restore, retention. Currently zero.** A repository-wide search for
`retention|backup|restore|disaster|recovery|pg_dump|PITR|object.lock|s3` returns **three** hits, all
cosmetic: a docstring at `evidence.py:67` reading "Development WORM analogue", the literal
`"retention_class": "regulatory_7y"` at `evidence.py:361`, and one more at `evidence.py:1289`. We emit
a seven-year regulatory retention claim inside signed records and have no backup, no restore, no
retention enforcement and no runbook. `docs/deployment/` contains one file, `mtls.md`. This is the
finding a bank's control questionnaire opens with. Ship the runbook **and the drill**: destroy the
database and the evidence store, restore both, export from the restored copy, and have the second
verifier PASS it. Rule 9 — the guarantee is the artifact, not the procedure.

**T-114 — a stranger can produce credentials and knows what to type.**
`compose.production.yaml:72` mounts `${MIZAN_TLS_DIRECTORY:-./secrets/tls}` and lines 14-23 consume
seven PEMs. `ls secrets` — no such directory. The only X.509 builders in the tree live inside
`tests/unit/test_mtls.py` and `tests/integration/test_closed_loop_postgres.py`, never as a reusable
operator script. No `.env.example` despite seven required variables. The chart assumes Secrets
`mizan-runtime` and `mizan-tls` (`values.yaml:11-16`) documented nowhere. And `README.md:34` still
says *"No service runtime has been selected by this scaffold."* Ship
`scripts/bootstrap_credentials.sh`, `.env.example`, `INSTALL.md`, a customer quickstart README, and
runnable code in `examples/`. You will also write T-063, so treat T-114 as its first half — the person
who wrote the system is the worst judge of what a stranger already knows, and this is where that hurts
most.

## Carried from CP-E, into Wave 4

**T-084** — F-2 (the prompt-injection test whose policy set contains no ALLOW rule, so no injection can
change the outcome), F-3 (the fault switch that substitutes `_AcceptEverythingVerifier` in the harness
rather than reverting a guard in the product), F-5 (thirteen suppressions all expiring **2026-09-03**,
validated inside `make check`, so on 2026-09-04 every developer on every branch fails). **Note the
date: F-5 becomes real in six days.** If the merge train is still running on 2026-09-01, move T-084
ahead of everything except T-062.

**T-085** — 674 lines of `ui/app.js` that no JavaScript runtime has ever loaded. **T-071** — the demo,
jointly with CLAUDE; per B-23 the gate replays a committed transcript of real `tool_use` blocks and
`MODEL=live` re-records it, so the model work stays and the gate stops requiring an API key the
stranger does not have. **T-063** — the auditor's first hour.

---

## Sequence

```
T-062  land verifier-two as a PR         ← fresh session, sealed, hour one, before anything
  → T-098  console scripts install       ← the headline gateway does not start today
  → T-099  mizan-drain-outbox, and not optional
  → T-102  Vault Transit, real Vault in CI      [B-18]
  → T-100  helm lint / helm template packaging gate
  → T-097  WORK_LOG stops serializing merges
  → T-104  durable evidence + chart completeness [B-21]
  → T-108  expiry sweeper
  → T-110  one bundle grammar  →  T-111  both verifiers gate the corpus
  → T-109  config refusal  ·  T-114  bootstrap + INSTALL  ·  T-113  the restore drill
  → Wave 4: T-084 → T-085 → T-071 → T-063
```

T-062 does not wait for the merge train — it needs only the spec and the fixtures. Everything after it
starts from a green `main`.

Full gates before every PR: `ruff check .`, `make check`, `pytest` with PostgreSQL, and the JS suite
once it exists. A previously-green test going red is a stop-and-report, not a thing to fix quietly in
the same branch.

## Escalate, do not decide

H-7 fires on money movement, approval semantics, crypto, key management and tenant isolation. Live in
this order: any change to the `KeyProvider` **contract** in T-102 rather than an addition to it; T-110
if reconciling the grammar would **widen** rather than narrow what a bundle may claim; and anything in
T-104 or T-113 that changes what `retention_class: regulatory_7y` means to a reader of a record we have
already signed.

Park freely. Refusing to start on a bad base has been the right call every time and has cost nothing.

## Review duty

You review CLAUDE's PRs. Find the vacuous assertion, the fault that lives in the harness, and the new
field inside a signed payload that claims more than it can support. "LGTM" is not a review; a review
that finds nothing says what it looked for.

One question earns its keep in this stage above all others, and `test_packaging.py` is why:
**does this gate reproduce the result, or does it read a file and look for a string?**

One process note, now mechanized rather than requested: your commit bodies carried no pre-fix SHA and
no what-did-not-work. PR-PROTOCOL §3 turns both into CI-checked PR fields and the `completion-report`
job already passes on PR #1 — so this stops being a matter of remembering. Rule 10 is the part that
earns its keep: the eight defects disclosed by two commits that no order named are why the crypto
contract work is in this queue at all.
