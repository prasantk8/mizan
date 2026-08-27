# mizan-verify-two — an independent second verifier

A second, from-scratch implementation of the Mizan evidence bundle verifier, written in JavaScript
from `docs/spec/EVIDENCE-BUNDLE-FORMAT.md` and the conformance fixtures alone.

**Read [FINDINGS.md](FINDINGS.md) first.** The verifier is the instrument; the findings are the
result. Four implementation disagreements and nine specification gaps came out of building it, two are
still open against the reference, and one of them found a bug in this verifier.

## Why a second verifier exists

A single verifier cannot tell you whether it implements the specification or whether the
specification merely describes it. Every ambiguity resolves silently in favour of whatever the one
implementation happens to do, and the spec drifts into being a prose transcript of the code. The
only way to find out is to have someone who has not read the code write the thing again from the
document, and then diff the verdicts.

That is why this was written under a seal: this session opened the spec and the fixtures and
**nothing** under `control-plane/` or `scripts/verify_*`. Where a constant was needed it was
derived from the spec at the point of use, in a comment — the RFC 8410 SPKI prefix for Ed25519 keys
is written out from the ASN.1 rather than pasted, for example. Git history shows this directory
authored before any reference source was opened, which is the only durable evidence that the seal
held.

Every disagreement was treated as a defect to be located and named, in the spec or in one
implementation. None was closed by adjusting this verifier until it agreed with the incumbent; see
FINDINGS.md D-2 for the one that took the most work to resolve honestly.

## Why JavaScript, and why zero dependencies

**A different language was the requirement**, because a second implementation in the same language
tends to reproduce the first one's assumptions about numbers, string ordering and encoding. Those
are exactly where a canonicalisation spec can be wrong. JavaScript is a useful choice
specifically here: RFC 8785 defines number serialisation as ECMAScript `Number::toString` and key
ordering as UTF-16 code-unit order, so `lib/jcs.js` is deliberately thin — it delegates both to the
language that *defines* them, which makes it a genuinely independent check on a Python
implementation that has to reconstruct both by hand.

**Zero dependencies** — `dependencies` and `devDependencies` are both empty, and the test runner is
`node --test` — because of who is meant to run this. An auditor with a Node runtime and a copy of
the bundle can verify it. No package manager, no lockfile to trust, no network fetch, nothing in
the supply chain between the spec and the verdict. A verifier that needs `npm install` to check
whether evidence was tampered with has quietly added everyone in its dependency tree to the set of
parties the auditor must trust.

Requires Node 20 or newer.

## Use

```
node bin/mizan-verify-two.js <bundle-dir> [--trust-root <pem>]... [--json] [--quiet]
```

Trust roots come from you, never from the bundle (spec §4). Exit status is the verdict:

| exit | verdict      | meaning                                                            |
|------|--------------|--------------------------------------------------------------------|
| 0    | VALID        | every required check passed                                          |
| 1    | INVALID      | well-formed, but an evidence check failed                            |
| 2    | CANNOT CHECK | structurally eligible; this environment cannot evaluate a claim      |
| 3    | MALFORMED    | not a bundle 1.0 document                                            |
| 64   | —            | usage error                                                          |

A clean verdict always prints what it does **not** prove (spec §6) at the same prominence as the
verdict itself.

## Layout

```
bin/mizan-verify-two.js   CLI
lib/jcs.js                RFC 8785 canonicalization
lib/codec.js              strict Base64 and hex digests
lib/der.js                strict DER reader (definite length, minimal, no trailing bytes)
lib/oid.js                object identifiers, and which ones this verifier supports
lib/ed25519.js            raw 32-byte keys wrapped into an RFC 8410 SPKI
lib/rfc3161.js            timestamp tokens, chain building, EKU policy
lib/verdict.js            the four verdicts and their precedence
lib/verify.js             the bundle checks
tools/differential.mjs    both verifiers over all three corpora
tools/fault-injection.mjs breaks lib/ on purpose to prove the suite can go red
```

## Checking it

```
npm test                          # 66 tests
npm run differential              # both verifiers, 300 cases
npm run fault-injection           # 13 faults, all must go red
```

`differential.mjs` compares **exit status only**. Prose is not the contract; two verifiers are
entitled to phrase the same finding differently and are not entitled to disagree about the verdict.

`fault-injection.mjs` reverts thirteen real guards in `lib/` — one at a time, restoring in a
`finally` — and requires the suite to go red for each, naming the test that caught it. Every fault
is a regression in product code, not a stub in the harness: a fault injected into a test double
proves only that a test asserting X fails when nothing does X, which was never in doubt. A fault
whose anchor text has moved is reported `STALE` and counted as a survivor, because a fault that no
longer applies has silently stopped proving anything.

Both tools exit non-zero on any disagreement or survivor, so both are CI-shaped.
