#!/usr/bin/env node
// Run both verifiers over the same inputs and report every disagreement.
//
// A disagreement is a defect -- in the spec, or in one of the two
// implementations. It is never something to reconcile by adjusting whichever
// verifier is easier to change. The point of a second implementation is that it
// was written from the specification, so when the two differ, the specification
// is the thing that gets read.
//
// Two corpora:
//   conformance  the six hand-built bundles in tests/fixtures/conformance
//   mutation     the 288 single-byte mutations named in mutation-result.json,
//                which turn a good bundle into 288 near-miss bundles
//   shipped      the bundles under tests/fixtures/evidence_export -- the ones the
//                product actually produces and CI actually verifies
//
// The shipped corpus was added after CI found a bug in verifier-two that the
// other two corpora could not reach: the conformance fixtures happen to use
// timestamp tokens that name their ESSCertIDv2 hash algorithm explicitly, and
// the shipped attested bundle relies on the DEFAULT. A corpus assembled to
// exercise a specification does not automatically exercise the artifacts.
//
// Usage: node verifier-two/tools/differential.mjs [--corpus conformance|mutation|shipped|both|all] [--json]

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const run = promisify(execFile);

const REPO = path.resolve(import.meta.dirname, '../..');
const CONFORMANCE = path.join(REPO, 'tests/fixtures/conformance');
const GOLDEN = path.join(CONFORMANCE, 'valid-unattested');

const REFERENCE = [
  fs.existsSync(path.join(REPO, '.venv/bin/python')) ? path.join(REPO, '.venv/bin/python') : 'python3',
  [path.join(REPO, 'scripts/verify_evidence_export.py')],
];
const SECOND = ['node', [path.join(REPO, 'verifier-two/bin/mizan-verify-two.js')]];

// Section 5 assigns these statuses; both verifiers are compared on the status,
// not on message text, because prose is not the contract.
const VERDICT_BY_STATUS = { 0: 'VALID', 1: 'INVALID', 2: 'CANNOT CHECK', 3: 'MALFORMED', 4: 'EXPIRED' };

async function verifyWith([command, baseArguments], bundleDir, trustRoots, extra = []) {
  const args = [...baseArguments, bundleDir, ...extra];
  for (const root of trustRoots) args.push(...(extra.length ? ['--trust-root', root] : ['--tsa-trust-anchor', root]));
  try {
    const { stdout, stderr } = await run(command, args, { maxBuffer: 32 * 1024 * 1024 });
    return { status: 0, verdict: 'VALID', output: (stdout + stderr).trim() };
  } catch (error) {
    const status = typeof error.code === 'number' ? error.code : -1;
    return {
      status,
      verdict: VERDICT_BY_STATUS[status] ?? `exit ${status}`,
      output: `${error.stdout ?? ''}${error.stderr ?? ''}`.trim(),
    };
  }
}

const reference = (dir, roots) => verifyWith(REFERENCE, dir, roots);
const second = (dir, roots) => verifyWith(SECOND, dir, roots, ['--quiet']);

// --- corpus 1: the conformance bundles ---------------------------------------

async function conformanceCorpus() {
  const cases = JSON.parse(fs.readFileSync(path.join(CONFORMANCE, 'verdicts.json'), 'utf8'));
  const results = [];

  for (const testCase of cases) {
    const dir = path.join(CONFORMANCE, testCase.bundle);
    const roots = testCase.trust_roots.map((relative) => path.resolve(CONFORMANCE, relative));

    for (const [label, suppliedRoots] of [['declared roots', roots], ['no roots', []]]) {
      // Running each bundle both with and without its trust roots is deliberate.
      // The no-roots pass is the one that separates "this bundle is bad" from
      // "you have not told me who you trust", and that is exactly where a
      // verifier is most likely to mislead an auditor.
      if (label === 'no roots' && roots.length === 0) continue;
      const [a, b] = await Promise.all([reference(dir, suppliedRoots), second(dir, suppliedRoots)]);
      results.push({
        corpus: 'conformance',
        name: `${testCase.bundle} (${label})`,
        expected: suppliedRoots.length === roots.length ? testCase.verdict : null,
        reference: a.verdict,
        second: b.verdict,
        referenceOutput: a.output,
        secondOutput: b.output,
      });
    }
  }
  return results;
}

// --- corpus 3: the bundles this product actually ships ------------------------

const SHIPPED = path.join(REPO, 'tests/fixtures/evidence_export');

const SHIPPED_CASES = [
  { bundle: 'golden/bundle', roots: [] },
  { bundle: 'attested/bundle', roots: ['attested/tsa-root.pem'] },
  {
    bundle: 'public-tsa/bundle',
    roots: ['public-tsa/freetsa-root.pem', 'public-tsa/usertrust-rsa-root.pem'],
  },
];

async function shippedCorpus() {
  const results = [];
  for (const testCase of SHIPPED_CASES) {
    const dir = path.join(SHIPPED, testCase.bundle);
    if (!fs.existsSync(dir)) continue;
    const roots = testCase.roots.map((relative) => path.join(SHIPPED, relative));

    for (const [label, suppliedRoots] of [['declared roots', roots], ['no roots', []]]) {
      if (label === 'no roots' && roots.length === 0) continue;
      const [a, b] = await Promise.all([reference(dir, suppliedRoots), second(dir, suppliedRoots)]);
      results.push({
        corpus: 'shipped',
        name: `${testCase.bundle} (${label})`,
        expected: null,
        reference: a.verdict,
        second: b.verdict,
        referenceOutput: a.output,
        secondOutput: b.output,
      });
    }
  }
  return results;
}

// --- corpus 2: single-byte mutations -----------------------------------------

function mutate(bytes, offset, operation) {
  switch (operation) {
    case 'flip':
      { const copy = Buffer.from(bytes); copy[offset] ^= 0x01; return copy; }
    case 'delete':
      return Buffer.concat([bytes.subarray(0, offset), bytes.subarray(offset + 1)]);
    case 'insert-space':
      return Buffer.concat([bytes.subarray(0, offset), Buffer.from([0x20]), bytes.subarray(offset)]);
    default:
      throw new Error(`unknown mutation operation ${operation}`);
  }
}

async function mutationCorpus(concurrency) {
  const spec = JSON.parse(fs.readFileSync(path.join(CONFORMANCE, 'mutation-result.json'), 'utf8'));
  const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'mizan-differential-'));
  const results = [];

  let next = 0;
  const workers = Array.from({ length: concurrency }, async () => {
    for (;;) {
      const index = next++;
      if (index >= spec.cases.length) return;
      const testCase = spec.cases[index];
      const [file, offsetText, operation] = testCase.case.split(':');
      const offset = Number(offsetText);

      const dir = path.join(scratch, String(index));
      fs.mkdirSync(dir);
      for (const name of fs.readdirSync(GOLDEN)) {
        const bytes = fs.readFileSync(path.join(GOLDEN, name));
        fs.writeFileSync(path.join(dir, name), name === file ? mutate(bytes, offset, operation) : bytes);
      }

      const [a, b] = await Promise.all([reference(dir, []), second(dir, [])]);
      results.push({
        corpus: 'mutation',
        name: testCase.case,
        expected: testCase.verdict,
        reference: a.verdict,
        second: b.verdict,
        referenceOutput: a.output,
        secondOutput: b.output,
      });
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  await Promise.all(workers);
  fs.rmSync(scratch, { recursive: true, force: true });
  results.sort((x, y) => x.name.localeCompare(y.name));
  return results;
}

// --- reporting ---------------------------------------------------------------

function main(argv) {
  const wanted = argv.includes('--corpus') ? argv[argv.indexOf('--corpus') + 1] : 'both';
  const asJson = argv.includes('--json');
  const concurrency = Math.max(2, Math.min(8, os.availableParallelism?.() ?? 4));

  return (async () => {
    const results = [];
    const all = wanted === 'both' || wanted === 'all';
    if (wanted === 'conformance' || all) results.push(...(await conformanceCorpus()));
    if (wanted === 'shipped' || all) results.push(...(await shippedCorpus()));
    if (wanted === 'mutation' || all) results.push(...(await mutationCorpus(concurrency)));

    const disagreements = results.filter((r) => r.reference !== r.second);
    const secondWrong = results.filter((r) => r.expected !== null && r.expected !== undefined && r.second !== r.expected);
    const referenceWrong = results.filter((r) => r.expected !== null && r.expected !== undefined && r.reference !== r.expected);

    if (asJson) {
      process.stdout.write(`${JSON.stringify({ results, disagreements }, null, 2)}\n`);
    } else {
      process.stdout.write(`cases:                       ${results.length}\n`);
      process.stdout.write(`verifiers disagree:          ${disagreements.length}\n`);
      process.stdout.write(`reference vs recorded oracle:${String(referenceWrong.length).padStart(4)}\n`);
      process.stdout.write(`verifier-two vs oracle:      ${String(secondWrong.length).padStart(4)}\n`);

      for (const [title, rows] of [
        ['DISAGREEMENTS', disagreements],
        ['verifier-two differs from the recorded oracle', secondWrong],
        ['reference differs from the recorded oracle', referenceWrong],
      ]) {
        if (rows.length === 0) continue;
        process.stdout.write(`\n${title}:\n`);
        for (const row of rows) {
          process.stdout.write(
            `  ${row.name}\n    expected=${row.expected ?? '-'}  reference=${row.reference}  verifier-two=${row.second}\n`,
          );
          process.stdout.write(`    reference: ${firstLine(row.referenceOutput)}\n`);
          process.stdout.write(`    second:    ${firstLine(row.secondOutput)}\n`);
        }
      }
    }

    process.exitCode = disagreements.length === 0 && secondWrong.length === 0 ? 0 : 1;
  })();
}

function firstLine(text) {
  const line = (text ?? '').split('\n').find((candidate) => candidate.trim().length > 0) ?? '';
  return line.length > 160 ? `${line.slice(0, 157)}...` : line;
}

await main(process.argv.slice(2));
