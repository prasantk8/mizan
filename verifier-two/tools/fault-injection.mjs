#!/usr/bin/env node
// Prove the test suite can fail, by breaking the verifier on purpose.
//
// Every fault below is a regression in lib/ -- product code -- not a stub swapped
// into the harness. A fault injected into a test double demonstrates only that a
// test asserting X fails when nothing does X, which was never in doubt. The
// question worth answering is whether reverting a real guard turns the suite red,
// and each entry here reverts exactly the guard the named test exists to prove.
//
// Usage: node verifier-two/tools/fault-injection.mjs [--list]

import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';

const ROOT = path.resolve(import.meta.dirname, '..');

const FAULTS = [
  {
    name: 'core-digest-drops-a-member',
    proves: 'the anchor core projection is a closed exclusion set',
    file: 'lib/verify.js',
    find: '  delete core.object_version;\n  return sha256Hex(jcs(core));',
    replace: '  delete core.object_version;\n  delete core.anchored_at;\n  return sha256Hex(jcs(core));',
  },
  {
    name: 'sidecar-may-extend-the-roster',
    proves: 'a sidecar overlays a rostered identity and never adds one',
    file: 'lib/verify.js',
    find: "    if (!identities.has(identity)) {\n      report.malformed(",
    replace: "    if (false) {\n      report.malformed(",
  },
  {
    name: 'failed-status-accepted-in-sidecar',
    proves: 'status "failed" is reserved and forbidden anywhere in a 1.0 bundle',
    file: 'lib/verify.js',
    find: "  if (status === 'failed') {\n    report.malformed(\n      `${where} uses status \"failed\", which section 4 reserves and forbids anywhere in a 1.0 bundle; ` +",
    replace: "  if (false) {\n    report.malformed(\n      `${where} uses status \"failed\", which section 4 reserves and forbids anywhere in a 1.0 bundle; ` +",
  },
  {
    name: 'receipt-signatures-not-checked',
    proves: 'receipt signatures are verified rather than assumed',
    file: 'lib/verify.js',
    find: '    if (!ed25519Verify(key.publicKey, jcs(payload), signature)) {',
    replace: '    if (false) {',
  },
  {
    name: 'anchor-signatures-not-checked',
    proves: 'anchor signatures are verified rather than assumed',
    file: 'lib/verify.js',
    find: '  if (!ed25519Verify(key.publicKey, jcs(anchor.payload), signature)) {',
    replace: '  if (false) {',
  },
  {
    name: 'assurance-claim-not-compared',
    proves: 'the manifest assurance claim is derived, not believed',
    file: 'lib/verify.js',
    find: '  if (jcs(claimed).toString() !== jcs(expected).toString()) {',
    replace: '  if (false) {',
  },
  {
    name: 'digests-checked-after-schema',
    proves: 'the phase order of FINDINGS.md D-2',
    file: 'lib/verify.js',
    find: '  checkFileDigests(bundle, report);\n  if (report.has(VERDICT.INVALID)) {\n    warnOnDevelopmentCustody(bundle, report);\n    return report;\n  }\n\n  // Phase 4 -- the rest of the 1.0 grammar, now over bytes the manifest vouches for.\n  checkStructuralGrammar(bundle, report);\n  if (report.has(VERDICT.MALFORMED)) return report;',
    replace: '  checkStructuralGrammar(bundle, report);\n  if (report.has(VERDICT.MALFORMED)) return report;\n\n  checkFileDigests(bundle, report);\n  if (report.has(VERDICT.INVALID)) {\n    warnOnDevelopmentCustody(bundle, report);\n    return report;\n  }',
  },
  {
    name: 'base64-decoded-leniently',
    proves: 'Base64 fields are rejected rather than salvaged',
    file: 'lib/codec.js',
    find: '  if (!STANDARD.test(text) && !URL_SAFE.test(text)) {',
    replace: '  if (false) {',
  },
  {
    name: 'jcs-sorts-by-code-point',
    proves: 'RFC 8785 key ordering is by UTF-16 code unit',
    file: 'lib/jcs.js',
    find: '  const keys = Object.keys(obj).sort();',
    replace: '  const keys = Object.keys(obj).sort((a, b) => (a.codePointAt(0) ?? 0) - (b.codePointAt(0) ?? 0) || (a < b ? -1 : a > b ? 1 : 0));',
  },
  {
    name: 'timestamp-eku-not-required-critical',
    proves: 'RFC 3161 section 2.3 criticality on the signing certificate',
    file: 'lib/rfc3161.js',
    find: "    throw new TokenInvalid('extended key usage on the signing certificate is not critical');",
    replace: '    void 0;',
  },
  {
    name: 'esscertid-v2-defaults-to-sha1',
    proves: 'RFC 5035 ESSCertIDv2 defaults to SHA-256, not to ESSCertID v1 SHA-1',
    file: 'lib/rfc3161.js',
    find: "  let algorithm = isV2 ? 'sha256' : 'sha1';",
    replace: "  let algorithm = 'sha1';",
  },
  {
    name: 'expired-chain-not-reported-as-a-distinct-verdict',
    proves: 'a stream past its independent timestamp horizon is EXPIRED, not silently VALID',
    file: 'lib/verify.js',
    find: "  if (derived === 'expired') {",
    replace: "  if (false) {",
  },
  {
    name: 'missing-expires-at-not-required',
    proves: 'an rfc3161 sidecar without expires_at is MALFORMED (malformed-missing-expiry)',
    file: 'lib/verify.js',
    find: "  if (type === 'rfc3161') {\n    // Section 4: an rfc3161 sidecar MUST carry expires_at. The malformed-\n    // missing-expiry conformance fixture is exactly this omission.",
    replace: "  if (false) {\n    // Section 4: an rfc3161 sidecar MUST carry expires_at. The malformed-\n    // missing-expiry conformance fixture is exactly this omission.",
  },
  {
    name: 'gentime-trusted-past-the-horizon',
    proves: 'past the horizon, the chain is re-checked without trusting genTime',
    file: 'lib/rfc3161.js',
    find: '  if (new Date() <= horizon) {',
    replace: '  if (true) {',
  },
  {
    name: 'missing-trust-root-treated-as-failure',
    proves: 'a missing dependency is CANNOT CHECK, not an evidence failure',
    file: 'lib/rfc3161.js',
    find: "    throw new CannotCheck('no trust roots supplied;",
    replace: "    throw new TokenInvalid('no trust roots supplied;",
  },
];

function runSuite() {
  try {
    // The reporter is pinned: the default depends on whether stdout is a TTY,
    // and a run that cannot name the test that went red proves less than one
    // that can.
    execFileSync('node', ['--test', '--test-reporter=tap'], { cwd: ROOT, stdio: 'pipe' });
    return { red: false };
  } catch (error) {
    const output = `${error.stdout ?? ''}${error.stderr ?? ''}`;
    const failing = [...output.matchAll(/^\s*not ok \d+ - (.+)$/gm)].map((m) => m[1].trim());
    return { red: true, failing };
  }
}

function main() {
  if (process.argv.includes('--list')) {
    for (const fault of FAULTS) process.stdout.write(`${fault.name}: ${fault.proves}\n`);
    return;
  }

  const baseline = runSuite();
  if (baseline.red) {
    process.stderr.write('the suite is already red before any fault was injected; fix that first\n');
    process.exitCode = 1;
    return;
  }
  process.stdout.write(`baseline: green\n\n`);

  const survivors = [];
  for (const fault of FAULTS) {
    const target = path.join(ROOT, fault.file);
    const original = fs.readFileSync(target, 'utf8');

    if (!original.includes(fault.find)) {
      // A fault that no longer applies is not a passing fault. If the code moved,
      // the fault has to move with it or it silently stops proving anything.
      process.stdout.write(`STALE   ${fault.name}\n        anchor text not found in ${fault.file}\n`);
      survivors.push(`${fault.name} (stale)`);
      continue;
    }

    fs.writeFileSync(target, original.replace(fault.find, fault.replace));
    try {
      const result = runSuite();
      if (result.red) {
        process.stdout.write(`RED     ${fault.name}\n        caught by: ${result.failing.slice(0, 3).join('; ')}\n`);
      } else {
        process.stdout.write(`SURVIVED ${fault.name}\n        nothing failed. ${fault.proves} is not actually tested.\n`);
        survivors.push(fault.name);
      }
    } finally {
      fs.writeFileSync(target, original);
    }
  }

  process.stdout.write(`\n${FAULTS.length - survivors.length}/${FAULTS.length} faults caught\n`);
  if (survivors.length > 0) {
    process.stdout.write(`uncaught: ${survivors.join(', ')}\n`);
    process.exitCode = 1;
  }
}

main();
