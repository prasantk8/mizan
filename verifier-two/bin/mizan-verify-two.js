#!/usr/bin/env node
// The second Mizan evidence verifier.
//
// Usage:
//   mizan-verify-two <bundle-dir> [--trust-root <pem>]... [--json] [--quiet]
//
// Exit status follows EVIDENCE-BUNDLE-FORMAT.md section 5:
//   0 VALID   1 INVALID   2 CANNOT CHECK   3 MALFORMED
//
// Trust roots are supplied by whoever runs this, never read from the bundle.
// A bundle that could name its own trust root could name one it controls.

import fs from 'node:fs';
import process from 'node:process';

import { verifyBundle, LIMITS_OF_A_CLEAN_VERDICT } from '../lib/verify.js';
import { loadTrustRoots } from '../lib/rfc3161.js';
import { VERDICT } from '../lib/verdict.js';

const USAGE = `mizan-verify-two <bundle-dir> [options]

  --trust-root <file>   PEM file of trust anchors for RFC 3161 timestamps.
                        Repeatable. Supplied by you, never by the bundle.
  --json                Emit the report as JSON.
  --quiet               Print the verdict line only.
  -h, --help            This text.

Exit status: 0 VALID, 1 INVALID, 2 CANNOT CHECK, 3 MALFORMED.
`;

function parseArguments(argv) {
  const options = { bundleDir: null, trustRootFiles: [], json: false, quiet: false };

  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    switch (argument) {
      case '-h':
      case '--help':
        process.stdout.write(USAGE);
        process.exit(0);
        break;
      case '--trust-root': {
        const file = argv[index + 1];
        if (!file) fail('--trust-root needs a file path');
        options.trustRootFiles.push(file);
        index += 1;
        break;
      }
      case '--json':
        options.json = true;
        break;
      case '--quiet':
        options.quiet = true;
        break;
      default:
        if (argument.startsWith('-')) fail(`unknown option ${argument}`);
        if (options.bundleDir) fail('exactly one bundle directory may be given');
        options.bundleDir = argument;
    }
  }

  if (!options.bundleDir) fail('a bundle directory is required');
  return options;
}

function fail(message) {
  process.stderr.write(`mizan-verify-two: ${message}\n\n${USAGE}`);
  process.exit(64); // EX_USAGE: a usage error is not a verdict about a bundle.
}

function main() {
  const options = parseArguments(process.argv.slice(2));

  const trustRoots = [];
  for (const file of options.trustRootFiles) {
    let text;
    try {
      text = fs.readFileSync(file, 'utf8');
    } catch (error) {
      fail(`cannot read trust root ${file}: ${error.message}`);
    }
    const certificates = loadTrustRoots(text);
    if (certificates.length === 0) fail(`${file} contains no PEM certificate`);
    trustRoots.push(...certificates);
  }

  const report = verifyBundle(options.bundleDir, { trustRoots });

  if (options.json) {
    process.stdout.write(`${JSON.stringify({
      verdict: report.verdict,
      exit_status: report.exitStatus,
      derived_assurance: report.derivedAssurance,
      findings: report.findings,
      warnings: report.warnings,
      notes: report.notes,
    }, null, 2)}\n`);
    process.exit(report.exitStatus);
  }

  render(report, options);
  process.exit(report.exitStatus);
}

function render(report, options) {
  const out = process.stdout;

  // The warnings go above the verdict, not below it. Section 4 requires the
  // custody warning to be printed; a warning under a large green VALID is a
  // warning nobody reads.
  if (!options.quiet) {
    for (const warning of report.warnings) out.write(`! ${warning}\n`);
    if (report.warnings.length > 0) out.write('\n');
  }

  out.write(`${report.verdict}  ${options.bundleDir}\n`);

  if (options.quiet) return;

  if (report.derivedAssurance) {
    out.write(`  derived assurance: ${report.derivedAssurance}\n`);
  }

  for (const cls of [VERDICT.MALFORMED, VERDICT.INVALID, VERDICT.CANNOT_CHECK]) {
    const findings = report.of(cls);
    if (findings.length === 0) continue;
    out.write(`\n${cls}:\n`);
    for (const finding of findings) out.write(`  - ${finding.message}\n`);
  }

  // Section 6, at equal prominence with the verdict. A verifier that prints a
  // verdict without its limits has told the reader something untrue by omission.
  out.write('\nWhat this verdict does not prove:\n');
  for (const limit of LIMITS_OF_A_CLEAN_VERDICT) out.write(`  - ${limit}\n`);

  const observations = report.notes.filter((note) => !LIMITS_OF_A_CLEAN_VERDICT.includes(note));
  if (observations.length > 0) {
    out.write('\nObserved:\n');
    for (const note of observations) out.write(`  - ${note}\n`);
  }
}

main();
