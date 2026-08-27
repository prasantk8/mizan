// The five terminal verdicts of EVIDENCE-BUNDLE-FORMAT.md section 5, and the
// exit statuses section 5 assigns them.
//
// The classes are mutually exclusive and neither MALFORMED nor CANNOT CHECK is
// an assurance result. Keeping them as four distinct values rather than a
// boolean is the whole design: "we could not check this" and "this is forged"
// must never render the same way to an auditor.

export const VERDICT = {
  VALID: 'VALID',
  INVALID: 'INVALID',
  CANNOT_CHECK: 'CANNOT CHECK',
  MALFORMED: 'MALFORMED',
  EXPIRED: 'EXPIRED',
};

export const EXIT_STATUS = {
  [VERDICT.VALID]: 0,
  [VERDICT.INVALID]: 1,
  [VERDICT.CANNOT_CHECK]: 2,
  [VERDICT.MALFORMED]: 3,
  [VERDICT.EXPIRED]: 4,
};

/**
 * Collects findings and resolves them to one terminal verdict.
 *
 * Precedence is MALFORMED, then INVALID, then CANNOT CHECK, then EXPIRED.
 * Grammar failures outrank everything because evidence checks over a non-bundle
 * are meaningless. A definite evidence failure outranks an unevaluable claim
 * because a bundle with a broken hash chain is broken whether or not a trust
 * root was supplied. CANNOT CHECK outranks EXPIRED because EXPIRED (section 5,
 * ratified in ADR-004 G.19) still asserts "every required check passed" -- an
 * indeterminate claim means that assertion cannot honestly be made yet, whether
 * or not the horizon has also been reached.
 *
 * Section 5 does not state MALFORMED/INVALID/CANNOT-CHECK precedence among
 * themselves; see FINDINGS.md S-7.
 */
export class Report {
  constructor() {
    this.findings = [];
    this.warnings = [];
    this.notes = [];
    this.derivedAssurance = null;
    this.expiry = null;
  }

  malformed(message) {
    this.findings.push({ class: VERDICT.MALFORMED, message });
    return this;
  }

  invalid(message) {
    this.findings.push({ class: VERDICT.INVALID, message });
    return this;
  }

  cannotCheck(message) {
    this.findings.push({ class: VERDICT.CANNOT_CHECK, message });
    return this;
  }

  warn(message) {
    this.warnings.push(message);
    return this;
  }

  note(message) {
    this.notes.push(message);
    return this;
  }

  /**
   * Record that the stream's independent timestamp horizon has been reached.
   * Not a defect: section 5 is explicit that EXPIRED is not a weaker INVALID.
   * `horizon` is the earliest anchor horizon (a Date); `message` names it.
   */
  expire(message, horizon) {
    this.expiry = { message, horizon };
    return this;
  }

  has(verdictClass) {
    return this.findings.some((finding) => finding.class === verdictClass);
  }

  of(verdictClass) {
    return this.findings.filter((finding) => finding.class === verdictClass);
  }

  get verdict() {
    if (this.has(VERDICT.MALFORMED)) return VERDICT.MALFORMED;
    if (this.has(VERDICT.INVALID)) return VERDICT.INVALID;
    if (this.has(VERDICT.CANNOT_CHECK)) return VERDICT.CANNOT_CHECK;
    if (this.expiry) return VERDICT.EXPIRED;
    return VERDICT.VALID;
  }

  get exitStatus() {
    return EXIT_STATUS[this.verdict];
  }
}
