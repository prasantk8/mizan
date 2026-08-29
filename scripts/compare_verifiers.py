#!/usr/bin/env python3
"""Run both verifiers over the conformance corpus and fail on any disagreement.

A single verifier cannot tell you whether it implements the specification or whether the
specification merely describes it: every ambiguity resolves silently in favour of whatever the one
implementation happens to do. `verifier-two/` was written from `EVIDENCE-BUNDLE-FORMAT.md` alone,
under a seal, precisely so the two could be diffed -- and until now nothing diffed them. The
findings in `verifier-two/FINDINGS.md` came from a human comparing outputs by hand, once.

This is that comparison as a gate. For every bundle in `tests/fixtures/conformance/verdicts.json`
it runs `scripts/verify_evidence_export.py` and `verifier-two/bin/mizan-verify-two.js` with the
same bundle and the same operator-supplied trust roots, and requires:

  * the same **verdict** -- and both matching the corpus's own declared expectation, so a shared
    misreading of the spec cannot pass by agreeing with itself;
  * the same **assurance** line, because "externally anchored" versus "unattested" is the claim an
    auditor acts on;
  * the same **NOT COVERED** list, because what a bundle does not prove is the half a reader is
    most likely to be misled about.

Every disagreement is a defect in the specification or in one implementation. None of them is
closed by editing a verifier until it agrees with the other; that would discard the only
independent signal this repository has about its own format.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

# Held here rather than imported from either verifier, and that is the point. An earlier draft
# filtered both sides through `verify_evidence_export.UNIVERSAL_LIMITATIONS`, which made the gate
# vacuous in the exact direction it exists to guard: deleting a limitation from the reference also
# removed it from the filter, so both sides lost it and the sets still matched. A gate that takes
# its expectations from one of the things it is checking cannot catch that thing shrinking. These
# four are the disclosures both implementations independently arrived at; what a verifier *must*
# disclose is not settled normatively anywhere, which is recorded against B-24.
EXPECTED_LIMITATIONS = frozenset(
    {
        "A valid bundle does NOT prove that a record was not omitted before it entered the chain "
        "(TM-001 pre-chain omission).",
        "A valid bundle does NOT prove that the exporting party did not withhold an entire final "
        "anchor or history suffix.",
        "RFC 3161 proves an included anchor existed by a time. It does not prove that no later "
        "anchor exists.",
        "A bundle does NOT prove when it was recorded after its declared expires_at. Bundle 1.0 "
        "claims offline verifiability for the lifetime of the timestamp authority's certificate "
        "and no longer (ADR-004 G.19); past the horizon a re-check supports only that the signer "
        "chains to the operator's trust root and the imprint is this anchor, never the time the "
        "token asserts.",
    }
)

# Verdicts for which "what this does not additionally prove" is a meaningful thing to say. A
# MALFORMED document is not a bundle and an INVALID one failed its checks.
QUALIFIED_VERDICTS = frozenset({"VALID", "EXPIRED"})

# Exit status is the verdict for both verifiers (verifier-two/README.md, and the same convention
# in verify_evidence_export.py): 0 VALID, 1 INVALID, 2 CANNOT CHECK, 3 MALFORMED, 4 EXPIRED.
VERDICT_BY_EXIT = {0: "VALID", 1: "INVALID", 2: "CANNOT CHECK", 3: "MALFORMED", 4: "EXPIRED"}


def run(command: list[str], repository: Path) -> tuple[dict, str]:
    """Run a verifier in `--json` mode and return its verdict document.

    Both emit the same shape. That shape is `verifier-two`'s, which derived it from the
    specification while sealed from the reference implementation; `verify_evidence_export.py`
    adopted it in T-110. The direction matters -- the independent implementation was not adjusted
    to match the incumbent, which would have discarded the only independent signal this
    repository has about its own format.
    """
    completed = subprocess.run(command, capture_output=True, text=True, cwd=repository)
    try:
        document = json.loads(completed.stdout)
    except json.JSONDecodeError:
        return {}, (
            f"exit {completed.returncode}, no JSON document on stdout:\n"
            f"{(completed.stdout + completed.stderr).strip()[:400]}"
        )
    if document.get("exit_status") != completed.returncode:
        return document, (
            f"document claims exit_status {document.get('exit_status')} while the process "
            f"exited {completed.returncode}"
        )
    return document, ""


def python_command(bundle: Path, roots: list[Path], repository: Path) -> list[str]:
    command = [
        sys.executable,
        str(repository / "scripts" / "verify_evidence_export.py"),
        str(bundle),
        "--json",
    ]
    for root in roots:
        command += ["--tsa-trust-anchor", str(root)]
    return command


def node_command(bundle: Path, roots: list[Path], repository: Path) -> list[str]:
    command = [
        "node",
        str(repository / "verifier-two" / "bin" / "mizan-verify-two.js"),
        str(bundle),
        "--json",
    ]
    for root in roots:
        command += ["--trust-root", str(root)]
    return command


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--corpus", type=Path, default=Path("tests/fixtures/conformance"))
    arguments = parser.parse_args(argv)

    repository = Path.cwd()
    corpus = arguments.corpus
    declared = json.loads((corpus / "verdicts.json").read_text(encoding="utf-8"))

    disagreements: list[str] = []
    for case in declared:
        name = case["bundle"]
        bundle = corpus / name
        roots = [(corpus / root).resolve() for root in case.get("trust_roots", [])]
        expected = case["verdict"]

        python_document, python_error = run(python_command(bundle, roots, repository), repository)
        node_document, node_error = run(node_command(bundle, roots, repository), repository)
        for who, error in (("python", python_error), ("node", node_error)):
            if error:
                disagreements.append(f"{name}: {who} did not produce a usable verdict -- {error}")

        python_verdict = python_document.get("verdict")
        node_verdict = node_document.get("verdict")
        agree = python_verdict == node_verdict
        correct = python_verdict == expected
        status = "ok" if agree and correct and not (python_error or node_error) else "DISAGREE"
        print(f"  {name:36s} python={python_verdict!s:12s} node={node_verdict!s:12s} {status}")

        if python_error or node_error:
            continue
        if not agree:
            disagreements.append(
                f"{name}: verdicts differ -- python says {python_verdict}, node says "
                f"{node_verdict}. One implementation or the specification is wrong. Do not "
                f"reconcile by editing a verifier until it agrees with the other."
            )
            continue
        if not correct:
            disagreements.append(
                f"{name}: both verifiers say {python_verdict}, the corpus declares {expected}. "
                f"Agreement is not correctness -- a shared misreading of the spec looks exactly "
                f"like this, which is why the corpus is checked too."
            )
            continue
        if python_document.get("derived_assurance") != node_document.get("derived_assurance"):
            disagreements.append(
                f"{name}: derived assurance differs -- python "
                f"{python_document.get('derived_assurance')!r}, node "
                f"{node_document.get('derived_assurance')!r}. This is the claim an auditor acts "
                f"on: 'externally anchored' and 'unattested' are not interchangeable."
            )

        # Disclosure is compared as a *set of limitations*, not as the whole notes array and not
        # word for word. Both implementations put free-form observations in `notes` as well --
        # `verifier-two` names the timestamp authority there, this side prints it in prose -- and
        # requiring those to match would force one implementation to copy the other's reporting
        # style, which is the one thing the seal exists to prevent. What must match is which of
        # the universal limitations each one discloses, because that is the half of the verdict a
        # reader is most likely to be misled about.
        python_limitations = {
            note for note in (python_document.get("notes") or []) if note in EXPECTED_LIMITATIONS
        }
        node_limitations = {
            note for note in (node_document.get("notes") or []) if note in EXPECTED_LIMITATIONS
        }
        required = EXPECTED_LIMITATIONS if python_verdict in QUALIFIED_VERDICTS else frozenset()
        for who, disclosed in (("python", python_limitations), ("node", node_limitations)):
            missing = sorted(required - disclosed)
            extra = sorted(disclosed - required)
            if missing:
                disagreements.append(
                    f"{name}: {who} does not disclose {len(missing)} limitation(s) it should on "
                    f"a {python_verdict} verdict: {missing}"
                )
            if extra:
                disagreements.append(
                    f"{name}: {who} attaches {len(extra)} limitation(s) to a {python_verdict} "
                    f"verdict, where they qualify nothing: {extra}"
                )

    if disagreements:
        print(file=sys.stderr)
        for entry in disagreements:
            print(f"DISAGREEMENT: {entry}", file=sys.stderr)
        print(
            f"\n{len(disagreements)} disagreement(s) across {len(declared)} conformance bundles.",
            file=sys.stderr,
        )
        return 1

    print(
        f"\nPASS: both verifiers agree with each other and with the corpus on "
        f"{len(declared)} bundles."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
