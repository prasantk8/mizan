#!/usr/bin/env python3
"""Require every pull request body to carry the H-2 completion report.

R-008's process note found four commit bodies with no pre-fix SHA (rule 8) and no
what-did-not-work (rule 10). A rule that depends on remembering is not a boundary, so this
gate is the boundary: the report is a CI-checked field of the pull request, not a habit.

The gate refuses a body that is missing a section, that names a pre-fix SHA git cannot
resolve, that claims a benchmark artifact which does not exist, or that fills rule 10 with
a word meaning "nothing". `Result: n/a - no behaviour change` is a legitimate rule-8 answer
for a change that touches only documentation, and the gate accepts it only for such a
change. Silence is never accepted.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

SECTIONS = (
    "Task",
    "What changed",
    "Rule 8",
    "Rule 10",
    "Rule 6",
    "H-7",
)

# Words an author reaches for when the section is a chore rather than a disclosure.
EMPTY_ANSWERS = {
    "",
    "-",
    "--",
    "n/a",
    "na",
    "none",
    "nothing",
    "nothing to report",
    "no",
    "tbd",
    "todo",
    "<!-- -->",
}

# `[^\S\n]` is horizontal whitespace only. `\s*` would step over the newline and read the
# next template line as the SHA, which is how the first draft of this gate reported
# "Pre-fix SHA: Command: does not resolve" against an untouched template.
SHA_PATTERN = re.compile(r"^Pre-fix SHA:[^\S\n]*(?P<sha>\S+)", re.MULTILINE)
RESULT_PATTERN = re.compile(r"^Result:[^\S\n]*(?P<result>.*)$", re.MULTILINE)
ARTIFACT_PATTERN = re.compile(r"benchmarks/results/[\w./-]+")

# Documentation is decided by suffix and by nothing else. The first draft also treated the
# `docs/` and `.github/` *directories* as documentation, which meant a pull request changing
# only `.github/workflows/ci.yml` could answer rule 8 with `Result: n/a - no behaviour
# change` -- the gate that gates, altered under a waiver. A directory is not evidence about
# whether a file executes. R-008 F-13a, found by CODEX reviewing this gate on PR #1.
DOCS_SUFFIXES = {".md", ".rst", ".txt"}

# `## Rule 80` used to be read as `## Rule 8`, because the heading was matched with a bare
# prefix test. `(?!\w)` requires the canonical token to end where the heading's own prose
# begins, so rewording after the number stays legal and renaming the number does not.
# R-008 F-13c.
HEADING_TOKENS = {name: re.compile(rf"{re.escape(name)}(?!\w)") for name in SECTIONS}

# The two sections a reviewer reads first, and the two the gate used to accept blank: the
# heading was present, so the section counted as answered. R-008 F-13b.
NARRATIVE_SECTIONS = ("Task", "What changed")


def split_sections(body: str) -> dict[str, str]:
    """Map each `## <heading>` to its text, keyed by the heading's leading token.

    Headings carry prose after the rule number -- `## Rule 8 - the test that fails before
    the fix` -- and the prose is allowed to be reworded. The key is the part that is not.
    """
    sections: dict[str, str] = {}
    current: str | None = None
    lines: list[str] = []
    for line in body.splitlines():
        if line.strip() == "---" and current is not None:
            # A horizontal rule ends the report. Without this the last section swallows the
            # reviewer note the template appends, and an empty H-7 reads as filled.
            sections[current] = "\n".join(lines).strip()
            current = None
            lines = []
        elif line.startswith("## "):
            if current is not None:
                sections[current] = "\n".join(lines).strip()
            heading = line[3:].strip()
            current = next(
                (name for name in SECTIONS if HEADING_TOKENS[name].match(heading)), heading
            )
            lines = []
        elif current is not None:
            lines.append(line)
    if current is not None:
        sections[current] = "\n".join(lines).strip()
    return sections


def strip_template_comments(text: str) -> str:
    return re.sub(r"<!--.*?-->", "", text, flags=re.DOTALL).strip()


def is_docs_only(changed_files: list[str]) -> bool:
    if not changed_files:
        return False
    return all(Path(path).suffix in DOCS_SUFFIXES for path in changed_files)


def sha_resolves(sha: str, repo: Path) -> bool:
    result = subprocess.run(
        ["git", "cat-file", "-e", f"{sha}^{{commit}}"],
        cwd=repo,
        capture_output=True,
        check=False,
    )
    return result.returncode == 0


def validate(body: str, changed_files: list[str], repo: Path) -> list[str]:
    failures: list[str] = []
    sections = split_sections(body)

    missing = [name for name in SECTIONS if name not in sections]
    if missing:
        failures.append(f"body has no `## {'`, `## '.join(missing)}` section")

    for name in NARRATIVE_SECTIONS:
        if name not in sections:
            continue  # already reported above; do not say the same thing twice
        answer = strip_template_comments(sections[name])
        if not answer or answer.lower() in EMPTY_ANSWERS:
            failures.append(
                f"`## {name}`: empty. The heading is not the answer -- this section was "
                f"present and blank, and the gate used to count that as filled"
            )

    docs_only = is_docs_only(changed_files)

    rule_eight = strip_template_comments(sections.get("Rule 8", ""))
    sha_match = SHA_PATTERN.search(rule_eight)
    result_match = RESULT_PATTERN.search(rule_eight)
    result_text = strip_template_comments(result_match.group("result")) if result_match else ""
    waived = docs_only and result_text.lower().startswith("n/a")

    if waived:
        pass
    elif not sha_match:
        failures.append(
            "rule 8: no `Pre-fix SHA:` line. Name the commit against which the new test "
            "fails, or -- for a documentation-only change -- write "
            "`Result: n/a - no behaviour change`"
        )
    elif not sha_resolves(sha_match.group("sha"), repo):
        failures.append(
            f"rule 8: `Pre-fix SHA: {sha_match.group('sha')}` does not resolve to a commit "
            "in this repository"
        )
    elif not result_text or result_text.lower() in EMPTY_ANSWERS:
        failures.append(
            "rule 8: `Result:` is empty. Paste the failure verbatim -- a test asserted to "
            "fail and never seen failing is the defect this rule exists to catch"
        )
    elif result_text.lower().startswith("n/a") and not docs_only:
        changed = ", ".join(changed_files[:5]) or "the diff"
        failures.append(
            f"rule 8: `Result: n/a` is only accepted for a documentation-only change, and "
            f"this one touches {changed}"
        )

    rule_ten = strip_template_comments(sections.get("Rule 10", ""))
    if rule_ten.lower() in EMPTY_ANSWERS:
        failures.append(
            "rule 10: empty. What was tried and abandoned, what was found on the way, what "
            "is still wrong. R-008 F-2 and F-3 are the shape of thing this section surfaces "
            "before a reviewer has to find it"
        )

    rule_six = strip_template_comments(sections.get("Rule 6", ""))
    if not rule_six:
        failures.append("rule 6: empty. Name the artifact path, or say `no numbers claimed`")
    for artifact in ARTIFACT_PATTERN.findall(rule_six):
        if not (repo / artifact).exists():
            failures.append(f"rule 6: `{artifact}` is named but does not exist in the tree")

    escalation = strip_template_comments(sections.get("H-7", ""))
    if not escalation:
        failures.append("H-7: empty. Say `does not fire`, or name the blocker filed")

    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--body-file", type=Path, required=True)
    parser.add_argument(
        "--changed-files-file",
        type=Path,
        help="newline-delimited paths changed by this pull request",
    )
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    arguments = parser.parse_args()

    body = arguments.body_file.read_text(encoding="utf-8")
    changed_files: list[str] = []
    if arguments.changed_files_file and arguments.changed_files_file.exists():
        changed_files = [
            line.strip()
            for line in arguments.changed_files_file.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]

    failures = validate(body, changed_files, arguments.repo)
    if failures:
        print("pull request body is not a completion report:", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        print(
            "\nSee docs/handoff/PR-PROTOCOL.md section 3. The template is "
            ".github/pull_request_template.md.",
            file=sys.stderr,
        )
        return 1
    print(f"pull request body carries the completion report ({len(SECTIONS)} sections)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
