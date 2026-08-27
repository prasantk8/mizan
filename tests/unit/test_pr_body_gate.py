"""The completion-report gate must reject the bodies R-008's process note describes.

Rule 11: the name of each test below is the claim. Every one of them names a body that a
reviewer would otherwise have to catch by reading, and asserts the gate catches it instead.
"""

from __future__ import annotations

from pathlib import Path

from scripts.validate_pr_body import validate

REPO = Path(__file__).resolve().parents[2]
TEMPLATE = REPO / ".github" / "pull_request_template.md"

CODE_CHANGE = ["control-plane/mizan_control_plane/evidence.py"]
DOCS_CHANGE = ["docs/handoff/PR-PROTOCOL.md"]
WORKFLOW_CHANGE = [".github/workflows/ci.yml"]

FILLED = """\
## Task
T-000 - a task

## What changed
The system now refuses something it used to permit.

## Rule 8 - the test that fails before the fix
Pre-fix SHA: {sha}
Command:     uv run pytest tests/unit/test_thing.py
Result:      FAILED test_thing.py::test_refusal - AssertionError: assert 'ALLOW' == 'DENY'

## Rule 10 - what did not work
Tried widening the policy grammar first; it made the refusal unprovable, so it was abandoned.

## Rule 6 - numbers
no numbers claimed

## H-7
does not fire
"""


def head_sha() -> str:
    import subprocess

    return subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=REPO, capture_output=True, text=True, check=True
    ).stdout.strip()


def test_a_filled_report_passes() -> None:
    assert validate(FILLED.format(sha=head_sha()), CODE_CHANGE, REPO) == []


def test_the_untouched_template_is_rejected() -> None:
    failures = validate(TEMPLATE.read_text(encoding="utf-8"), CODE_CHANGE, REPO)
    assert failures, "an unfilled template is the single most likely body to be submitted"


def test_a_body_with_no_rule_8_section_is_rejected() -> None:
    body = FILLED.format(sha=head_sha()).replace(
        "## Rule 8 - the test that fails before the fix", "## Notes"
    )
    assert any("Rule 8" in failure for failure in validate(body, CODE_CHANGE, REPO))


def test_a_reworded_heading_still_counts_as_its_section() -> None:
    """Headings are matched on the rule number, so the prose after it may be reworded."""
    body = FILLED.format(sha=head_sha()).replace(
        "## Rule 8 - the test that fails before the fix", "## Rule 8 (pre-fix reproduction)"
    )
    assert validate(body, CODE_CHANGE, REPO) == []


def test_an_unresolvable_pre_fix_sha_is_rejected() -> None:
    body = FILLED.format(sha="deadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
    failures = validate(body, CODE_CHANGE, REPO)
    assert any("does not resolve" in failure for failure in failures)


def test_rule_10_answered_with_a_word_meaning_nothing_is_rejected() -> None:
    for evasion in ("Nothing", "n/a", "None", "TBD", "-"):
        body = FILLED.format(sha=head_sha()).replace(
            "Tried widening the policy grammar first; it made the refusal unprovable, so it "
            "was abandoned.",
            evasion,
        )
        failures = validate(body, CODE_CHANGE, REPO)
        assert any("rule 10" in failure for failure in failures), evasion


def test_the_rule_8_waiver_is_refused_for_a_change_that_touches_code() -> None:
    body = FILLED.format(sha=head_sha()).replace(
        "Result:      FAILED test_thing.py::test_refusal - AssertionError: assert 'ALLOW' == 'DENY'",
        "Result:      n/a - no behaviour change",
    )
    failures = validate(body, CODE_CHANGE, REPO)
    assert any("documentation-only" in failure for failure in failures)


def test_the_rule_8_waiver_is_accepted_for_a_documentation_only_change() -> None:
    body = FILLED.format(sha=head_sha()).replace(
        "Result:      FAILED test_thing.py::test_refusal - AssertionError: assert 'ALLOW' == 'DENY'",
        "Result:      n/a - no behaviour change",
    )
    assert validate(body, DOCS_CHANGE, REPO) == []


def test_a_change_to_the_workflow_that_gates_cannot_waive_rule_8() -> None:
    """R-008 F-13a. `.github/` was a documentation prefix, so `ci.yml` was documentation.

    A pull request that alters the job which decides whether every other pull request is
    correct is the last change that should be admitted on `no behaviour change`.
    """
    body = FILLED.format(sha=head_sha()).replace(
        "Result:      FAILED test_thing.py::test_refusal - AssertionError: assert 'ALLOW' == 'DENY'",
        "Result:      n/a - no behaviour change",
    )
    failures = validate(body, WORKFLOW_CHANGE, REPO)
    assert any("documentation-only" in failure for failure in failures)


def test_documentation_that_happens_to_live_under_the_workflow_directory_still_waives() -> None:
    """The repair is by suffix, not by banning the directory: `.md` is still documentation."""
    body = FILLED.format(sha=head_sha()).replace(
        "Result:      FAILED test_thing.py::test_refusal - AssertionError: assert 'ALLOW' == 'DENY'",
        "Result:      n/a - no behaviour change",
    )
    assert validate(body, [".github/pull_request_template.md"], REPO) == []


def test_a_present_but_empty_narrative_section_is_not_an_answer() -> None:
    """R-008 F-13b. Deleting the prose under `## Task` used to leave the body valid."""
    for section, answer in (
        ("## Task", "T-000 - a task"),
        ("## What changed", "The system now refuses something it used to permit."),
    ):
        body = FILLED.format(sha=head_sha()).replace(f"{section}\n{answer}\n", f"{section}\n")
        failures = validate(body, CODE_CHANGE, REPO)
        assert any(section in failure for failure in failures), section


def test_a_heading_that_merely_begins_with_a_rule_number_is_not_that_rule() -> None:
    """R-008 F-13c. `## Rule 80` satisfied `## Rule 8` under a bare prefix match."""
    body = FILLED.format(sha=head_sha()).replace(
        "## Rule 8 - the test that fails before the fix", "## Rule 80 - a heading I invented"
    )
    assert any("Rule 8" in failure for failure in validate(body, CODE_CHANGE, REPO))


def test_a_claimed_benchmark_artifact_that_does_not_exist_is_rejected() -> None:
    body = FILLED.format(sha=head_sha()).replace(
        "no numbers claimed", "benchmarks/results/chain-verifier-does-not-exist.json"
    )
    failures = validate(body, CODE_CHANGE, REPO)
    assert any("does not exist" in failure for failure in failures)


def test_a_pre_fix_sha_line_left_blank_is_reported_as_missing_not_as_the_next_line() -> None:
    """The first draft of the gate read `Command:` as the SHA because `\\s*` crosses newlines."""
    body = FILLED.format(sha="").replace("Pre-fix SHA: \n", "Pre-fix SHA:\n")
    failures = validate(body, CODE_CHANGE, REPO)
    assert any("no `Pre-fix SHA:` line" in failure for failure in failures)
    assert not any("Command:" in failure for failure in failures)
