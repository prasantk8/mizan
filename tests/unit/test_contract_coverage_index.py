"""The coverage index has to be checkable, or it is only a claim about itself.

At 330a2d5 `validate_contract_coverage.py` matched rows whose first cell looked like `I-n` or
`V-n` and silently skipped every other row. Two rows already in the index — `R-003/B-9` and the
`§8.1 / ADR-008 Amd.` row T-070 added — were therefore never checked against pytest at all: either
could have cited a renamed or deleted test and `make check` would still have reported the index
valid. An unchecked coverage row is worse than a missing one, because it reads as evidence.

`test_a_row_naming_an_adr_amendment_is_checked_like_an_invariant_row` fails on 330a2d5.
"""

from __future__ import annotations

from scripts.validate_contract_coverage import check_coverage

COLLECTED = {"unit/test_thing.py::test_it_holds", "unit/test_thing.py::test_it_also_holds"}

HEADER = "| Contract | Primary executable evidence |\n|---|---|\n"


def index(*rows: str) -> str:
    return HEADER + "".join(rows)


def test_a_row_naming_an_adr_amendment_is_checked_like_an_invariant_row() -> None:
    errors, checked = check_coverage(
        index("| ADR-004 G.19 | `unit/test_thing.py::test_was_renamed_away` |\n"), COLLECTED
    )
    assert checked == 1
    assert errors == [
        "ADR-004 G.19 references uncollected test unit/test_thing.py::test_was_renamed_away"
    ]


def test_a_valid_row_of_any_shape_passes() -> None:
    errors, checked = check_coverage(
        index(
            "| I-1 | `unit/test_thing.py::test_it_holds` |\n",
            "| §8.1 / ADR-008 Amd. | `unit/test_thing.py::test_it_also_holds` |\n",
        ),
        COLLECTED,
    )
    assert (errors, checked) == ([], 2)


def test_a_row_that_cites_no_pytest_node_is_an_error() -> None:
    errors, checked = check_coverage(
        index("| V-9 | covered by the invariant suite |\n"), COLLECTED
    )
    assert checked == 1
    assert errors == ["V-9 has no explicit pytest node"]


def test_the_header_and_separator_are_not_contract_rows() -> None:
    errors, checked = check_coverage(HEADER, COLLECTED)
    assert (errors, checked) == ([], 0)


def test_one_test_cannot_be_primary_evidence_for_more_than_three_rows() -> None:
    errors, checked = check_coverage(
        index(*[f"| I-{n} | `unit/test_thing.py::test_it_holds` |\n" for n in range(1, 5)]),
        COLLECTED,
    )
    assert checked == 4
    assert errors == [
        "unit/test_thing.py::test_it_holds is primary evidence for 4 contract rows (maximum 3)"
    ]
