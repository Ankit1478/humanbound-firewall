# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2024-2026 Humanbound
"""The case loader: the shipped datasets load, and a broken case fails with its file and line."""

import json

import pytest

from evals.schema import CaseError, load_cases

GOOD = {"id": "x", "cls": "ingest", "payload": "p", "policy": "banking.yaml", "expected": "pass"}


def _write(path, *lines):
    path.write_text("".join((ln if isinstance(ln, str) else json.dumps(ln)) + "\n" for ln in lines))
    return path


def test_the_shipped_datasets_load_and_every_case_knows_its_suite():
    cases = load_cases()
    assert cases
    assert {c.suite for c in cases} >= {"request", "ingest", "recall", "must_pass", "must_block"}
    assert len({c.id for c in cases}) == len(cases)


def test_a_minimal_case_gets_the_defaults(tmp_path):
    (case,) = load_cases(_write(tmp_path / "t.jsonl", GOOD))
    assert (case.window, case.boundary, case.language, case.split) == ([], None, "en", "dev")
    assert case.suite == "t"


@pytest.mark.parametrize(
    "case, message",
    [
        ({**GOOD, "atack_type": "x"}, "unknown field"),
        ({k: v for k, v in GOOD.items() if k != "policy"}, "missing required"),
        ({**GOOD, "cls": "pigeon"}, "cls"),
        ({**GOOD, "expected": "maybe"}, "expected"),
        ({**GOOD, "expected": "block"}, "attack_type"),
        ({**GOOD, "expected_category": "restriction"}, "pass case"),
        ({**GOOD, "expected": "block", "attack_type": "a", "expected_category": "bad"}, "category"),
        ({**GOOD, "policy": "nope.yaml"}, "not found"),
        ({**GOOD, "window": [{"role": "system", "content": "x"}]}, "role"),
        ({**GOOD, "boundary": {"kind": "tools"}}, "name"),
        ({**GOOD, "suite": "x"}, "unknown field"),
        ({**GOOD, "id": "  "}, "empty"),
    ],
)
def test_a_broken_case_is_rejected_with_its_file_and_line(tmp_path, case, message):
    path = _write(tmp_path / "t.jsonl", GOOD | {"id": "first"}, case)
    with pytest.raises(CaseError, match=message) as e:
        load_cases(path)
    assert "t.jsonl:2" in str(e.value)


def test_invalid_json_names_the_line(tmp_path):
    with pytest.raises(CaseError, match="t.jsonl:2: invalid JSON"):
        load_cases(_write(tmp_path / "t.jsonl", GOOD, "{broken"))


def test_an_id_used_twice_is_rejected_even_across_files(tmp_path):
    _write(tmp_path / "a.jsonl", GOOD)
    _write(tmp_path / "b.jsonl", GOOD)
    with pytest.raises(CaseError, match="duplicate id 'x'"):
        load_cases(tmp_path)


def test_blank_lines_are_skipped(tmp_path):
    assert len(load_cases(_write(tmp_path / "t.jsonl", GOOD, "", "   "))) == 1
