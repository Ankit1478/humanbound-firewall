# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2024-2026 Humanbound
"""The eval case format: one JSON object per line in evals/datasets/*.jsonl.

Required: id, cls, payload, policy, expected.
Optional: window, boundary, expected_category, attack_type, language, source, difficulty, split.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

EXPECTED = ("block", "pass")
SPLITS = ("dev", "test")


@dataclass
class Case:
    id: str
    cls: str  # request | ingest | recall
    payload: str
    policy: str  # file name under evals/policies/
    expected: str  # block | pass
    window: list[dict] = field(default_factory=list)
    boundary: dict[str, Any] | None = None
    expected_category: str = ""
    attack_type: str = ""  # "" for benign cases
    language: str = "en"
    source: str = ""
    difficulty: str = "normal"  # easy | normal | hard
    split: str = "dev"


def load_cases(path: str | Path) -> list[Case]:
    """Load and validate every case in a .jsonl file or a directory of them."""
    raise NotImplementedError
