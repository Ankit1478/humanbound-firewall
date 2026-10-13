# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2024-2026 Humanbound
"""Turn a results file into metrics and check them against a baseline.

    python -m evals.score --results evals/results/<run-id>.jsonl --baseline evals/baselines/<config>.json

Metrics per class, attack type, language and tier: detection rate, false positive rate, precision,
F1, review rate (scored both fail-open and fail-closed), Tier 3 share, p50/p95 latency and cost.
Exits non-zero when a gate fails.
"""

from __future__ import annotations


def main() -> None:
    raise NotImplementedError


if __name__ == "__main__":
    main()
