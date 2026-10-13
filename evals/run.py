# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2024-2026 Humanbound
"""Run a dataset through one firewall configuration and write one result per case.

    python -m evals.run --config evals/configs/tier0.yaml --dataset evals/datasets

Each result records the verdict, category, tier, latency, tokens and the full explanation.
LLM replies are cached under evals/cache/ so a re-run costs nothing.
"""

from __future__ import annotations


def main() -> None:
    raise NotImplementedError


if __name__ == "__main__":
    main()
