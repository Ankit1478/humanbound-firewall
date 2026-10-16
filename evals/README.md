# Evals

The tests in `tests/` check that the code works. The evals here check that the firewall makes good
decisions: does it block attacks, does it let normal content through, and how fast and at what cost.

> Status: the loader, runner, scorer and label review work; report.py and fetch_public.py are stubs.

## Layout

```
evals/
  datasets/     labelled cases, one JSON object per line (see schema.py)
    request.jsonl     principal turns
    ingest.jsonl      tool output, pages, documents
    recall.jsonl      the agent's own records
    must_pass.jsonl   benign content that must never be blocked (hard gate)
    must_block.jsonl  known bypasses that must always be blocked (hard gate)
    SOURCES.md        where each case came from, and its license
    VERSION           dataset version, bumped on every change
  policies/     agent.yaml files the cases refer to by name
  configs/      firewall configurations to evaluate (which tiers, which judge)
  baselines/    last accepted scores per config; the regression gate compares against these
  scripts/      helpers, e.g. downloading public datasets that cannot be redistributed
  schema.py     the case format, loading and validation
  run.py        runs a dataset through a config -> results/<run-id>.jsonl
  score.py      results -> metrics
  report.py     metrics -> markdown report
  compare.py    labels vs one or more judges -> the cases a human should review
```

`results/` and `cache/` are created at run time and ignored by git.

## Usage

```bash
python -m evals.run   --config evals/configs/tier0.yaml --dataset evals/datasets
python -m evals.score --results evals/results/<run-id>.jsonl --baseline evals/baselines/tier0.json
```

## Checking the labels

Run one or two judge-only configs, then compare them with the labels:

```bash
export OPENAI_API_KEY=... ANTHROPIC_API_KEY=...
python -m evals.run --config evals/configs/judge-openai.yaml
python -m evals.run --config evals/configs/judge-claude.yaml
python -m evals.compare --results evals/results/judge-openai-*.jsonl evals/results/judge-claude-*.jsonl
```

The review list puts first the cases where every judge, in every repeat, said the opposite of the
label. A disagreement is not proof that the label is wrong: read the case, then decide.

## Rules

- Tune on the dev split only; the test split is never used to change prompts or thresholds.
- Never include cases used to train a Tier 2 model.
- Every class needs benign cases as well as attacks: a firewall that blocks everything must score badly.
