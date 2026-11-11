# Ghost Data Still Exists: deletion-audit agent

A deterministic audit agent for the HackerRank Orchestrate (October 2026) challenge "Ghost Data Still Exists".
For each deletion request it decides whether a person's data is really gone (`COMPLETE` / `INCOMPLETE` /
`NOT_APPLICABLE`) and emits the ordered findings, remediation and verification steps.

It reconstructs the state of every system at the audit cutoff from supplied evidence (SQL snapshots, logs, JSON,
ledgers, screenshots), treats workflow statuses as claims rather than proof, resolves current and historical
identifiers, and applies the deletion policy, including account tombstones and restore/sync risks.
No model is called at run time.

- Code, setup and pipeline description: [`code/README.md`](code/README.md)
- Evaluation results and custom cases: [`code/evaluation/evaluation_report.md`](code/evaluation/evaluation_report.md)
- Usage and cost: [`code/evaluation/usage_report.md`](code/evaluation/usage_report.md)

## Data

The challenge dataset belongs to HackerRank and is **not** included. Download it from
https://github.com/interviewstreet/hackerrank-orchestrate-october26 into `dataset/`, then:

```bash
python3 code/main.py            # writes output.csv
python3 code/evaluation/main.py # scores the 32 public samples
```

Predictions and the screenshot-transcription cache are derived from the dataset and are also not included. Without
the cache, the 14 PNG/PDF artefacts contribute no evidence and a few steps are missed; regenerate it with
`code/tools/extract_media.py` (needs `ANTHROPIC_API_KEY` in the environment).

## Honest limits

With the screenshot-transcription cache: 32/32 sample statuses and 98.4% sample step F1 (the numbers in the evaluation
report). Without it, as in this public repo: 96.9% sample statuses (31/32) and 98.4% step precision, and the full run gives
337 INCOMPLETE / 171 COMPLETE instead of 347 / 161, because evidence that only appears in screenshots and PDFs is
missed. The samples guided development, so these are fits, not holdout scores. Known weak spots are in the
evaluation report.

Built with AI assistance. MIT licensed.
