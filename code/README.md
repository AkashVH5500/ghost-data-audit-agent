# Ghost Data deletion-audit agent

Deterministic evidence-reconstruction agent. For each request it decides `COMPLETE` / `INCOMPLETE` /
`NOT_APPLICABLE` and emits the ordered FINDING -> REMEDIATION -> VERIFICATION steps. No model is called
at run time (see `evaluation/usage_report.md`); PNG/PDF artefacts are read through a transcription
cache that a vision model produced once (see "Media evidence").

## Setup and run

Python 3.9+, standard library only. `pdftotext` is optional (not needed for the shipped output).

```bash
python3 code/main.py                                   # dataset/ -> output.csv (518 rows, sorted)
python3 code/main.py --trace trace.txt                 # also write a per-case resource trace
python3 code/evaluation/main.py                        # score vs dataset/sample_output.csv
python3 code/evaluation/diff.py                        # per-case step differences on the samples
python3 code/evaluation/validate.py                    # structural/contract check of output.csv
python3 code/evaluation/custom_cases.py                # our additional evaluation cases
```

Paths resolve relative to the repository root, so the layout is `<root>/dataset/...`, `<root>/code/...`.

## Pipeline (`code/ghost/`)

| Stage | Module | What it does |
| --- | --- | --- |
| Intent | `intent.py` | Multilingual lexicon: does `request_text` authorise deletion? Access / correction / export / opt-out / "keep my account" -> `NOT_APPLICABLE`, `[]`. |
| Identity | `identity.py` | Request e-mail (current or historical) -> user; collects every e-mail, hash and phone from `user_identities.csv` + `user_audit_log.csv`, resolving shared addresses by the holder at `requested_at`. |
| Evidence | `evidence.py`, `logparse.py`, `media.py` | Parses JSON exports, SQL snapshots (primary/replica tables loaded into SQLite semantics), text ledgers, five log dialects, and the media cache into uniform observations (system, resource, kind, state, identifier tokens, capture time, in-file position). |
| Linking + state | `audit.py` | Links observations to the subject by identifier tokens and `LINK_RESOURCE_IDENTITY` catalog rows; reconstructs the state at `audit_at` (later evidence ignored, stale pre-request sightings discarded, absence proven by later complete snapshots); links identity-less copies (deleted / anonymised) through worker activity + file order. |
| Policy | `policy.py` | `deletion_rules.csv` -> required treatment per data category (DELETE / REDACT / ANONYMIZE / RETAIN, restore-block, flow-disable); decides violations and emits the allowed operation vocabulary only. |
| Output | `runner.py` | Orders steps (phase -> operation table order -> system -> resource), numbers them, writes `output.csv`. |

Key rules implemented: reported statuses and worker results are claims, never proof; findings and
`COMPLETE` verifications cite only evidence/activity at or before `audit_at`; remediation and future
verification steps of `INCOMPLETE` cases have an empty `evidence_id`; retained records (security audit
log, legal hold, backups with restore blocked, tombstones with only `user_id`) get
`VERIFY_RECORD_PRESENT` / `VERIFY_RESTORE_BLOCKED` / `VERIFY_RECORD_REDACTED` instead of deletion.

## Media evidence

`code/cache/media_extractions.json` (not included in the public repo; it is derived from the dataset) holds structured transcriptions of 14 PNG/PDF artefacts (what each
screen/document displays: resource id, system, kind, visible state, identifiers shown, no verdicts). It was
produced by a vision-capable model during development. `code/tools/extract_media.py` is an
optional script that automates the same transcription via the Anthropic API (`ANTHROPIC_API_KEY` from the
environment); it was **not** run to produce the shipped cache. One PDF (the legal retention register) is
not in the cache; it lists order ids and `user_NN` references only, with no resource ids to cite.

## Known limitations

* Audit records of two sample cases (retained `audit_record_*` ids) are not discoverable in the
  participant data, so those verification steps are missed.
* When two identical failed account deletions fall in the same time window with no other link, the
  choice between them is a guess (sample `case_23`).
* Linking of identity-less copies uses claim/time consistency as a *link* heuristic; rotating
  `reported_status` leaves statuses stable but changes which copies are linked (custom case C3).
