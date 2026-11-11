# Evaluation report

Reproduce: `python3 code/evaluation/main.py`, `diff.py`, `validate.py`, `custom_cases.py` (see `code/README.md`).
The agent never reads `sample_output.csv`; it is used only by the scorer.

> Numbers below are with the media transcription cache. The public repo omits that cache (it is derived from the
> HackerRank dataset); without it sample status accuracy is 96.9% (31/32) and the full run gives 337/171/10.

## 1. Public samples (32 cases, scored against `dataset/sample_output.csv`)

| Metric | Value |
| --- | --- |
| Case-level `deletion_status` accuracy | 32/32 = **100%** (COMPLETE 10/10, INCOMPLETE 22/22) |
| Row exact match (status + full steps) | 28/32 = 87.5% |
| Step precision / recall / F1 | 99.5% / 97.4% / 98.4% |
| Field accuracy on aligned steps (phase, system_id, resource_id, operation, state, evidence_id) | 97.4% each (every matched step is fully correct) |
| Sequence exact (ordered list identical) | 87.5% |
| Sequence LCS ratio | 95.9% |

Note: the samples contain no `NOT_APPLICABLE` case, so that class is covered by custom cases C1/C5 below.

### Remaining sample failures (4 cases, all step-level, none change status)
| Case | Miss | Cause |
| --- | --- | --- |
| case_04 | 2 `VERIFY_*` steps (account_004, analytics_901) | Resource only identifiable through a PDF/PNG that is not in the media cache or has no linkable identifier |
| case_18, case_20 | `VERIFY_RECORD_PRESENT` for a retained `audit_record_*` | The retained audit-record id is not discoverable in participant-visible data |
| case_23 | 1 missing + 1 extra `VERIFY_RECORD_ABSENT` (account_410 vs account_7015) | Two identical failed account deletions in the same window with no distinguishing link; we pick the wrong one |

## 2. Full dataset (518 requests)
`output.csv`: 347 INCOMPLETE, 161 COMPLETE, 10 NOT_APPLICABLE. `validate.py`: 518 rows, sorted, unique case ids,
consecutive step numbers, phase order, allowed operation/state pairs, empty `evidence_id` for remediation and future
verification, **0 violations**. No reference exists for these rows, so only structural/invariant checks apply.
The run is deterministic (two consecutive runs produce byte-identical `output.csv`).

## 3. Additional evaluation cases (created by us; invariants, no gold labels)
| ID | Test | Result |
| --- | --- | --- |
| C1 | Multilingual / negated requests (access, export, correction, marketing opt-out, "keep my account") -> `NOT_APPLICABLE`, `[]`; plain deletions stay authorised | 13/13 |
| C2 | Request using a user's *historical* email resolves to the same user and gives the same result as the current email | 100/100 cases with a historical email |
| C3 | Rotating `reported_status` on every request must not change `deletion_status` | status unchanged 516/518; steps unchanged 313/518 |
| C4 | Moving `audit_at` back to request time must never cite evidence captured after the new `audit_at` | 0 late citations over 109 checked |
| C5 | Access-only text attached to a real ghost-record email stays `NOT_APPLICABLE` | 40/40 |

C3 finding: 2 statuses and 205 step lists change when the claim changes. Claims are not used as proof of state, but they are
used as a tie-breaker when linking identity-less copies (deleted / anonymised) to a user. This is the weakest part of the design
and is listed under limitations.

## 4. Failures found and improvements made
| Failure found | Improvement |
| --- | --- |
| Early build: 90.6% status accuracy, low step recall | Added SQL snapshot parsing (primary/replica drift, absence proven by later complete snapshots), five log dialects, and ledger parsing |
| Missing account / audit-record verification steps | Tombstone handling (keep `user_id`, remove name/email/phone/hash) and retained-record `VERIFY_RECORD_PRESENT` |
| Stale pre-request sightings polluted state | Discard observations older than the request / newer than `audit_at` |
| Hist. emails and shared addresses | Resolve by holder at `requested_at` using `user_audit_log.csv` |
| PNG/PDF artefacts ignored | Transcription cache (`code/cache/media_extractions.json`) read via `media.py` |

## 5. Known limitations
Unlinkable retained audit records (case_18/20), ambiguous identical failed deletions (case_23), one PDF not transcribed,
and claim-dependent linking of identity-less copies (C3). Hidden-set accuracy is expected to be somewhat below sample accuracy.
