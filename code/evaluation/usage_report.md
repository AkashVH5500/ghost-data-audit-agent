# Usage report (final full-dataset run that produced `output.csv`)

The final run is **fully deterministic and calls no model at run time**.

| Provider / model | Calls | Input tokens | Output tokens | Est. cost |
| --- | --- | --- | --- | --- |
| none (pure Python, standard library) | 0 | 0 | 0 | $0.00 |

| Overall | Value |
| --- | --- |
| Requests processed | 518 |
| Total tokens | 0 |
| Average tokens per request | 0 |
| Estimated total cost | $0.00 |
| Estimated cost per request | $0.00 |

## Development-time model use (not part of the final run)
- An AI coding assistant helped write the code and, once, a vision-capable model transcribed 14 PNG/PDF artefacts into
  `code/cache/media_extractions.json` (what each shows; no verdicts). Token counts for that interactive work were not
  metered, so no figure is claimed here.
- `code/tools/extract_media.py` can regenerate the cache through the Anthropic API (`ANTHROPIC_API_KEY` from the environment);
  it was not run to produce the shipped output. No keys or credentials are included.
