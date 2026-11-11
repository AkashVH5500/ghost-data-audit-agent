"""Media evidence (PNG screenshots, PDF documents).

The audit is deterministic and does not call a model.  Images and PDFs were transcribed once, by a
vision-capable model, into structured observations in ``code/cache/media_extractions.json``;
the audit consumes that cache at run time.  Each observation records only what the artefact displays
(resource id, system, kind, visible state, identifiers shown) -- never a verdict.
``code/tools/extract_media.py`` automates the same transcription through the API (optional; it was
not used to produce the shipped cache, which was transcribed in the development session).

Artefacts missing from the cache contribute no observations.  The only such file in this dataset
(``legal_retention_register_20260529.pdf``) lists order ids and ``user_NN`` references but no resource
ids, so it carries nothing the audit could cite.
"""
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
CACHE = os.path.join(HERE, "..", "cache", "media_extractions.json")


def load_media_cache(dataset_dir=None):
    try:
        with open(CACHE, encoding="utf-8") as fh:
            return json.load(fh).get("files", {})
    except (OSError, ValueError):
        return {}
