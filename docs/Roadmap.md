# TraceShield Roadmap

Only v0.1.0 is committed. Everything after it is current intent and may change as the
earlier milestones produce evidence. Nothing here may be described as shipped until it is.

## v0.1.0 — Sanitize a trace, prove what you removed

The complete acceptance criteria are in [`ProductBrief.md`](ProductBrief.md) §7. Delivered
as end-to-end slices, each of which is usable on its own:

1. **Core engine.** Domain model, validated policy, detector protocol, regex rule pack,
   checksum verifiers, entropy scoring, key-name heuristics, bounded structure-preserving
   walk, redaction actions, findings. Public `Sanitizer` API. Full quality gate and CI.
2. **OpenTelemetry adapter.** `SanitizingSpanExporter` with identity preservation, event
   attribute coverage, and fail-closed export behaviour.
3. **CLI.** `traceshield scan` and `traceshield sanitize` over exported OTLP JSON, exiting
   non-zero on unredacted findings so it works as a CI check.
4. **Release.** Public-readiness checklist, benchmark with committed evidence, repository
   made public, 0.1.0 published to PyPI via Trusted Publishing.

## v0.2.0 — Meet users where they already are

- Langfuse `mask_otel_spans` adapter built on the same engine.
- Integration guides written against real running pipelines, not from documentation.
- Policy authoring ergonomics: policy inheritance, per-attribute overrides, a `traceshield
  policy explain` command that shows which rule would fire on a given value.
- Audit sink protocol with a JSONL implementation.

## v0.3.0 — Recall where determinism is not enough

- Optional `traceshield[presidio]` extra behind the existing `Detector` protocol.
- A measured recall and false-positive comparison on a synthetic corpus, with the corpus,
  command and raw results committed, so the trade-off is documented rather than asserted.
- Blob part handling design and ADR.

## Under consideration, not scheduled

- An OpenTelemetry Collector processor sharing the core rule pack, for defence in depth.
- Reversible tokenization for teams that must re-identify under controlled access.
- Metrics and logs signals.
- Streaming and chunk-level redaction.
