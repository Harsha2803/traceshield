# ADR 0003: Integrate as an exporter wrapper, not a span processor

- Status: Accepted
- Date: 2026-09-06

## Context

TraceShield must modify span attribute values before they leave the process. The obvious
place is a `SpanProcessor`, since that is the documented extension point for reacting to
span lifecycle events.

It does not work. In the OpenTelemetry Python SDK, `SpanProcessor.on_end()` receives a
`ReadableSpan`, which is immutable. An upstream issue asking for hooks to modify span
content before conversion to `ReadableSpan` is open
(`open-telemetry/opentelemetry-python#4424`), and the same question in the Go and JS
repositories reaches the same answer. `on_start()` does receive a mutable span, but the
content TraceShield needs to inspect is not set until the operation completes.

Full evidence and sources are in `Research.md` §4.

## Decision

The OpenTelemetry integration is `SanitizingSpanExporter`, which implements `SpanExporter`
and wraps a delegate exporter:

```python
SanitizingSpanExporter(OTLPSpanExporter(), policy=Policy.default())
```

`export()` constructs a sanitized replacement for each `ReadableSpan` and delegates to the
wrapped exporter. `shutdown()` and `force_flush()` forward to the delegate.

The replacement preserves span identity exactly — trace ID, span ID, parent, name, kind,
start and end time, status, links, resource attributes and instrumentation scope. Only
attribute values and event attribute values may differ. This is invariant 2 in
`Architecture.md` and is asserted by test.

Because the wrapper runs on the `BatchSpanProcessor` worker thread, the engine is
synchronous, performs no I/O, and never raises into `export()`.

## Alternatives considered

**Span processor.** Impossible as described above.

**Instrument at the source, patching each LLM SDK's instrumentation.** Rejected: it would
require a per-library adapter for every instrumentation package, would break on their
upgrades, and would miss any instrumentation not yet adapted. The exporter is the one choke
point every span passes through.

**OpenTelemetry Collector processor.** Rejected as the v0.1 surface. It cannot descend into
serialized chat message structures, requires deployed infrastructure, leaves no audit record,
and lets sensitive values cross the network before redaction. A collector processor built on
the same core remains a reasonable later addition for defence in depth.

**Vendor masking hooks first, such as Langfuse `mask_otel_spans`.** Rejected as the v0.1
surface because it ties the release to one destination. The engine's contract is
deliberately compatible with that hook — deterministic, no I/O, read-only in and sparse
attribute patch out — so a Langfuse adapter is planned for v0.2 at low cost.

## Consequences

- Sanitization cost lands on the export path and must be measured, not assumed.
- Users who export to several backends must wrap each exporter, or wrap once and fan out.
  The quickstart shows the single-exporter case and the guide covers the other.
- Spans dropped by sampling are never sanitized because they are never exported, which is
  correct and worth stating in the documentation.
- If OpenTelemetry later provides a mutable pre-export hook, this ADR should be revisited
  rather than silently deviated from.
