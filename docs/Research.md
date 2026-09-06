# TraceShield Research and Landscape

This is the evidence base behind the TraceShield brief. It records what already exists,
what those tools do and do not do, and which verified facts the design depends on. Update
it when an upstream fact changes; do not let the brief or the code rely on a claim that is
not written down here with a source.

Last verified: 2026-09-06.

## 1. What LLM and agent telemetry actually carries

OpenTelemetry moved its GenAI semantic conventions into a dedicated repository,
[`open-telemetry/semantic-conventions-genai`](https://github.com/open-telemetry/semantic-conventions-genai).
The attribute registry at `model/gen-ai/registry.yaml` currently defines 72 `gen_ai.*`
attributes. Every one of them is still at `development` stability, which means names can
change and any tool that hard-codes them must version its rule pack.

Eleven of those attributes are explicitly annotated in the upstream registry with the note
"This attribute may contain sensitive information":

| Attribute | Carries |
| --- | --- |
| `gen_ai.system_instructions` | System prompt text |
| `gen_ai.input.messages` | Full input conversation |
| `gen_ai.output.messages` | Full model output |
| `gen_ai.tool.call.arguments` | Arguments passed to a tool |
| `gen_ai.tool.call.result` | Value returned by a tool |
| `gen_ai.tool.definitions` | Tool schemas, which often embed endpoints and examples |
| `gen_ai.tool.description` | Free-text tool description |
| `gen_ai.retrieval.query.text` | RAG query text |
| `gen_ai.memory.query.text` | Agent memory query |
| `gen_ai.memory.records` | Agent memory contents |
| `gen_ai.prompt.variable` | Values interpolated into a prompt template |

Three more attributes are content-bearing in practice even though upstream has not tagged
them: `gen_ai.retrieval.documents`, `gen_ai.evaluation.explanation`, and
`gen_ai.conversation.id` (frequently an application user or session identifier).

These are not flat strings. `model/gen-ai/` ships JSON Schemas —
`gen-ai-input-messages.json`, `gen-ai-output-messages.json`,
`gen-ai-tool-call-arguments.json`, `gen-ai-tool-call-result.json`,
`gen-ai-tool-definitions.json`, `gen-ai-system-instructions.json`,
`gen-ai-memory-records.json`, `gen-ai-retrieval-documents.json` — describing structured
payloads. An input message is a `ChatMessage` with a `role` and a list of `parts`, where a
part is a `TextPart`, `ToolCallRequestPart`, `ToolCallResponsePart`, or `BlobPart`
(base64-encoded binary with a MIME type and modality). `ToolCallArguments` is an open
object with `additionalProperties: true`.

This is the single most important design input. Sensitive content in GenAI telemetry lives
at the *leaves of a nested JSON document serialized into a span attribute*, not in a flat
string. Any redactor that treats the attribute as opaque text either destroys the structure
the observability UI needs or misses values that only appear after parsing.

MCP spans add `mcp.method.name`, `mcp.session.id`, `mcp.resource.uri`, and
`mcp.protocol.version`; `mcp.resource.uri` can carry identifiers and query parameters.

Sources:
[GenAI semconv repo](https://github.com/open-telemetry/semantic-conventions-genai),
[GenAI observability blog](https://opentelemetry.io/blog/2026/genai-observability/),
[semconv cheat sheet](https://greptime.com/blogs/2026-05-09-opentelemetry-genai-semantic-conventions).

## 2. Why content capture is the problem, not the answer

Content capture is opt-in in the GenAI conventions precisely because these fields are
sensitive. That creates a binary that teams actually live with:

- Content capture **off**: traces show model, token counts, latency, and finish reason. You
  cannot debug a bad answer, a broken tool call, or a prompt-injection incident.
- Content capture **on**: prompts, completions, tool arguments and retrieved documents are
  shipped to an observability vendor, indexed, retained under that vendor's policy, and
  usually stored outside the jurisdiction the data was collected in.

Storing large content directly in span attributes is also called out upstream as an
anti-pattern: attributes are indexed and size-limited, so the conventions prefer events,
which a collector can drop wholesale. Dropping wholesale is still the same binary.

TraceShield exists to remove the binary: keep the structure and the debuggable metadata,
remove the sensitive leaves, and record what was removed.

## 3. Prior art, and precisely where it stops

### OpenTelemetry Collector `redactionprocessor`

Attribute allowlist/blocklist plus regex value masking, applied in the collector.

Stops at: traces only (metrics and logs need `attributesprocessor`); operates on attribute
values as opaque strings, so it cannot descend into a serialized `ChatMessage` and redact a
single `TextPart` while preserving roles and part types; requires deploying and operating a
collector, which is not available to a library author or a notebook user; and it produces
no structured record of which rule fired on which field, so there is nothing to audit
afterwards.

### Vendor masking hooks

Langfuse ships the closest thing to TraceShield's insertion point. Its Python SDK takes
`mask_otel_spans(*, params: MaskOtelSpansParams) -> Optional[MaskOtelSpansResult]`, where
`params.spans` maps `OtelSpanIdentifier(trace_id, span_id)` to read-only `OtelSpanData`
snapshots and the result carries `span_patches` of `OtelSpanPatch(delete_attributes,
set_attributes)`. It documents that the hook can only change span attributes — not the span
name, IDs, parent, resource attributes, events, links, or scope — that it must be
deterministic and fast because it runs on the batch processor worker thread, and that an
invalid result causes Langfuse to drop the entire export batch.

Stops at: it is a hook, not a redactor. Langfuse supplies the seam; you still have to write
every detector, every policy decision and every audit record yourself. It is also
Langfuse-specific, so the work does not transfer when a team also exports to Datadog,
Grafana or Phoenix. LangSmith's equivalent guidance is to run a collector-side transform
processor, which inherits the collector limitations above.

This is a useful validation signal rather than a competitor: the shape of Langfuse's hook
(read-only snapshot in, sparse attribute patch out, deterministic, no I/O) is almost exactly
the contract TraceShield's engine must satisfy, so a Langfuse adapter is cheap to add later.

### PII libraries

Microsoft Presidio separates detection (recognizers producing spans with confidence) from
anonymization (operators), and is extensible with new recognizers and NLP backends.
Reported accuracy out of the box is mediocre and needs tuning; it pulls spaCy models.
Scrubadub is a lighter rule-based cleaner. `logprivacy`, `pii-redactor`, `sanityze` and
similar packages target logs, dataframes or free text.

Stops at: all of them take text or a dataframe and return redacted text. None of them model
a span, a trace, a policy decision or an audit record, and none understand GenAI attribute
semantics. They are candidate *detectors* to plug into TraceShield later, not substitutes
for it.

### Secret scanners

Gitleaks is rule-first with a large regex library and Shannon entropy as a secondary
signal; TruffleHog's distinguishing feature is live credential verification; Yelp's
detect-secrets targets large existing codebases where naive detection produces unusable
false-positive volume. A published comparison found TruffleHog at 370 and Gitleaks at 635
false positives on the same corpus, attributing the gap to broad rules.

Stops at: they scan repositories and filesystems in batch, offline, where a 200 ms scan and
a human triage queue are both acceptable. None of them are designed to run synchronously
inside a telemetry export path with a per-span latency budget. Their *rule corpora and the
false-positive lesson* transfer; their execution model does not.

The lesson TraceShield takes from them: pattern match alone is not enough. Where a
credential or identifier has a checksum — Luhn for payment cards, mod-97 for IBAN, CRC32 in
GitHub token suffixes, Verhoeff for Aadhaar — verifying it is what separates a usable
default policy from an alert-fatigue generator.

### Closest adjacent package

`agent-sanitizer` on PyPI sanitizes untrusted *text* for prompt injection, ANSI and Unicode
exploits, with optional detect-secrets redaction. It is a Python bridge to a Node CLI and
requires Node >= 22. Different problem (untrusted input into a model), different direction
of data flow, and not a telemetry component.

Sources:
[redactionprocessor README](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/processor/redactionprocessor/README.md),
[OTel handling sensitive data](https://opentelemetry.io/docs/security/handling-sensitive-data/),
[Langfuse masking docs](https://langfuse.com/docs/observability/features/masking),
[LangSmith OTel gateway redaction](https://docs.langchain.com/langsmith/otel-gateway-trace-redaction),
[Presidio](https://github.com/microsoft/presidio),
[Gitleaks vs TruffleHog benchmarks](https://appsecsanta.com/secret-scanning-tools/gitleaks-vs-trufflehog),
[secret detection tool study](https://arxiv.org/pdf/2307.00714),
[agent-sanitizer](https://pypi.org/project/agent-sanitizer/).

## 4. The binding technical constraint: spans are immutable at `on_end`

In the OpenTelemetry Python SDK, `SpanProcessor.on_end()` receives a `ReadableSpan`, which
is immutable. There is an open upstream issue asking for hooks to modify span content before
conversion to `ReadableSpan` (`opentelemetry-python#4424`), and the equivalent questions in
the Go and JS repositories reach the same answer: you cannot mutate the span in a processor.

The community-accepted approach is to **wrap the `SpanExporter`**: implement
`SpanExporter.export(spans)`, build sanitized replacements, and delegate to the real
exporter. This is why TraceShield's OTel integration is an exporter wrapper and not a span
processor, and it is recorded in ADR 0003.

Practical consequences the implementation must respect:

- Sanitization runs on the `BatchSpanProcessor` worker thread. It must be synchronous,
  deterministic, allocation-conscious, and must never perform network or disk I/O.
- Raising from `export()` degrades or breaks the caller's telemetry pipeline. The engine
  must never propagate an exception into the export path; on internal failure it fails
  closed by removing the value it could not prove safe.
- A replacement span must preserve identity — trace ID, span ID, parent, name, kind, start
  and end time, status, resource and instrumentation scope — or the backend will not stitch
  the trace together. Only attribute values, and event attribute values, may change.

Sources:
[opentelemetry-python#4424](https://github.com/open-telemetry/opentelemetry-python/issues/4424),
[opentelemetry-go discussion #2794](https://github.com/open-telemetry/opentelemetry-go/discussions/2794),
[opentelemetry-js discussion #2817](https://github.com/open-telemetry/opentelemetry-js/discussions/2817),
[SDK export docs](https://opentelemetry-python.readthedocs.io/en/latest/sdk/trace.export.html).

## 5. Why the audit record is a feature, not decoration

EU AI Act Article 12 requires high-risk AI systems to support automatic event logging that
makes system operation traceable; Article 19 sets a minimum six-month log retention period;
Article 18 requires providers to retain automatically generated logs for traceability and
accountability. Full enforcement lands 2026-08-02. GDPR separately expects traceable flows
for personal data.

That produces a requirement that is in direct tension with redaction: you must be able to
show what your system did, while not retaining the personal data it did it to.

A per-decision record — rule identifier, attribute key, JSON path within the payload,
detector, action taken, severity, and a salted hash of the removed value — satisfies both
sides. It proves a redaction happened, allows correlation of the same secret across traces
without storing it, and supports incident response ("this leaked credential appears in 41
spans between these timestamps") without keeping the credential.

No prior-art tool surveyed above emits such a record. This is TraceShield's clearest
differentiator and its most defensible resume claim.

Sources:
[EU AI Act audit-trail analysis](https://www.confident-ai.com/knowledge-base/guides/enterprise-ai-governance-audit-trails),
[Article 12 compliance logging discussion](https://github.com/langchain-ai/langchain/issues/35357).

## 6. Packaging and distribution facts

- `traceshield`, `trace-shield` and `traceshield-otel` all return 404 from the PyPI JSON
  API as of 2026-09-06, so the name is unclaimed.
- PyPI Trusted Publishing with GitHub Actions OIDC removes long-lived API tokens and
  produces Sigstore-backed provenance attestations automatically. Over 132,000 PyPI
  packages carried attestations as of March 2026.
- `id-token: write` is the required workflow permission; `hatchling` is a standard PEP 517
  backend and `hatch-vcs` can derive the version from git tags.

Sources:
[Why trusted publishing](https://pydevtools.com/handbook/explanation/why-use-trusted-publishing-for-pypi/),
[uv packaging guide](https://docs.astral.sh/uv/guides/package/),
[Python supply chain security](https://bernat.tech/posts/securing-python-supply-chain/).

## 7. Open questions carried into implementation

1. How much of the 72-attribute registry should the bundled policy enumerate explicitly
   versus matching by prefix? Explicit is auditable, prefix survives upstream churn. Current
   plan: explicit entries for the 14 content-bearing attributes, prefix fallback for the
   rest, both versioned in the policy file.
2. What is an acceptable p95 added latency per span? Must be measured, not asserted, before
   any performance claim appears in the README.
3. Blob parts are base64 binary. v0.1 will drop blob content rather than attempt to scan it;
   scanning encoded binary needs its own design.
4. Streaming and chunked span updates are out of scope for v0.1 and need a separate ADR.
5. GitHub's token checksum is documented as a base62-encoded CRC32 in the trailing six
   characters, but the blog post says only that it covers "the token" without stating
   whether the prefix is included. Determining this needs either an authoritative
   specification or a real token to test against. Until then GitHub tokens are matched on
   prefix and charset alone, which is unambiguous enough on its own.
