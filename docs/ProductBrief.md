# TraceShield Product Brief

Status: approved 2026-09-06 by the project owner. This is the canonical statement of what
TraceShield is and what the first release must do. Evidence for every claim about the
problem space is in [`Research.md`](Research.md). Foundational choices are recorded as ADRs
in [`adr/`](adr/).

## 1. One-line definition

TraceShield is an open-source Python library that sanitizes LLM and agent telemetry inside
the export path, before it reaches an observability platform. It detects and redacts
secrets, PII and sensitive tool arguments while preserving trace structure, and records an
auditable decision for every redaction it makes.

## 2. The problem

Teams instrumenting LLM and agent applications face a binary choice today.

Turn GenAI content capture off, and traces contain a model name, token counts and a latency
number. You cannot debug why an agent called the wrong tool, why a RAG answer was wrong, or
what a prompt-injection attempt actually said.

Turn content capture on, and prompts, completions, tool call arguments, tool results,
retrieved documents and agent memory are shipped verbatim to a third-party observability
vendor, where they are indexed, retained under that vendor's policy and often stored in
another jurisdiction. Upstream OpenTelemetry marks eleven `gen_ai.*` attributes as possibly
containing sensitive information for exactly this reason.

In practice the payload is worse than personal data alone. Tool arguments routinely contain
API keys, database connection strings, bearer tokens and internal endpoints, because that is
what tools take as parameters. A trace store is a credential store nobody threat-modelled.

The existing mitigations are all partial, and [`Research.md`](Research.md) documents where
each one stops:

- The OpenTelemetry Collector `redactionprocessor` treats an attribute as opaque text, so it
  cannot redact one text part inside a serialized chat message without destroying the
  message structure. It also needs a deployed collector and leaves no audit trail.
- Vendor masking hooks such as Langfuse's `mask_otel_spans` give you a seam but no
  detectors, no policy and no decision record, and only for that vendor.
- PII libraries redact text; secret scanners scan repositories offline. Neither models a
  span, a policy or an export-path latency budget.

## 3. Who it is for

1. **The platform or ML engineer** who owns the observability pipeline for an LLM product
   and has been asked to turn content capture on without leaking customer data. Wants one
   line of code, not a collector deployment.
2. **The security or compliance engineer** who has to answer "what personal data leaves our
   boundary, and prove what you removed". Wants an auditable decision record, not a promise.
3. **The open-source agent developer** who wants safe defaults in a notebook or a small
   service and will not stand up infrastructure at all.

## 4. What TraceShield is not

- Not an observability platform. It has no storage, no UI and no query layer. It makes
  whatever platform you already use safe to send data to.
- Not a prompt-injection or model-safety guard. It protects telemetry flowing *out*, not
  model input flowing *in*.
- Not a replacement for the OpenTelemetry Collector. It is complementary and runs earlier,
  in the process that produced the data, so sensitive values never cross the network at all.
- Not a data-loss-prevention suite. It has a narrow, testable job.

## 5. Product principles

1. **Structure survives redaction.** A redacted trace must remain debuggable and must still
   render in the destination UI. Roles, part types, tool names, object keys, array lengths
   and JSON shape are preserved; only sensitive leaf values change.
2. **Every decision is recorded.** A redaction that leaves no evidence is indistinguishable
   from data loss. Each redaction emits a finding with rule, path, action and a salted hash
   of what was removed.
3. **Fail closed, never fail loudly.** The engine runs inside someone else's export path. It
   must never raise into that path, and when it cannot prove a value safe it removes it.
4. **Deterministic by default.** Same input, same policy, same salt gives the same output.
   No model downloads, no network calls, no hidden nondeterminism in the hot path.
5. **The policy is the product.** Detection rules and attribute handling live in a
   versioned, reviewable policy document, not scattered through code.

## 6. MVP boundary (v0.1.0)

### In scope

- A deterministic detection engine: versioned regex rule pack, checksum verifiers, Shannon
  entropy scoring, and key-name heuristics. Pure Python, no runtime dependencies in the core.
- Structure-preserving redaction that walks strings, byte strings, JSON-encoded strings,
  mappings and sequences to a bounded depth and size, and replaces only detected spans.
- A typed, validated policy model with a bundled default policy covering the fourteen
  content-bearing `gen_ai.*` attributes and the `mcp.*` attributes identified in research.
- Redaction actions: mask, partial mask, hash, and drop.
- Findings and an audit record for every decision.
- A drop-in `SanitizingSpanExporter` that wraps any OpenTelemetry `SpanExporter`.
- A CLI that scans and sanitizes exported OTLP JSON files offline, exiting non-zero when
  unredacted sensitive values are found, so it is usable in CI.
- Fail-closed behaviour with explicit time, depth and size budgets.

### Out of scope for v0.1.0

- NER and ML-based detection. Presidio and similar remain a documented optional extra for a
  later release (ADR 0004).
- A collector, proxy or sidecar deployment mode.
- Metrics and logs signals. Traces only.
- Reversible tokenization or format-preserving encryption.
- Vendor-specific adapters beyond generic OpenTelemetry, including the Langfuse
  `mask_otel_spans` adapter, which is planned for v0.2.
- Scanning inside base64 blob parts. v0.1 drops blob content instead.
- Streaming or chunk-level redaction.
- Scanning non-string leaves. A number is left alone rather than replaced, because swapping
  a number for a placeholder changes the node's type and breaks consumers that validate the
  payload against its schema. An identifier stored as a JSON number is therefore missed.

## 7. Acceptance criteria for v0.1.0

The release ships only when all of these are demonstrably true, with committed evidence.

1. Given an OpenTelemetry span whose `gen_ai.input.messages` attribute holds a serialized
   chat message list containing an AWS access key inside a `TextPart`, exporting through
   `SanitizingSpanExporter` produces a span in which the message list still parses, still
   has the same roles, part count and part types, and the key is replaced by a placeholder
   naming the rule that fired.
2. All fourteen content-bearing attributes identified in `Research.md` §1 are handled by the
   bundled default policy, and a test asserts the policy covers each of them by name.
3. Span identity is preserved through sanitization: trace ID, span ID, parent, name, kind,
   start and end time, status, resource attributes and instrumentation scope are byte-equal
   before and after.
4. The engine never raises into the export path. A test injects a detector that throws and
   asserts the value is dropped, a finding is recorded, and `export()` still succeeds.
5. Property tests establish that sanitization is idempotent, that no substring of a detected
   secret longer than a configured threshold survives in the output, and that JSON structure
   is preserved.
6. Checksum-verified rules reject values that match the shape but fail the checksum, proven
   by tests for Luhn, IBAN mod-97 and Verhoeff. GitHub token CRC32 was dropped from this
   criterion: the scheme is documented as a base62-encoded CRC32 in the trailing characters
   but not precisely enough to know which portion it covers, and confirming a guess would
   need a real token. A verifier that silently rejected genuine tokens would be worse than
   none, so GitHub tokens are matched on their unambiguous prefix and charset instead.
7. `traceshield scan <file>` exits non-zero on a fixture containing an unredacted secret and
   zero on its sanitized counterpart.
8. Every redaction emits a finding carrying rule ID, attribute key, JSON path, action,
   severity and a salted hash, and no finding ever contains the original value.
9. The aggregate quality gate passes: format, lint, strict mypy, tests, Bandit, pip-audit
   and build. Coverage is at least 90% for `traceshield.core` and 80% for adapters.
10. Added export latency is measured by a committed benchmark, with the command, environment
    and raw result artifact in the repository. The README states the measured number or
    states nothing.
11. The package installs from PyPI as `traceshield` and the documented quickstart runs
    verbatim against that installed package.

## 8. Success measures

Judged at 90 days after the v0.1.0 release:

- The quickstart works unmodified for a user who has never seen the repository.
- At least one integration guide exists for a real destination platform, written against a
  running pipeline rather than from documentation.
- Measured added latency per span stays within the budget recorded in the benchmark artifact.
- No issue reports a redacted trace that became undebuggable, and no issue reports a secret
  that passed through the default policy.

## 9. Milestones

See [`Roadmap.md`](Roadmap.md). v0.1.0 is the only committed milestone; later entries are
intent, not promises.
