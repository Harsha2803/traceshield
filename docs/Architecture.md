# TraceShield Architecture

Companion to [`ProductBrief.md`](ProductBrief.md). Records the intended module structure,
the domain model and the invariants the implementation must hold. Decisions that were
genuinely contested are ADRs; this document is the design that follows from them.

## 1. Shape

Hexagonal, as required by `CodingStandards.md` §3. The domain knows nothing about
OpenTelemetry, any vendor SDK, the filesystem or the clock.

```
traceshield/
  core/                  pure domain. no I/O, no third-party imports, no OTel
    model.py             Finding, Decision, Action, Severity, RuleId, Confidence
    policy.py            Policy, AttributeRule, DetectorRule; validation and loading
    detectors/
      base.py            Detector protocol and DetectionSpan
      patterns.py        regex rule pack, compiled once per policy
      verifiers.py       Luhn, IBAN mod-97, GitHub CRC32, Verhoeff
      entropy.py         Shannon entropy scoring with charset-aware thresholds
      keyname.py         key-name heuristics for structured payloads
    walk.py              bounded structure-preserving traversal
    redact.py            mask, partial, hash, drop
    engine.py            Sanitizer: the one public entry point of the domain
    audit.py             AuditRecord and the sink protocol
    errors.py            exception hierarchy
  policies/
    default.yaml         bundled versioned default policy
  otel/                  adapter
    exporter.py          SanitizingSpanExporter
    attributes.py        OTel attribute value <-> domain value marshalling
  cli/                   adapter
    main.py              scan and sanitize subcommands
```

Dependency direction is strictly inward. `otel/` and `cli/` may import `core/`; `core/` may
import nothing from them. An import-boundary test enforces this once the packages exist.

## 2. Domain model

`Finding` is the unit of evidence. It is immutable and must never carry the original value.

```
Finding
  rule_id: RuleId                 which rule fired, e.g. "secret.aws.access_key_id"
  category: Category              SECRET | PII | CREDENTIAL_MATERIAL | IDENTIFIER
  severity: Severity              LOW | MEDIUM | HIGH | CRITICAL
  confidence: Confidence          bounded 0.0-1.0, raised by a passing checksum
  attribute_key: str              e.g. "gen_ai.input.messages"
  path: JsonPath                  location within the parsed payload
  action: Action                  MASK | PARTIAL | HASH | DROP
  value_hash: ValueHash           salted digest of what was removed
  detector: str                   which detector produced it
```

`Decision` pairs a finding with the policy rule that selected the action, so an auditor can
reconstruct why a given action was taken from a given policy version.

`Policy` is validated at load, rejects unknown fields, and carries a `version` that is
recorded in every audit record. Scalar invariants — confidence bounds, byte limits,
non-negative budgets — live in the validated types rather than in call-site checks.

## 3. The sanitization pipeline

For one attribute value:

1. **Classify.** Look up the attribute key in the policy. Outcome is `keep`, `drop`, or
   `scan`. Unknown keys resolve through prefix rules, then the policy default. The default
   for content-bearing prefixes is `scan`; the global default is configurable and ships as
   `scan` for strings and `keep` for numerics.
2. **Parse.** If the value is a string that parses as JSON and the policy says the attribute
   is structured, parse it. Parsing is bounded by max depth, max node count and max bytes,
   and a bound breach is itself a finding that fails the value closed.
3. **Walk.** Traverse the parsed structure. At every node, key-name heuristics can raise the
   sensitivity of the subtree. Leaves reach the detectors.
4. **Detect.** Run detectors over each leaf. Detectors return non-overlapping
   `DetectionSpan`s with a rule ID and confidence. Overlaps are resolved by
   highest-confidence-then-longest-span, deterministically.
5. **Decide.** The policy maps rule ID and confidence to an action.
6. **Redact.** Apply the action to the leaf, leaving structure intact.
7. **Record.** Emit one finding per applied decision, and re-serialize the structure in the
   same form it arrived in.

Idempotence matters: the output of step 7 fed back into step 1 must produce no new findings.
Placeholders are therefore chosen so that they cannot themselves match any bundled rule.

## 4. Invariants

These are the assertions tests must hold, not aspirations.

1. **Structure preservation.** For a structured payload, the sanitized output parses, and
   its shape — object keys, array lengths, node types — is identical to the input's.
2. **Identity preservation.** A sanitized span is byte-equal to the original in trace ID,
   span ID, parent, name, kind, start time, end time, status, links, resource attributes and
   instrumentation scope.
3. **No leakage into evidence.** No `Finding`, log line, exception message or audit record
   contains any substring of a detected value beyond a configured safe prefix length.
4. **Idempotence.** `sanitize(sanitize(x)) == sanitize(x)` for every policy.
5. **Fail closed.** Any internal error, budget breach, or detector exception results in the
   value being removed and a finding recorded. `export()` still returns success.
6. **No I/O in the hot path.** The domain performs no network, disk or clock access.
   Salt and time are constructor-injected.
7. **Determinism.** Given the same policy version, salt and input, the output and the ordered
   findings are identical.

## 5. The OpenTelemetry adapter

`ReadableSpan` is immutable at `on_end`, so redaction cannot happen in a `SpanProcessor`.
TraceShield wraps the exporter instead; the reasoning and sources are in ADR 0003 and
`Research.md` §4.

```python
provider.add_span_processor(
    BatchSpanProcessor(
        SanitizingSpanExporter(OTLPSpanExporter(), policy=Policy.default())
    )
)
```

`SanitizingSpanExporter.export(spans)` builds a sanitized replacement for each span,
delegates to the wrapped exporter, and forwards `shutdown` and `force_flush`. It runs on the
`BatchSpanProcessor` worker thread, so it is synchronous and non-blocking by construction.
Span events carry attributes too, and the GenAI conventions put content in events, so event
attributes go through the same pipeline as span attributes.

The same core engine backs the CLI and will back a Langfuse `mask_otel_spans` adapter in
v0.2, whose contract — read-only snapshot in, sparse attribute patch out, deterministic, no
I/O — the engine already satisfies.

## 6. Performance stance

Sanitization runs per exported span on a shared worker thread, so the cost is real and must
be measured rather than assumed. The controls are: compile regexes once per policy and cache
by policy version; short-circuit attributes the policy marks `keep`; apply entropy scoring
only to leaves that survive cheaper filters; and bound depth, node count and bytes so a
pathological payload cannot stall the exporter.

No performance number appears in the README, the package description or anywhere else until
a committed benchmark produces it, and it is re-measured whenever the pipeline changes.

## 7. Deliberately deferred

Reversible tokenization, format-preserving encryption, blob-content scanning, streaming
redaction, metrics and logs signals, and any ML detector. Each needs its own ADR when its
time comes.
