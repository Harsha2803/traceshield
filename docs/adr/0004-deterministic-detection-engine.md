# ADR 0004: Deterministic detection engine for v0.1

- Status: Accepted
- Date: 2026-09-06

## Context

Detection has to run synchronously on the telemetry export path, on a shared worker thread,
for every exported span. That environment rules out most of the accuracy techniques
available to an offline scanner.

The prior art surveyed in `Research.md` §3 splits cleanly. Secret scanners are rule-first
with entropy as a secondary signal and accept a triage queue: a published comparison found
370 and 635 false positives for two leading tools on the same corpus. PII frameworks such as
Presidio are extensible and NLP-backed, with reported out-of-the-box accuracy that needs
tuning and a spaCy model download.

## Decision

The v0.1 engine is deterministic and dependency-free, combining four signals:

1. **Pattern rules.** A versioned regex pack for named credential and identifier formats.
2. **Checksum verifiers.** Where a format carries a checksum, it is verified before the
   match is accepted: Luhn for payment cards, mod-97 for IBAN, Verhoeff for Aadhaar, and a
   base64url decode of the header for JWTs. A shape match that fails its checksum is not a
   finding.

   GitHub token CRC32 was considered and rejected. GitHub documents a base62-encoded CRC32
   in the trailing characters, but not precisely enough to determine which portion of the
   token it covers, and confirming a guess would require a real token. A verifier that
   silently rejected genuine tokens would be strictly worse than no verifier, so GitHub
   tokens are matched on their unambiguous prefix and charset.

   Verification interacts with greedy matching: if a quantifier absorbs one character too
   many, the checksum fails and a genuine value is exported intact. A property test found
   exactly that. Rules therefore declare how far they may retry shorter candidates, weighed
   against how easily the checksum passes by chance — Luhn accepts roughly one random input
   in ten, so a payment card retries only at separator boundaries, while IBAN's mod-97
   accepts roughly one in ninety-seven and can retry character by character.
3. **Shannon entropy.** Charset-aware thresholds for unnamed high-randomness strings,
   applied only to leaves that survive cheaper filters.
4. **Key-name heuristics.** In structured payloads, a key such as `api_key`, `password`,
   `token`, `secret`, `authorization` or `credential` raises the sensitivity of its subtree.
   This is what makes tool call arguments tractable, since their values are frequently
   opaque strings that no pattern would catch but whose key states the intent.

Confidence is a bounded value, raised by a passing checksum and by a corroborating key name,
and the policy maps rule ID plus confidence to an action. Detection is not a boolean.

ML and NER detection are deliberately excluded from v0.1 and remain a documented optional
extra for a later release, behind the `Detector` protocol so no core change is needed to add
one.

## Alternatives considered

**Ship the Presidio extra in v0.1.** Better recall on free-text names and addresses.
Rejected: it pulls spaCy and a model download into a security library's install, adds
material latency to a hot path, and roughly doubles the v0.1 test surface, for recall on a
category the target users mostly do not have in tool arguments. Deferred, not discarded.

**LLM-based classification of ambiguous spans.** Rejected outright. It is nondeterministic,
adds cost and latency to telemetry export, and sends the exact data TraceShield exists to
protect to another model provider.

**Entropy only, no named rules.** Rejected: unusable false-positive rate, and it produces
findings that name nothing, which defeats the audit record.

## Consequences

- Recall on implicit and contextual PII is limited. This is stated plainly in the README and
  in `ThreatModel.md` T1 rather than glossed over.
- The rule pack is a maintenance commitment. It is versioned, each rule carries a test with
  positive and negative fixtures, and every fixture is synthetic.
- Checksum verification is the main lever against alert fatigue and is what makes the default
  policy safe to enable. Its tests are non-negotiable acceptance criteria.
- Because detection is deterministic, the engine can be property-tested for idempotence and
  non-leakage, which an ML detector would not permit.
