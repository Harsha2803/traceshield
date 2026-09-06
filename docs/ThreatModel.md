# TraceShield Threat Model

Required by `CodingStandards.md` §10, which asks for threat-model notes whenever a change
introduces a new data source, execution capability, credential, network boundary or
sensitive-data store. TraceShield's entire purpose is to sit on such a boundary, so the
model is a standing document rather than a per-change note.

## 1. What TraceShield handles

Untrusted, potentially sensitive input in every case:

- span and event attribute values produced by instrumentation TraceShield does not control;
- serialized chat messages, tool call arguments and tool results, which may contain
  attacker-influenced content because model output and tool responses are untrusted;
- retrieved documents and agent memory records;
- a user-supplied policy document; and
- for the CLI, exported OTLP JSON files from the local filesystem.

## 2. Assets

1. The sensitive values themselves. These must not leave the process unredacted, must not
   appear in TraceShield's own logs, exceptions or findings, and must not be written to disk.
2. The redaction salt. Compromise turns value hashes into an offline dictionary attack
   against short or low-entropy values.
3. The audit record. Its value depends on being an accurate account of what happened.
4. The caller's telemetry pipeline availability. TraceShield sits in it and must not break it.

## 3. Trust boundaries

| Boundary | Direction | Control |
| --- | --- | --- |
| Instrumentation to TraceShield | in | Treat every attribute as hostile. Bound depth, node count and bytes before parsing. |
| Policy file to engine | in | Parse into a validated model, reject unknown fields, bound regex complexity. |
| TraceShield to wrapped exporter | out | Only sanitized values pass. Fail closed if sanitization did not complete. |
| TraceShield to its own logs | out | Structured events only. Never the value, never a long prefix of it. |
| CLI to filesystem | both | Read explicit paths only. Never write in place without an explicit flag. |

## 4. Threats and mitigations

**T1 — Sensitive value passes through undetected.** The core risk. Mitigated by
checksum-verified rules, entropy scoring, key-name heuristics that escalate whole subtrees,
a conservative default that scans unknown string attributes, and property tests. Accepted
residual: a deterministic engine cannot detect implicit identifiers such as a description
that uniquely identifies a person. This is stated in the README rather than papered over.

**T2 — Redaction destroys debuggability, so users disable TraceShield.** A real
availability threat to the control itself. Mitigated by structure-preserving redaction,
partial masking that keeps a safe prefix, and findings that name what was removed.

**T3 — Sensitive value leaks through TraceShield's own diagnostics.** Mitigated by invariant
3 in `Architecture.md`: no finding, log, exception or audit record carries the value.
Exceptions raised by the domain are constructed from rule IDs and paths only. Tested
adversarially, not just on the happy path.

**T4 — Malicious or pathological payload stalls or crashes the exporter.** A deeply nested
or enormous attribute, a decompression bomb, or catastrophic regex backtracking. Mitigated
by explicit depth, node-count and byte budgets checked before work is done, by rejecting
policy regexes with unbounded nested quantifiers, and by fail-closed handling that turns a
budget breach into a dropped value plus a finding rather than an exception.

**T5 — Salt compromise reverses value hashes.** Mitigated by requiring the salt to be
supplied by the caller from a secret manager or environment, never generated into a file,
never logged, never included in the audit record, and by documenting that hashes are
correlation identifiers rather than a confidentiality guarantee.

**T6 — Policy misconfiguration silently disables protection.** Mitigated by validating the
policy at load, failing fast on an invalid document, recording the policy version in every
audit record, and providing the CLI as a CI check so a regression in coverage is caught
before deployment.

**T7 — Supply-chain compromise of the published package.** Mitigated by Trusted Publishing
with OIDC rather than long-lived tokens, Sigstore attestations, pinned CI actions, a
dependency-free core, pip-audit in the gate, and a documented release process (ADR 0005).

**T8 — TraceShield is mistaken for a complete DLP control.** A documentation threat with
real consequences. Mitigated by stating limits plainly in the README and by the honest-gaps
requirement in `CodingStandards.md` §12.

## 5. Explicit non-goals

TraceShield does not defend against a compromised host, a malicious operator of the
destination platform, an attacker with the redaction salt and unlimited offline compute
against low-entropy values, or the observability vendor's own retention behaviour. It does
not protect model input from prompt injection.
