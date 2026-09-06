# TraceShield Tracker

The agenda. This file is the single source of truth for **what to work on next**.
[`prompt.txt`](../prompt.txt) is the bootstrap that points an agent here;
[`ProductBrief.md`](ProductBrief.md) is the source of truth for **what the product is**.

Rules for this file:

- Exactly one task carries the status `NEXT`. An agent picks that task and no other.
- A task moves to `DONE` only when its PR is merged, not when the code is written.
- Update this file in the same commit as the work it describes.
- Do not invent tasks to stay busy. If `NEXT` is empty, stop and ask the project owner.
- Acceptance criteria here are binding. Do not narrow them; if one is wrong, say so in the
  PR and get it changed rather than quietly skipping it.

Status values: `DONE`, `IN REVIEW` (PR open, not merged), `NEXT`, `PLANNED`, `BLOCKED`.

---

## Current position

| | |
| --- | --- |
| Milestone | v0.1.0 |
| Next task | **TS-005 — OpenTelemetry SanitizingSpanExporter** |
| Blocked on | PRs #1, #2 and #3 need merging by the owner before TS-005 branches cleanly |
| Last verified | 2026-09-06 |

---

## v0.1.0 — Sanitize a trace, prove what you removed

### TS-001 — Governance baseline · `DONE`

Cross-agent operating rules, coding standards, GitHub workflow, employment separation, PR
template and ignores. Established remote `main`.

Evidence: commit `1267fec`.

---

### TS-002 — Product brief, research and decision records · `IN REVIEW` (PR #1)

Problem statement, users, v0.1.0 boundary, eleven acceptance criteria, the research evidence
base, architecture, threat model, roadmap, open-source readiness checklist, ADRs 0001-0005.

Evidence: PR #1. Merge before TS-003.

---

### TS-003 — Core detection and redaction engine · `IN REVIEW` (PR #2)

The domain: bounded structure-preserving walk, 19-rule pattern pack, checksum verifiers,
entropy scoring, key-name escalation, redaction actions, findings, fail-closed behaviour.
Package scaffold and the full quality gate ship with it.

Evidence: PR #2. `make check` green; 249 tests, 99.64% coverage; CI green on Python
3.10-3.13. Merge after PR #1.

---

### TS-004 — Tracker and agent handoff system · `IN REVIEW` (PR #3)

This file, plus a `prompt.txt` that any agent can be started from by pasting its contents.

Evidence: PR #3. Merge after PR #2.

---

### TS-005 — OpenTelemetry `SanitizingSpanExporter` · `NEXT`

**Outcome.** A user adds one line to their OpenTelemetry setup and every exported span is
sanitized before it leaves the process:

```python
provider.add_span_processor(
    BatchSpanProcessor(SanitizingSpanExporter(OTLPSpanExporter(), sanitizer=sanitizer))
)
```

**Why an exporter and not a span processor.** `ReadableSpan` is immutable at `on_end`. This
is settled in ADR 0003 and is not open for reconsideration; read it before starting.

**Depends on.** TS-003.

**Acceptance criteria.**

1. `traceshield.otel.SanitizingSpanExporter` implements `SpanExporter`, wraps a delegate,
   and forwards `shutdown()` and `force_flush()` to it.
2. Span identity is byte-equal before and after: trace ID, span ID, parent, name, kind,
   start time, end time, status, links, resource attributes and instrumentation scope.
   This is `Architecture.md` invariant 2 and needs an explicit test.
3. Event attributes go through the same pipeline as span attributes, because the GenAI
   conventions put content in events.
4. Attributes the policy drops are removed from the exported span, not replaced with a
   placeholder.
5. `export()` never raises and never returns failure because of sanitization. A test injects
   a detector that throws and asserts the delegate still receives a span and the result is
   success.
6. A delegate that raises is not masked: its failure is the caller's failure, reported
   faithfully. Sanitization failures and delegate failures are distinguishable.
7. OpenTelemetry is an optional extra: `pip install traceshield` must not pull it in, and
   `import traceshield` must work without it. `traceshield[otel]` adds it.
8. The composition root reads `TRACESHIELD_HASH_SECRET` and fails fast with an actionable
   message when it is absent. The domain still receives the salt by injection.
9. Adapter coverage at least 80%; the repository gate stays green.
10. README gains a working OpenTelemetry quickstart, covered by a test the way the existing
    quickstart is.

**Files.** `src/traceshield/otel/__init__.py`, `exporter.py`, `attributes.py`;
`tests/otel/`; `pyproject.toml` optional-dependencies; `README.md`.

**Verification.** `make check`, plus a test that builds a real `ReadableSpan` via the SDK
rather than a mock, since the point is that the SDK's own type round-trips correctly.

**Notes.** Sanitization runs on the `BatchSpanProcessor` worker thread: synchronous, no I/O,
no logging of values. Do not add a performance claim; TS-007 measures that.

---

### TS-006 — Command line interface · `PLANNED`

**Outcome.** `traceshield scan trace.json` exits non-zero when unredacted sensitive values
are found, so it works as a CI check. `traceshield sanitize trace.json -o clean.json`
rewrites an exported OTLP JSON file.

**Depends on.** TS-003. Independent of TS-005.

**Acceptance criteria.**

1. `scan` reports findings as a table by default and as JSON with `--json`, and never prints
   a detected value.
2. `scan` exits 0 on a clean file and non-zero when any finding is produced.
3. `sanitize` writes to stdout or `-o`, and never modifies the input in place without an
   explicit `--in-place`.
4. Policy loading arrives here: `--policy policy.json` builds a `Policy` through a validated
   `Policy.from_mapping`, rejecting unknown fields and reporting the offending path. JSON
   only; the core stays dependency-free (ADR 0001).
5. Malformed input, an unreadable file and an invalid policy each produce a clear message and
   a distinct non-zero exit code; no stack trace crosses the boundary.
6. Fixtures are synthetic OTLP JSON committed under `tests/data/`.
7. Coverage at least 80% for the CLI; gate green.

**Files.** `src/traceshield/cli/`, `tests/cli/`, `pyproject.toml` `[project.scripts]`.

---

### TS-007 — Measured overhead benchmark · `PLANNED`

**Outcome.** A reproducible number for the latency TraceShield adds per span, with the
command, environment and raw result committed. Until this exists, no performance claim
appears anywhere in the repository.

**Depends on.** TS-005.

**Acceptance criteria.**

1. A benchmark script measuring per-span sanitization across representative payloads: a
   small chat span, a large tool result, a deeply nested document, and a clean span.
2. Results committed as an artifact recording the command, machine, Python version, package
   version and policy version.
3. The README states the measured number, or states nothing. No estimate, no "roughly".
4. Documented as needing a re-run whenever the pipeline changes, per
   `CodingStandards.md` section 12.

---

### TS-008 — Public-readiness documentation · `PLANNED`

**Outcome.** Every item in section 1 to 4 and 6 of
[`OpenSourceReadiness.md`](OpenSourceReadiness.md) is checked.

**Depends on.** TS-005, TS-006.

**Acceptance criteria.** `LICENSE` (Apache-2.0, unmodified), `NOTICE`, `CONTRIBUTING.md`,
`CODE_OF_CONDUCT.md`, `SECURITY.md`, `CHANGELOG.md` with a real 0.1.0 entry, and issue
templates including a rule-gap template that tells reporters never to paste the real secret
they found. Check the boxes in `OpenSourceReadiness.md` in the same PR.

---

### TS-009 — Release workflow · `PLANNED`

**Outcome.** Pushing a `v*` tag builds and publishes to PyPI with no stored credential.

**Depends on.** TS-008.

**Acceptance criteria.**

1. A release workflow with `id-token: write`, publishing via PyPI Trusted Publishing (ADR
   0005). No API token is created or stored anywhere.
2. Actions pinned by commit SHA, as in the CI workflow.
3. sdist and wheel built from a clean checkout with full git history so `hatch-vcs` derives
   the right version.
4. Attestations produced.
5. An installed-package smoke test that runs the README quickstart against the built wheel
   rather than the source tree.

---

### TS-010 — Publish 0.1.0 and make the repository public · `PLANNED`

**Depends on.** TS-005 through TS-009, and every box in `OpenSourceReadiness.md` sections
1 to 6.

**Acceptance criteria.** Confirm with the owner first — this is irreversible. Then: tag
`v0.1.0`, verify the release workflow published to PyPI, `pip install traceshield` in a
clean environment on each supported Python, run the README quickstart verbatim against the
installed package, then flip repository visibility and enable branch protection, private
vulnerability reporting, secret scanning and push protection.

---

## v0.2.0 — Meet users where they already are · `PLANNED`

Not scheduled. Do not start any of these while a v0.1.0 task is open.

- **TS-011** Langfuse `mask_otel_spans` adapter on the same engine. Its contract is already
  documented in `Research.md` section 3.
- **TS-012** Audit sink protocol and a JSONL implementation.
- **TS-013** `traceshield policy explain <value>`, showing which rule would fire and why.
- **TS-014** Policy inheritance and per-attribute overrides.
- **TS-015** Integration guides written against real running pipelines, not documentation.

## v0.3.0 — Recall where determinism is not enough · `PLANNED`

- **TS-016** Optional `traceshield[presidio]` extra behind the `Detector` protocol.
- **TS-017** Recall and false-positive comparison on a synthetic corpus, corpus and raw
  results committed.
- **TS-018** Base64 blob part handling, with an ADR.

## Under consideration, not scheduled

An OpenTelemetry Collector processor sharing the rule pack; reversible tokenization; metrics
and logs signals; streaming and chunk-level redaction. Each needs an ADR before any work.

---

## Definition of done

A task is done only when all of these hold. Copied from `CodingStandards.md` section 14 so
an agent does not have to go looking.

1. The agreed behaviour works end to end, with no placeholder, stub or fake integration.
2. `make check` passes locally and required CI is green.
3. Security and privacy implications are handled and stated in the PR.
4. Documentation, this tracker, `prompt.txt`, fixtures and any measured claim are current.
5. The branch is pushed under the verified personal account `Harsha2803`.
6. The PR exists, is out of draft, and CI is green.
7. The PR is merged.
8. Local `main` is fast-forwarded and the worktree is clean.

---

## Log

Newest first. One line per merged change; detail belongs in the PR and in Git.

| Date | Task | Change | Evidence |
| --- | --- | --- | --- |
| 2026-09-06 | TS-004 | Tracker and paste-and-go agent handoff | PR #3, open |
| 2026-09-06 | TS-003 | Core engine, package and quality gate | PR #2, open, CI green |
| 2026-09-06 | TS-002 | Brief, research, architecture, threat model, ADRs | PR #1, open |
| 2026-09-06 | TS-001 | Governance baseline, remote `main` established | `1267fec` |
