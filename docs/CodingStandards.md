# Coding Standards

Rules, not suggestions. Everything here should be machine-enforced where practical; the
rest is review policy. These standards carry forward Mnemos's engineering discipline while
leaving TraceShield's product scope and implementation stack undecided.

## 1. Toolchain and quality gate

Maintain one aggregate local command that mirrors CI. It must include formatting, lint,
strict type checking, tests, security/dependency checks, and a production build where the
selected stack supports them. A pull request is blocked when any gate fails.

If Python is selected, the default toolchain is:

- Ruff for formatting and linting, including datetime, async, security, stray-print, and
  commented-code rules;
- mypy in strict mode; explicit `Any` requires a written boundary justification;
- pytest and pytest-asyncio with strict configuration;
- Hypothesis for pure policy logic and parsers with meaningful invariants;
- Testcontainers for adapters that depend on real databases or queues;
- Bandit and pip-audit for static and dependency security checks; and
- Alembic for schema changes, including a tested downgrade.

Python defaults are version-specific only after the runtime is selected. Preserve the
Mnemos defaults of a 100-character line length, strict mypy, naive-datetime detection,
blocking-in-async detection, and bans on stray `print` and commented-out code.

If TypeScript is selected, use strict TypeScript, linting, deterministic formatting, unit
tests, dependency auditing, and a production build as blocking gates. Commit lockfiles and
use clean, reproducible dependency installation in CI.

Do not add redundant tools that enforce the same rule. Document exact versions and commands
in repository configuration when the stack is chosen.

## 2. Types and domain models

- Type every public API and internal boundary. Do not use dictionaries of `Any` as domain
  models.
- Parse untrusted data at the boundary into explicit validated models.
- Prefer immutable domain models. Reject unknown fields for security-relevant inputs.
- Use distinct identifier types rather than interchangeable strings or UUIDs when mixing
  them could cause a security or data-integrity defect.
- Put scalar invariants such as non-negative durations, bounded scores, and byte limits in
  validated types rather than repeating checks at call sites.
- Model state and outcomes explicitly. Avoid boolean parameters and nullable combinations
  that permit invalid states.

An escape hatch such as `Any`, an unchecked cast, or a lint suppression must be narrow and
carry a comment explaining why the boundary cannot be typed safely.

## 3. Architecture and dependencies

- Keep domain policy independent of web frameworks, databases, vendors, and LLM SDKs.
- Depend on small interfaces or protocols at boundaries; inject concrete adapters at a
  single composition root.
- Constructor-inject clocks, identifiers, external clients, and other nondeterministic
  dependencies. Do not reach for global time, random values, or network clients in domain
  code.
- Make ownership of transactions, retries, timeouts, and idempotency explicit. Exactly one
  layer owns each policy.
- Keep modules cohesive and dependencies one-directional. Add automated architecture
  boundary checks once the module structure exists.
- Add an ADR before introducing or replacing a foundational database, framework, broker,
  model provider, deployment platform, or trust boundary.

Prefer the smallest architecture that solves the agreed problem. Complexity must correspond
to a demonstrated requirement, not to resume decoration.

## 4. Async and external calls

- Keep asynchronous request paths async all the way down. Never perform blocking file,
  network, database, SDK, or inference work on the event loop.
- Put CPU-bound work in an explicit thread or process pool and measure it.
- Use structured concurrency; do not launch fire-and-forget tasks whose lifecycle and
  exceptions are unowned.
- Every external call has an explicit timeout and a defined cancellation policy.
- Retries require bounded attempts, backoff with jitter, retryable-error classification,
  and an idempotency analysis. Do not stack retries at multiple layers.
- Background jobs need durable state, idempotency keys, visible failure, and recovery rules.

## 5. Errors and degradation

Treat expected domain outcomes differently from unexpected bugs or infrastructure faults.
Expected failures use typed results or stable domain errors; unexpected failures propagate
as exceptions rooted in a project-specific exception hierarchy.

- Never swallow exceptions.
- A tolerated failure must be recorded with structured context and its impact must be
  visible to the caller when it changes the result.
- Public errors are stable, actionable, and non-leaking. Logs hold diagnostic context.
- Never expose stack traces, filesystem paths, SQL fragments, credentials, provider payloads,
  or internal exception messages across an API boundary.
- Preserve exception causes and distinguish retryable from terminal failures.

Silent fallback is prohibited because it makes incorrect output appear successful.

## 6. Data access and migrations

- Repositories return domain models, not live ORM/session objects.
- Transactions are owned by the application/use-case layer so related writes can be atomic.
- Parameterize every query. Parse or allowlist user-influenced identifiers that cannot be
  parameterized.
- Prevent N+1 access with batching or joins and prove important query-count expectations in
  integration tests.
- If multi-tenancy is introduced, every query must scope the tenant explicitly even when
  database row-level security also applies. Authorization must fail closed.
- Enforce critical invariants in both application logic and database constraints.
- Every schema change has a migration, a tested downgrade where technically possible, and a
  drift check in CI. Never mutate an already-shipped migration.
- Store timestamps in UTC with timezone awareness. Define retention and deletion semantics
  for trace data before persisting it.

Use real datastore instances for adapter tests. Mocking an ORM session tests the mock rather
than the query, transaction, and constraint behavior that can actually fail.

## 7. APIs and contracts

- Validate request and response schemas at entrypoints. Reject unknown or malformed input.
- Use stable machine-readable error codes and standard status semantics.
- Define pagination, ordering, size limits, timeouts, and idempotency for endpoints that need
  them. Never leave collections unbounded.
- Version externally consumed contracts deliberately and test compatibility.
- Generate clients and schema artifacts from one source of truth; never hand-edit generated
  output.
- Apply authentication, authorization, rate limits, and request-size limits at explicit
  boundaries. Authentication must never imply authorization.

## 8. Configuration and secrets

- Validate configuration at startup and fail fast. Use a single typed settings boundary.
- Use the `TRACESHIELD_` prefix for application environment variables unless an ADR changes
  it.
- Tunable values are named configuration with documented defaults and units. Do not scatter
  unexplained magic numbers through implementation code.
- Secrets are never committed, embedded in defaults, printed, included in exception text, or
  logged. Example environment files contain keys with empty or unmistakably fake values.
- Use least-privilege credentials per service and separate migration ownership from runtime
  database access when a database is introduced.
- Validate production safety settings separately from local-development convenience.

## 9. Logging, telemetry, and trace privacy

Use structured logs with stable event names and bound request/trace correlation. Event names
follow `noun.verb_past`; values belong in fields rather than interpolated messages.

Never log or persist by default:

- credentials, API keys, cookies, authorization headers, or session tokens;
- raw prompts, responses, tool arguments, or trace payloads containing user data;
- PII or customer identifiers not required for the stated purpose;
- full SQL with literal values; or
- local filesystem paths and exported diagnostic files.

Redaction is a defense-in-depth processor, not permission to collect sensitive data. Test
redaction against nested objects, arrays, encoded values, streaming chunks, malformed input,
and new integration payloads. Preserve enough metadata to debug behavior without preserving
the sensitive content itself.

Log levels: debug for local diagnostics, info for meaningful state changes, warning for
degradation, error when human attention is needed, and critical when integrity is at risk.
Metrics must avoid unbounded-cardinality labels.

## 10. Security

- Deny by default at every trust boundary and grant the minimum necessary capability.
- Treat traces, prompts, model output, retrieved documents, tool responses, and webhook
  payloads as untrusted input.
- Protect outbound fetches against SSRF, DNS rebinding, unsafe redirects, and access to local
  or cloud-metadata addresses.
- Verify webhook authenticity before parsing or enqueuing work.
- Bound decompression, parsing depth, payload size, fan-out, token use, and execution time.
- Keep audit records tamper-evident enough for the stated threat model, while minimizing
  sensitive content.
- Pin dependencies, review automated upgrades, and block known exploitable vulnerabilities
  according to a documented policy.
- Add threat-model notes or an ADR whenever a change introduces a new data source, execution
  capability, credential, network boundary, or sensitive-data store.

Security controls need adversarial tests, not only happy-path tests.

## 11. Testing

Use the smallest test that proves the behavior, backed by realistic integration coverage:

- unit tests for pure domain rules, edge cases, and invariants;
- property tests for parsers, redactors, budgets, ordering, and other broad input spaces;
- integration tests against real databases, queues, and provider-compatible boundaries;
- contract tests for every external API surface;
- end-to-end tests for critical user journeys; and
- performance tests for measured resume claims, run outside the per-PR fast path when needed.

Preserve the Mnemos coverage expectations as starting gates: 90% for domain policy and 80%
for adapters, while prioritizing meaningful branch and invariant coverage over a vanity
repository-wide percentage.

- Do not mock code owned by the repository. Fake at ports; use real adapters where their
  semantics matter.
- Every defect gets a failing regression test before or with the fix.
- Tests must be deterministic, isolated, order-independent, and safe to run in parallel.
- Freeze or inject clocks, randomness, identifiers, and model/provider responses.
- Do not weaken, skip, or delete a test merely to make a gate pass without documenting and
  resolving the underlying mismatch.

## 12. Documentation and evidence

- Public functions and non-obvious modules document why they exist and why their decisions
  are surprising; do not restate signatures.
- Keep setup commands executable and documentation consistent with the current repository.
- Record durable architecture decisions in ADRs with context, alternatives, consequences,
  and status. Supersede decisions explicitly instead of silently deviating.
- Track known gaps honestly. Do not describe planned behavior as shipped.
- Re-run benchmarks whenever their code path, corpus, environment, or dependency changes.
  Commit the command, environment, raw result artifact, and summarized claim together.
- Never manufacture performance, accuracy, security, cost, or scale claims.

## 13. Frontend, if introduced

- Use strict types at API and component boundaries; avoid duplicated server contract types.
- Define reusable design tokens instead of scattering colors, spacing, typography, and
  radii through components.
- Meet keyboard, focus, semantic HTML, contrast, reduced-motion, loading, empty, and error
  state requirements.
- Test behavior with accessible queries and exercise critical browser journeys end to end.
- Ship the usable screen or developer interface with the backend capability it exposes.

The interface exists to make the system observable and useful; visual polish does not
substitute for working backend behavior.

## 14. Commits, pull requests, and completion

Use Conventional Commits scoped by capability. Every PR must pass all gates, update docs
when behavior changes, add an ADR for architectural decisions, and include compatible schema
migrations when persistence changes.

A task is complete only when:

1. the agreed behavior works end to end;
2. relevant automated tests and the full repository gate pass;
3. security and privacy implications have been handled;
4. documentation, status, fixtures, generated output, and measured claims are current;
5. the scoped branch is pushed under the verified personal account;
6. its PR exists, is out of draft, and required CI is green;
7. the PR is merged using the established repository strategy; and
8. local `main` is fast-forwarded and the worktree is clean.

Follow `docs/GitHubWorkflow.md` for the exact identity and push preflight.
