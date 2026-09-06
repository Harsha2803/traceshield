# ADR 0001: Python library and toolchain

- Status: Accepted
- Date: 2026-09-06

## Context

`AGENTS.md` and `prompt.txt` left the implementation stack undecided at bootstrap. The
approved product brief requires TraceShield to run inside the export path of an application
that is already emitting LLM telemetry, and to ship as an installable open-source package.

The OpenTelemetry Python SDK, every major LLM SDK, and every LLM observability client in the
target ecosystem are Python. A sanitizer that runs in-process must be in the same language
as the process it runs in.

`CodingStandards.md` §1 already specifies the Python toolchain defaults to use if Python is
selected, so selecting Python inherits a fully specified quality gate rather than requiring
one to be invented.

## Decision

TraceShield is a Python library distributed on PyPI as `traceshield`.

- Runtime support: Python 3.10 through 3.13. 3.10 is the floor because it is the oldest
  release still receiving security fixes and still widely deployed in ML environments;
  3.13 is the current ceiling under test.
- Build backend: `hatchling`, with `hatch-vcs` deriving the version from git tags.
- Environment and dependency management: `uv`, with a committed lockfile.
- Quality gate, all blocking: `ruff format --check`, `ruff check`, `mypy --strict`,
  `pytest` with coverage thresholds, `hypothesis` property tests, `bandit`, `pip-audit`,
  and a package build. One `make check` target runs the same commands CI runs.
- Line length 100, strict mypy, naive-datetime detection, blocking-in-async detection, and
  bans on stray `print` and commented-out code, as carried over in `CodingStandards.md`.

The `traceshield.core` package has no runtime dependencies. OpenTelemetry support is an
optional extra, `traceshield[otel]`, so that the core can be used by projects that are not
on OpenTelemetry and so that a security library does not force a dependency graph on its
users.

## Alternatives considered

**Rust core with Python bindings.** Faster detection and a single engine reusable from other
languages. Rejected for v0.1: it adds a build matrix, wheels for every platform, and a
contribution barrier, in exchange for performance that has not yet been shown to be a
bottleneck. Revisit only if a committed benchmark shows the pure-Python engine exceeding its
latency budget.

**Go, matching the OpenTelemetry Collector ecosystem.** Rejected: the collector is
explicitly not the insertion point (ADR 0003), and the target users write Python.

**Poetry or plain pip-tools instead of uv.** Rejected: uv covers locking, environments and
publishing with OIDC in one tool, which keeps the contributor setup to a single command.

## Consequences

- The performance ceiling is CPython's. The engine must be written with that in mind:
  compile once, short-circuit early, avoid per-leaf allocation where practical.
- The dependency-free core constrains detector implementations to the standard library.
  Checksum verifiers and entropy scoring are cheap to write; NER is not, which reinforces
  ADR 0004.
- A published Python package on PyPI creates a supply-chain surface, handled in ADR 0005 and
  threat T7 of `ThreatModel.md`.
