# TraceShield

TraceShield sanitizes LLM and agent telemetry before it reaches an observability platform.
It detects and redacts secrets, PII and sensitive tool arguments while preserving trace
structure, and records an auditable decision for every redaction it makes.

It is being built as an open-source Python package, distributed on PyPI as `traceshield`
under Apache-2.0.

**Status: pre-release, in development. Nothing is published yet and no behaviour described
in the brief is implemented.** The repository currently contains governance, the approved
product brief, the architecture and threat model, and the decision records behind them.
Follow [`docs/Roadmap.md`](docs/Roadmap.md) for what is committed.

## Why

Instrumenting an LLM application forces a bad choice. Leave GenAI content capture off and a
trace tells you the model, the token count and the latency — useless for debugging a wrong
tool call or a bad RAG answer. Turn it on and prompts, completions, tool arguments, tool
results and retrieved documents are shipped verbatim to a third-party store. Upstream
OpenTelemetry marks eleven `gen_ai.*` attributes as possibly containing sensitive
information for that reason.

Tool arguments are the sharpest edge: they routinely carry API keys, connection strings and
bearer tokens, because that is what tools take as parameters. A trace store quietly becomes
a credential store.

TraceShield removes the choice. It runs in-process, in the export path, understands the
structure of GenAI span payloads, redacts the sensitive leaves while keeping the shape, and
emits a record of what it did.

## Where to start reading

| Document | What it answers |
| --- | --- |
| [`docs/ProductBrief.md`](docs/ProductBrief.md) | What TraceShield is, who it is for, the v0.1.0 boundary and acceptance criteria |
| [`docs/Research.md`](docs/Research.md) | The evidence base: what telemetry actually carries, what already exists and where it stops |
| [`docs/Architecture.md`](docs/Architecture.md) | Module structure, domain model, the pipeline and its invariants |
| [`docs/ThreatModel.md`](docs/ThreatModel.md) | Trust boundaries, threats, mitigations and explicit non-goals |
| [`docs/adr/`](docs/adr/) | Why the stack, license, integration surface, detection approach and release process are what they are |
| [`docs/Roadmap.md`](docs/Roadmap.md) | What is committed and what is only intent |
| [`docs/OpenSourceReadiness.md`](docs/OpenSourceReadiness.md) | The checklist that gates making this repository public |

## Contributing

Not open for contributions yet; the repository is private until v0.1.0 (ADR 0005).

Working in this repository — human or agent — starts with [`prompt.txt`](prompt.txt), then
[`AGENTS.md`](AGENTS.md), [`docs/CodingStandards.md`](docs/CodingStandards.md) and
[`docs/GitHubWorkflow.md`](docs/GitHubWorkflow.md). Those files are canonical.
