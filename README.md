# TraceShield

TraceShield sanitizes LLM and agent telemetry before it reaches an observability platform.
It detects and redacts secrets, PII and sensitive tool arguments while preserving trace
structure, and records an auditable decision for every redaction it makes.

It is being built as an open-source Python package, distributed on PyPI as `traceshield`
under Apache-2.0.

**Status: pre-release, in development. Not published to PyPI yet.**

Working today: the core detection and redaction engine. It sanitizes attribute values,
including the nested JSON payloads that GenAI span attributes carry, and returns an
auditable finding for every redaction.

Not built yet: the `SanitizingSpanExporter` that plugs this into an OpenTelemetry pipeline,
and the CLI. Both are committed for v0.1.0 — see [`docs/Roadmap.md`](docs/Roadmap.md).

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

## What it does

```python
import json
import os

from traceshield import Policy, Sanitizer, ValueHasher

sanitizer = Sanitizer(
    policy=Policy.default(),
    hasher=ValueHasher.from_secret(os.environ["TRACESHIELD_HASH_SECRET"]),
)

messages = [
    {
        "role": "assistant",
        "parts": [
            {"type": "text", "content": "rotating with AKIAIOSFODNN7EXAMPLE"},
            {
                "type": "tool_call",
                "name": "rotate_key",
                "arguments": {"api_key": "9f2c4a7b1e8d", "region": "eu-west-1"},
            },
        ],
    }
]

result = sanitizer.sanitize_attribute("gen_ai.input.messages", json.dumps(messages))
print(json.dumps(json.loads(str(result.value)), indent=2))
for finding in result.findings:
    print(finding.rule_id, finding.path, finding.action.value)
```

The trace keeps its shape. The role, the part types, the tool name and the region are all
still there, so the span is still worth reading:

```json
[
  {
    "role": "assistant",
    "parts": [
      {
        "type": "text",
        "content": "rotating with [redacted:secret.aws.access_key_id]"
      },
      {
        "type": "tool_call",
        "name": "rotate_key",
        "arguments": {
          "api_key": "[redacted:secret.generic.sensitive_key]",
          "region": "eu-west-1"
        }
      }
    ]
  }
]
```

```text
secret.aws.access_key_id /0/parts/0/content mask
secret.generic.sensitive_key /0/parts/1/arguments/api_key mask
```

The second finding is the interesting one. `9f2c4a7b1e8d` matches no credential pattern and
carries little entropy — nothing about the value marks it as a secret. The key does. Tool
arguments are where agent telemetry leaks credentials, and they are also where pattern
matching alone is weakest.

Every finding is safe to keep: it names the rule and the location, and carries a salted
digest of what was removed rather than the value itself.

### Known limitations

- Deterministic detection cannot find implicit or contextual PII, such as a description that
  uniquely identifies a person without naming them.
- Non-string leaves are not scanned. An identifier stored as a JSON number is missed, because
  replacing it with a placeholder would change the node's type.
- Base64 blob parts are not scanned.
- Entropy scoring skips paths, URLs and dotted names to avoid flooding on ordinary tool
  arguments, so an unnamed base64 secret containing several slashes can be missed unless a
  named rule or its key name catches it.
- These are limits of the v0.1 design, not bugs. See
  [`docs/ThreatModel.md`](docs/ThreatModel.md).

## Where to start reading

| Document | What it answers |
| --- | --- |
| [`docs/Tracker.md`](docs/Tracker.md) | The agenda: every task, its acceptance criteria, and the one marked `NEXT` |
| [`docs/ProductBrief.md`](docs/ProductBrief.md) | What TraceShield is, who it is for, the v0.1.0 boundary and acceptance criteria |
| [`docs/Research.md`](docs/Research.md) | The evidence base: what telemetry actually carries, what already exists and where it stops |
| [`docs/Architecture.md`](docs/Architecture.md) | Module structure, domain model, the pipeline and its invariants |
| [`docs/ThreatModel.md`](docs/ThreatModel.md) | Trust boundaries, threats, mitigations and explicit non-goals |
| [`docs/adr/`](docs/adr/) | Why the stack, license, integration surface, detection approach and release process are what they are |
| [`docs/Roadmap.md`](docs/Roadmap.md) | What is committed and what is only intent |
| [`docs/OpenSourceReadiness.md`](docs/OpenSourceReadiness.md) | The checklist that gates making this repository public |

## Development

```bash
make setup    # install the locked environment with uv
make check    # the full gate: format, lint, strict types, tests, security, audit, build
```

`make check` runs exactly what CI runs. A pull request is blocked when any part of it fails.

## Contributing

Not open for contributions yet; the repository is private until v0.1.0 (ADR 0005).

Working in this repository — human or agent — starts with [`prompt.txt`](prompt.txt), then
[`AGENTS.md`](AGENTS.md), [`docs/CodingStandards.md`](docs/CodingStandards.md) and
[`docs/GitHubWorkflow.md`](docs/GitHubWorkflow.md). Those files are canonical.
