# Mnemos Rules Transfer

This bootstrap deliberately transfers Mnemos's reusable engineering and repository rules,
not its product design.

## Transferred

- personal Git identity and `Harsha2803` account verification before every push;
- private-until-ready posture and strict employer/IP separation;
- one logical change per conventional commit and prompt pull requests;
- full local verification matching CI before push;
- strict typing, explicit boundaries, dependency injection, and deterministic domain code;
- structured concurrency, timeouts, visible degradation, and non-leaking errors;
- disciplined data access, transactions, migrations, and tenant isolation if applicable;
- startup-validated configuration, secret hygiene, structured telemetry, and privacy;
- layered tests, property testing for policy logic, real adapter tests, and regression tests;
- ADRs, evidence-backed documentation, honest gaps, and reproducible measured claims; and
- end-to-end, demonstrable milestones instead of disconnected infrastructure layers.

## Intentionally not transferred

- Mnemos memory, bitemporal, context-compilation, retrieval, ACL, and benchmark invariants;
- Mnemos's service topology, database choices, ports, commands, milestones, and tracker state;
- Mnemos-specific UI identity and design tokens; and
- Mnemos's Apache-2.0 license decision, which needs a separate TraceShield decision before
  publication.

Those items describe a different product. Carrying them over would constrain TraceShield
before its problem statement and architecture are agreed. New project-specific invariants
belong in the TraceShield brief, ADRs, and tests once selected.
