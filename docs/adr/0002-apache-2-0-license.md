# ADR 0002: Apache-2.0 license

- Status: Accepted
- Date: 2026-09-06

## Context

`docs/EmploymentSeparation.md` requires a TraceShield-specific licensing decision and
explicitly forbids inheriting the Mnemos choice. The project is intended to be adopted by
security and platform engineers inside companies, which means the license is read by a legal
or compliance function before the code is used.

## Decision

TraceShield is licensed under Apache-2.0. The repository carries `LICENSE` containing the
unmodified license text and a `NOTICE` file identifying the project and copyright holder.
Source files do not carry per-file license headers; the `LICENSE` and `NOTICE` files and the
package metadata are authoritative.

The name "TraceShield" is not licensed by Apache-2.0. `NOTICE` states that the name may not
be used to endorse or identify derived works without permission, so a fork cannot ship under
the project name.

## Alternatives considered

**MIT.** Shorter and marginally more permissive, and common for small libraries. Rejected
because it contains no express patent grant. For a security and compliance tool that
enterprises are asked to place in their data path, an explicit patent grant removes a
question that would otherwise reach a legal reviewer.

**AGPL or a source-available license.** Rejected. The product's value depends on being
adopted into other people's pipelines; a copyleft or non-OSI license makes that a decision
requiring approval, which defeats the purpose.

## Consequences

- Contributions are accepted under Apache-2.0 §5 inbound-equals-outbound. `CONTRIBUTING.md`
  states this; no separate CLA is required.
- Derived works must preserve `NOTICE` and state significant modifications.
- Adding any dependency under a copyleft license would be a licensing conflict for
  downstream users, so the dependency policy in `CONTRIBUTING.md` restricts runtime
  dependencies to permissive licenses.
