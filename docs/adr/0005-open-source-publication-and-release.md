# ADR 0005: Open-source publication and release process

- Status: Accepted
- Date: 2026-09-06

## Context

TraceShield is intended to be an open-source pip package. `docs/EmploymentSeparation.md`
requires the repository to stay private until it has a runnable, reviewed release and a
completed public-readiness checklist, and requires a licence decision before publication
(made in ADR 0002).

The PyPI names `traceshield`, `trace-shield` and `traceshield-otel` all returned 404 from
the PyPI JSON API on 2026-09-06, so the name is available but unclaimed.

## Decision

**Timing.** The repository stays private while v0.1.0 is built. At the moment the v0.1.0
acceptance criteria in `ProductBrief.md` §7 are met and the gate is green, the repository is
made public and 0.1.0 is published to PyPI in the same change. No placeholder release is
uploaded to reserve the name.

**Publishing.** PyPI Trusted Publishing with GitHub Actions OIDC. No long-lived API token is
ever created or stored. The publish workflow requests `id-token: write`, and Sigstore
provenance attestations are produced automatically. Releases are cut from a tag; `hatch-vcs`
derives the version from that tag, so the version is never hand-edited.

**Versioning.** Semantic versioning. Before 1.0.0, a minor bump may change the API. The
policy file format carries its own version, independent of the package version, because a
policy outlives an upgrade.

**Public-readiness checklist.** Tracked in `docs/OpenSourceReadiness.md`. Every item must be
checked before the repository visibility changes.

**Security reporting.** `SECURITY.md` directs reports to GitHub private vulnerability
reporting rather than a public issue, states a 72-hour acknowledgement target, and defines
what counts as a vulnerability in a redaction library — specifically, a bypass of the default
policy for a value the documentation claims is covered.

## Alternatives considered

**Publish a 0.0.1 placeholder now to reserve the name.** Rejected. It puts a package that
does nothing under a security-sounding name in front of users, which is the opposite of the
trust this project needs. The name-collision risk over the build window is low and accepted.

**Go public immediately and build in the open.** Better "building in public" signal.
Rejected because it conflicts with the private-until-reviewed-release rule already agreed in
`docs/EmploymentSeparation.md`, and because early half-built commits of a security tool are
permanently visible.

**Stay private until 1.0.0.** Rejected: no community signal, no external feedback on the
rule pack, and a real risk of losing the name.

## Consequences

- The first public commit history includes the whole private build history. Every commit
  must therefore be clean of secrets, employer artifacts and real trace data from the start,
  which is already required by `AGENTS.md`.
- CI must be green and the gate must be complete before the visibility flip, since it becomes
  the project's public first impression.
- Trusted Publishing binds releases to this repository and workflow. Moving the repository
  requires reconfiguring the PyPI publisher.
