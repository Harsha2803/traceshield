# Open-Source Readiness Checklist

TraceShield's second problem, alongside the redaction engine, is being a credible
open-source project rather than a repository that happens to be public. This checklist is
the definition of "ready". Every unchecked item is a blocker for making the repository
public, per ADR 0005.

Nothing here is checked yet. Items are checked in the pull request that actually completes
them, never in advance.

## 1. Legal and ownership

- [ ] `LICENSE` with unmodified Apache-2.0 text (ADR 0002)
- [ ] `NOTICE` with copyright holder and the project-name statement
- [ ] `pyproject.toml` license metadata matches `LICENSE`
- [ ] No employer artifact, real trace, real prompt, credential or PII anywhere in history
- [ ] Every runtime dependency is under a permissive license, recorded in `CONTRIBUTING.md`
- [ ] Employment terms confirmed to permit publication (`docs/EmploymentSeparation.md`)

## 2. Contributor-facing documentation

- [ ] `README.md` rewritten for a stranger: what it is, the problem, a quickstart that runs
      verbatim, a redacted-trace before/after example, honest limitations, and a link to the
      threat model
- [ ] `CONTRIBUTING.md`: environment setup in one command, how to run the gate, how to add a
      detection rule with fixtures, commit and PR conventions, dependency policy,
      inbound-equals-outbound licensing
- [ ] `CODE_OF_CONDUCT.md` (Contributor Covenant) with a working contact address
- [ ] `SECURITY.md`: private vulnerability reporting, 72-hour acknowledgement target, and a
      definition of what counts as a vulnerability in a redaction library
- [ ] `CHANGELOG.md` in Keep a Changelog format with a real 0.1.0 entry
- [ ] Issue templates for bug, rule-gap and feature; a rule-gap template that explicitly
      tells reporters never to paste the real secret or PII they found
- [ ] Pull-request template retained and referenced

## 3. Repository configuration

- [ ] Description and topics set: `llm-observability`, `opentelemetry`, `pii-redaction`,
      `secrets-detection`, `ai-governance`, `python`
- [ ] Branch protection on `main`: required status checks, no direct pushes
- [ ] GitHub private vulnerability reporting enabled
- [ ] Dependabot or equivalent for dependencies and pinned GitHub Actions
- [ ] Secret scanning and push protection enabled
- [ ] Discussions enabled for rule-pack proposals

## 4. Quality signals a stranger checks in the first minute

- [ ] CI badge showing a passing gate on `main`
- [ ] Coverage evidence, meeting the thresholds in `CodingStandards.md` §11
- [ ] Tests visibly cover the adversarial cases, not only the happy path
- [ ] A worked example directory with synthetic traces, runnable end to end
- [ ] Benchmark artifact with the command, environment and raw results committed
- [ ] Type annotations complete; `mypy --strict` clean
- [ ] No `TODO`, stub, or placeholder anywhere in the shipped package

## 5. Distribution

- [ ] PyPI Trusted Publishing configured for this repository and workflow (ADR 0005)
- [ ] Release workflow builds sdist and wheel, publishes on tag, attaches attestations
- [ ] `pip install traceshield` works in a clean environment on every supported Python
- [ ] Package metadata: description, keywords, classifiers, project URLs for source, issues,
      changelog and security policy
- [ ] `py.typed` marker shipped so downstream users get the types
- [ ] Installed-package smoke test in CI that runs the README quickstart verbatim against the
      built artifact, not the source tree

## 6. First-impression content

- [ ] The README before/after example is the first thing after the one-liner. The product is
      visual: a trace that stays readable with the secrets gone.
- [ ] Limitations section states what the deterministic engine cannot catch
- [ ] Comparison section that is fair to the OpenTelemetry Collector redaction processor and
      to vendor masking hooks, and says when to use those instead
- [ ] A short "why not just turn content capture off" paragraph, since that is the reflex
      alternative

## 7. After going public

Not blockers for the flip, but the difference between a released package and a maintained
project. Do not start these until v0.1.0 is out.

- [ ] Answer every issue within a week, even if the answer is "not planned"
- [ ] A rule-pack contribution merged from someone else, which is the real signal the
      detector protocol is usable
- [ ] An integration guide written against a pipeline the maintainer actually ran
