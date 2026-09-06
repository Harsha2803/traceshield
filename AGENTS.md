# TraceShield Development Rules

These rules apply to the entire repository and to every human or coding agent working in
it. They are requirements, not suggestions.

## Read before changing anything

Read, in order:

1. `prompt.txt` — the living handoff and current repository state
2. `docs/Tracker.md` — the agenda; the single task marked `NEXT` is the one to do
3. `README.md`
4. `docs/ProductBrief.md` — the approved scope, v0.1.0 boundary and acceptance criteria
5. `docs/Architecture.md` and `docs/ThreatModel.md`
6. `docs/CodingStandards.md`
7. `docs/GitHubWorkflow.md`
8. `docs/adr/` and the files being changed

`prompt.txt` is written to be pasted whole into a fresh agent session. It is the entry
point for every session, whichever tool is being used.

Product scope, stack, license, integration surface, detection approach and release process
are settled in `docs/ProductBrief.md` and ADRs 0001-0005. Work outside the v0.1.0 boundary
is not authorized. Do not silently make a new foundational decision or deviate from an
existing one; write an ADR, and supersede rather than edit a decided one.

## Non-negotiable rules

1. Use only the personal Git identity `Cheella Sree Harsha
   <cheellasreeharsha2803@gmail.com>` and GitHub account `Harsha2803`. Never use
   `harshaJKT`, an `@jktech.com` address, or any other employer identity.
2. Keep this work independent. Do not read, copy, adapt, reconstruct, or commit employer
   source code, schemas, prompts, configuration, credentials, internal documentation,
   customer data, traces, or proprietary vocabulary. Patterns learned through experience
   are portable; employer artifacts are not.
3. Never commit secrets, tokens, credentials, raw production traces, raw prompts, PII, or
   personal log exports. Test and demo data must be synthetic or explicitly sanitized.
4. Do not import the Langfuse JSON files in the user's Downloads directory into this
   repository unless the user explicitly requests it and the data has first been reviewed
   and sanitized.
5. No placeholders, `TODO` implementations, stubbed success responses, fake integrations,
   or claims that unimplemented behavior works. Split work into a smaller complete slice.
6. One logical change per commit. Do not mix unrelated cleanup with feature work.
7. A change is not complete until its relevant tests, lint, type checks, security checks,
   and build pass. Run the same aggregate gate CI runs before pushing.
8. Add a regression test for every bug fix. Test behavior and boundaries rather than
   implementation trivia.
9. Update documentation and project status in the same commit as behavior changes. Claims
   and benchmark numbers must point to reproducible evidence and must be re-measured when
   their code path changes.
10. User-facing capabilities must ship as a usable end-to-end slice. Infrastructure may be
    built as part of that slice, but it is not a resume milestone on its own.
11. Do not hand-edit generated files. Change their source and regenerate them.
12. Finish only the task marked `NEXT` in `docs/Tracker.md`. Do not begin an unrequested
    next milestone. If nothing is marked `NEXT`, stop and ask the owner.
13. Update `docs/Tracker.md` and `prompt.txt` in the same commit as every completed task, so
    the next session has the exact branch/PR state, verified product state, known gaps, and
    one clearly specified next task. Replace stale handoff facts instead of accumulating a
    chronological diary. Acceptance criteria in the tracker are binding and may not be
    narrowed to make a task easier to close.

## Git and GitHub

Follow `docs/GitHubWorkflow.md` exactly. In particular, verify the active GitHub account,
repo-local identity, and remote before every push. The initial reviewed baseline may create
`main`; after that, use scoped branches and pull requests. Do not push directly to `main`.

## Engineering standard

Follow `docs/CodingStandards.md`. Where a rule is conditional on the selected stack, it
becomes mandatory as soon as that stack is introduced. If a project-specific need requires
an exception, document the rationale in an ADR rather than silently weakening the rule.
