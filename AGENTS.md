# TraceShield Development Rules

These rules apply to the entire repository and to every human or coding agent working in
it. They are requirements, not suggestions.

## Read before changing anything

Read, in order:

1. `prompt.txt` — the living handoff and current repository state
2. `README.md`
3. the current project brief/tracker once one exists
4. `docs/CodingStandards.md`
5. `docs/GitHubWorkflow.md`
6. relevant ADRs and the files being changed

The product scope and stack are not decided at bootstrap time. Do not silently make
foundational product or architecture decisions. Record consequential decisions in an ADR.

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
12. Finish only the requested task. Do not begin an unrequested next milestone.
13. Update `prompt.txt` at the end of every completed task so the next session has the exact
    branch/PR state, verified product state, known gaps, and one clearly specified next task.
    Replace stale handoff facts instead of accumulating a chronological diary.

## Git and GitHub

Follow `docs/GitHubWorkflow.md` exactly. In particular, verify the active GitHub account,
repo-local identity, and remote before every push. The initial reviewed baseline may create
`main`; after that, use scoped branches and pull requests. Do not push directly to `main`.

## Engineering standard

Follow `docs/CodingStandards.md`. Where a rule is conditional on the selected stack, it
becomes mandatory as soon as that stack is introduced. If a project-specific need requires
an exception, document the rationale in an ADR rather than silently weakening the rule.
