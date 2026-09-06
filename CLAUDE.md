# Claude Instructions

Read `prompt.txt` first for the live handoff, then `docs/Tracker.md` for the single task
marked `NEXT`. Then read and follow `AGENTS.md`, `docs/CodingStandards.md`, and
`docs/GitHubWorkflow.md` before changing this repository. Those files are canonical; do not
duplicate or weaken their rules here.

`prompt.txt` is designed to be pasted whole into any agent to start a session. Keep it that
way: it must stay self-contained, current, and free of tool-specific instructions.

The approved product brief is `docs/ProductBrief.md` and the decisions behind it are in
`docs/adr/`. Read the brief, `docs/Architecture.md`, and `docs/ThreatModel.md` before
writing code. Scope beyond the v0.1.0 boundary in the brief is not authorized; do not start
a later milestone, and do not reverse an ADR without writing a superseding one.
