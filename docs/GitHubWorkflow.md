# Git and GitHub Workflow

These rules are inherited from Mnemos and apply to every TraceShield change.

## Ownership and identity

- GitHub owner: `Harsha2803`
- Repository: `Harsha2803/traceshield`
- Visibility at bootstrap: private
- Repo-local author: `Cheella Sree Harsha`
- Repo-local email: `cheellasreeharsha2803@gmail.com`
- Expected origin: `https://github.com/Harsha2803/traceshield.git`

The machine may have both personal and work GitHub accounts authenticated. Never infer that
the currently active account is correct. Never change the global Git identity for this
project; set and verify the repository-local identity.

## Mandatory pre-push check

Before every push, run:

```bash
git config --local user.name
git config --local user.email
git remote get-url origin
gh auth status
gh api user --jq .login
```

The results must be exactly consistent with the ownership values above. If another GitHub
account is active, switch deliberately and verify again:

```bash
gh auth switch --hostname github.com --user Harsha2803
gh api user --jq .login
```

Stop instead of pushing if the personal authentication is unavailable. Never fall back to
`harshaJKT`, an `@jktech.com` identity, a differently owned fork, or a changed remote.

## Branch and pull-request rules

The first reviewed bootstrap commit may establish `main` because an empty remote has no base
branch. After that exception:

1. Start from an up-to-date, clean `main`.
2. Create one scoped branch for one logical change. Use names such as `feat/<topic>`,
   `fix/<topic>`, `docs/<topic>`, `test/<topic>`, or `chore/<topic>`.
3. Use Conventional Commits with a meaningful scope, for example
   `feat(ingest): redact secrets before trace persistence`.
4. Push the branch after its first coherent commit and open a pull request immediately.
   Keep it draft while incomplete.
5. Keep unrelated changes out of the branch. Rebase or update from `main` deliberately;
   never rewrite shared history without explicit approval.
6. Run the complete repository gate before every push. All required GitHub checks must pass.
7. Update docs, ADRs, migrations, generated artifacts, fixtures, and measured claims in the
   same change when applicable.
8. Mark the PR ready only when the behavior is complete and verified. Merge using the
   repository's established strategy, return to `main`, fast-forward from `origin/main`,
   and verify the worktree is clean.

Do not report a task complete while its finished work exists only on a branch, its PR is
still draft, or required CI is red. Report authentication, review, or branch-protection
problems as blockers.

## Pull-request evidence

Every PR description must state:

- the user-visible or developer-visible outcome;
- why the change is needed;
- commands run and results observed;
- security/privacy implications;
- documentation, migration, or generated-file impact; and
- any known limitation or deliberate follow-up.

Claims such as latency, accuracy, coverage, throughput, cost, or vulnerability reduction
must reference a reproducible command and committed artifact where appropriate.
