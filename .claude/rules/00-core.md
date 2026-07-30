# Core program discipline

Always loaded. Complements `CLAUDE.md`; does not repeat it.

## Evidence

- Ground every factual claim in a `file:line`, an exact command output, or exact GitHub state.
- If you cannot ground it, say **UNVERIFIED**. An honest gap is worth more than a confident guess.
- A subagent's report is input, never proof. Verify load-bearing claims yourself before acting.
- Never infer completion from a milestone name, a PR title, or a document heading.

## Anti-duplication

Before creating any new seam, adapter, resolver, transport, identity model, gate, CLI verb or
status vocabulary: find the canonical one and extend it. If extending is genuinely wrong, say
plainly why the canonical system cannot serve, and escalate — do not quietly build the second one.

CI catches import-boundary duplication. It catches **no vocabulary duplication**: two agents
adding a `Permission` or `AuditAction` member always collide, and nothing detects a semantic
duplicate. Treat shared vocabularies as exclusive-ownership resources.

## Hook denials

A hook denial is a decision, not a prompt. Stop, or take a compliant alternative. Never retry the
same call hoping for a different answer, and never wait for a human to approve past it.

The shell is not an escape hatch, and it is guarded in two tiers.

**A small absolute set** — `.github/`, `infra/ci/`, `production.py`, `signing.py`,
`docs/program/SAFETY_INVARIANTS.md`, `apps/api/migrations/versions/` — may not be *named* in a
shell command at all unless every segment is a known reader. Deciding "does this shell command
write to X" is undecidable in general, and each unmodelled verb is a silent hole, so for these
few operator-owned paths the rule is inverted. **Reading them is fine** (`cat`, `grep`, `ls`,
`git log/diff/show -- <path>`); writing, deleting, extracting into, or passing them to a script
is not. Use the Read tool.

**Everything else** — product source and product docs on a program-foundation branch — is denied
only when an actual write target is detected: a redirection, `sed -i`, `cp`, `rm`, `tee`, `dd`,
`tar`/`unzip`, `git checkout -- <path>`, a PowerShell write cmdlet, or inline interpreter code
that opens a path. Read-only commands are never blocked here, so `python -m pytest apps/api/tests`
and `uv run mypy apps/api` work normally.

Wrapper prefixes (`env`, `sudo`, `xargs`, a bare `VAR=value`), shell keywords, grouping brackets
and nested `sh -c` / `Invoke-Expression` payloads are unwrapped before either decision.
`git apply` and `patch` are refused outright: their targets live inside the diff, so no
command-line check can clear them.

## Model posture

- Program Lead: Opus 5, xhigh, Opus 1M selector, interactive Ultracode workflow posture.
- Child sidechains: claim Opus 5 and xhigh **only when transcript-proven**
  (`message.model`, top-level `effort` in the session transcript).
- Claim 1M context **only** when the `context-1m-2025-08-07` beta request header is observed.
  The model id alone never proves it — an `opus[1m]` session still records `claude-opus-5`.
- Never claim a child independently inherits Ultracode.
- `CLAUDE_CODE_SUBAGENT_MODEL` is a single global override that silently supersedes per-agent
  `model:` frontmatter. Check it before reasoning about what a child is running on.
- The built-in `Explore` agent is model-capped unless `CLAUDE_CODE_DISABLE_EXPLORE_INHERIT_CAP`
  is set. Do not route Opus-required work through it.
- `claude --help` is **not** authoritative for this client: `--effort` accepts `ultracode`
  despite both the help text and its own invalid-value warning omitting it, and
  `--teammate-mode` is hidden entirely. Verify client behaviour differentially.

## Escalation

Architecture · migration · trust · provider authority · merge · deployment · residual risk.
State the decision needed, the options, and a recommendation.
