# SECP Agent Operating Model

How multiple Claude agents work this repository without colliding, duplicating systems, or
claiming completion they have not earned.

**Observed at:** `e72f28f` (`main`, SECP-PR5H-B2A). Client behaviour in §8 was verified
first-party against the installed CLI, its embedded schemas, and live session transcripts.

**Scope note.** This document is doctrine written in PR 1. The agent *definitions*
(`.claude/agents/`), on-demand skills, the Project Brain documents and the model-policy canary
arrive in PR 2. Nothing here presumes those exist yet.

---

## 1. Roles and authority

| Role | Git authority |
| --- | --- |
| **Program Lead** | Create feature branches; commit and push **orchestration-only** changes to its own non-`main` branch; open and update **draft** PRs; coordinate worktrees. **Must not implement product code itself.** |
| **Worktree implementer** | Commit and push **only its assigned branch**; open and update that branch's draft PR. |
| **Review agents** (architecture, security-adversary, test-verifier) | **Read-only.** May post findings; may never edit a branch. |
| **Integration manager** | Approved shared-file wiring on a **dedicated integration branch only** — never directly on another agent's branch. |

### Universal — no role overrides these

- No force push. No push to `main`. No amend or rebase of published history.
- No mark-ready (`gh pr ready`, or `gh pr create` without `--draft`). No merge.
- Every branch is created from the task contract's **exact base SHA**.
- All pushes are ordinary fast-forwards to an approved non-`main` branch.

Enforced by `.claude/hooks/guard_bash.py`, not by trust.

### CI state and authority

An `infrastructure_invalid` CI classification does **not** block local implementation, commit,
normal push, or opening a draft PR. It blocks **mark-ready and merge** — which are Juan's alone
in every case.

---

## 2. Hook denials are decisions

A hook denial is a decision, not a prompt. On denial: **stop, or take a compliant alternative.**
Never retry the same call hoping for a different result, and never wait for a human to approve
past it. Under `--permission-mode bypassPermissions` there is no approval surface at all — an
agent that waits, hangs.

### Honest boundary

`bypassPermissions` removes Claude's approval prompts and grants **full host authority** to the
session. The committed hooks reduce accidental project-policy violations by agents. **They are
not an operating-system security boundary**: anything running under the operator's identity can
edit the hooks, mint or consume unlock tokens, or start a session with `--safe-mode` / `--bare`,
all of which disable hooks entirely. `permissions.deny` string matching is likewise evadable.

---

## 3. Escalate to Juan

Architecture · migration · trust · provider authority · merge · deployment · residual risk.

State the decision needed, the options, and a recommendation — not just a question. Everything
else: decide, act, and record why.

---

## 4. Preventing a second system

The repository's largest structural risk is a *duplicate*, not a bug. Before creating any seam,
adapter, resolver, transport, identity model, gate, CLI verb or status vocabulary, find the
canonical one (`.claude/rules/` names it per tree) and extend it. If extending is genuinely
wrong, say plainly why and escalate — do not quietly build the second one.

CI catches import-boundary duplication. It catches **no vocabulary duplication**.

---

## 5. Collision control

`docs/program/FILE_OWNERSHIP.md` is authoritative. In short:

- **Tier 1 (serialised, repo-wide):** the Alembic head literal cluster (55 occurrences, 25
  files, four planes) and the shared `Permission` / `AuditAction` vocabularies.
- **Tier 2 (exclusive):** one live contract per file — `enums.py`, `models.py`, `main.py`,
  `immutability.py`, `config.py`, `errors.py`, `dispatch.py`, `client.ts`, `types.ts`,
  `main.tsx`, `App.tsx`, `conftest.py`, `pyproject.toml`, `STATUS.md`, and the guard tests.
- **Tier 3 (operator-only):** `.github/**`, `infra/ci/**`, trust roots, secrets, seals.
- **Tier 4 (free):** new files inside one plane.

Shared-file wiring is deferred to a single integration pass rather than done concurrently. That
is what prevents the merge conflicts a 55-occurrence literal otherwise guarantees.

---

## 6. Worktree scheduling

A git worktree isolates the working tree **and nothing else**. Before running agents in parallel:

| Resource | Requirement |
| --- | --- |
| `.venv` | Absent in a fresh worktree (gitignored). Run `uv venv && uv pip install -e ".[dev]"` first |
| `.env` | Absent in a fresh worktree; dev Compose interpolates ~15 bare `${VAR}` references |
| `node_modules` | Absent; `npm ci` in `apps/web` |
| `infra/dev` Compose stack | **Singleton** (fixed project name, ports 5432/7233/5173). One agent holds it at a time |
| `SECP_TEST_POSTGRES_URL` | 28 modules `DROP SCHEMA … CASCADE`. Give each concurrent agent a **distinct database** |
| SQLite test DB | `apps/api/tests/conftest.py` is file-backed. Never run two suites in one checkout |

---

## 7. Evidence and completion

Completion is earned by a command that ran, never asserted in prose.

- `.claude/hooks/record_evidence.py` records validation outcomes to a session ledger kept outside
  the repository.
- `.claude/hooks/guard_task_completion.py` blocks completing a task while the tree is dirty and
  no passing validation has been recorded.
- `.claude/hooks/guard_teammate_idle.py` blocks a teammate going idle while holding an open
  contract or uncommitted work.

**A local green run is not the gate.** `pyproject.toml` `testpaths` omits
`contracts/scenario-schema/tests` which the CI manifest includes, and 26 modules skip silently
without `SECP_TEST_POSTGRES_URL`. Only the two named CI contexts prove the full gate:
*"Backend (format, lint, types, tests, schema, boundary, security)"* and
*"Frontend (types, lint, build, tests, security)"*.

A subagent's report is input, not proof. Verify load-bearing claims against code before acting.

---

## 8. Model policy

| Posture | Statement |
| --- | --- |
| Program Lead | Opus 5, xhigh, Opus 1M selector, interactive Ultracode workflow posture |
| Child sidechains | Opus 5 and xhigh — claimed **only when transcript-proven** |
| 1M context | Claimed **only** when the `context-1m-2025-08-07` beta request header is observed |
| Ultracode inheritance | **Never claimed** for children |

**How to prove it.** The session transcript records `message.model` and a top-level `effort` per
assistant record, plus `isSidechain`. Measured across 12 concurrent subagents at
`e72f28f`: all reported `claude-opus-5` / `xhigh` / `isSidechain: true`, matching the lead.

**What cannot be proven that way.** An `opus[1m]` session records plain `claude-opus-5` — the
`[1m]` suffix is a client-side selector that applies a beta header, not a distinct model id. The
model id therefore never proves the context window.

### Client facts that bite

- `CLAUDE_CODE_SUBAGENT_MODEL` is a **single global override** that silently supersedes every
  per-agent `model:` frontmatter and the per-invocation model parameter. Check it before
  reasoning about what a child runs on. The launcher sets it explicitly.
- The built-in `Explore` agent is **model-capped** unless
  `CLAUDE_CODE_DISABLE_EXPLORE_INHERIT_CAP` is set; custom project agents are exempt. Do not
  route Opus-required work through `Explore`.
- `claude --help` is **not authoritative** for this client: `--effort` accepts `ultracode`
  although both the help text and its own invalid-value warning list only
  `low, medium, high, xhigh, max`; `--teammate-mode` is hidden entirely. Verify differentially —
  an invalid value warns, a valid one does not.
- Ultracode is session-only and not persistable: `~/.claude/settings.json` stores at most
  `effortLevel: "xhigh"`.

---

## 9. Launching the standing Program Lead

`scripts/program/Start-ProgramLead.ps1` launches:

```
claude --agent secp-program-lead --model opus[1m]
       --permission-mode bypassPermissions --teammate-mode in-process
       -n 'SECP Program Lead'
```

No `--effort` flag is passed: Ultracode is activated interactively with `/effort ultracode`.

The launcher **fails closed before starting** if the committed hook configuration is missing, any
required hook file is missing, the checkout is not the SECP repository, `bypassPermissions` is
disabled by managed configuration, or the requested model is unavailable.

`--agent` is passed only once `.claude/agents/secp-program-lead.md` exists (PR 2); until then the
launcher establishes the model, permission, teammate and session-name posture alone.
