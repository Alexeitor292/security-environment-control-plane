---
paths:
  - "docs/**"
  - "README.md"
---

# Documentation governance

## Doc prose is machine-enforced here

Around ten pytest modules assert marker presence and forbidden claims in `docs/STATUS.md`,
`README.md`, runbooks and design documents — e.g. `tests/test_project_status_truthfulness.py`,
`tests/test_b1b_architecture_lock.py`, `tests/test_live_collector_design.py`,
`apps/api/tests/test_oidc_c_security_boundary.py`. Editing a document can fail CI.

`tests/test_no_real_endpoints.py` scans `docs/` — never write a real endpoint, host or public IP
into any document, including a Project Brain document.

## The doc type system

| Directory | Purpose | Mutability |
| --- | --- | --- |
| `PROJECT_CHARTER.md` | Intent, domain model, §6 invariants, §17 roadmap | Amend only via approved ADR |
| `adr/` | 28 accepted decisions | Accepted ADRs are amended in place, never flipped to Superseded |
| `STATUS.md` | Point-in-time capability ledger | Near-append-only; historical rows are annotated, never rewritten |
| `architecture/` | Per-milestone design locks | Design-only; some are test-pinned as non-runnable |
| `implementation/` | PR decomposition | Historical |
| `runbooks/` | Target operator experience | Aspirational, not runnable |
| `verification/` | Dated runtime evidence | Historical (abandoned after 2026-07-01) |
| `proxmox/` | Activation checklists and gates | Living |
| `program/` | Project Brain (agent-facing) | See below |

## Appending to STATUS.md

It is **descriptive, not an activation authority** — nothing in it enables, unseals or authorises
anything. When adding to it:

- **Append** a new dated entry. Never rewrite or delete a historical row.
- Where an older row is superseded, annotate it in place with a pointer — the file's own
  convention (`docs/STATUS.md:6-8`, `:38`, `:43`).
- Use the closed status vocabulary already defined in §A.
- Anchor the claim to a commit SHA and to enforcing code, not to a milestone name.

Known live drift: STATUS.md is behind HEAD and names a stale Alembic head. Do not propagate its
claims; verify against code.

## docs/program/ mutability

- `SAFETY_INVARIANTS.md` — **append-only**. A committed hook denies any edit that removes an
  existing line. Corrections are new entries carrying `supersedes:`.
- `FILE_OWNERSHIP.md`, `AGENT_OPERATING_MODEL.md` — amend forward; keep entries evidence-anchored.

## ADR convention

Every ADR carries a fixed header block (`ADR-001` is the canonical form). There is **no template
and no test enforcing it** — match the existing shape by hand. Charter §6 and §15 say
boundary-affecting changes require an ADR; that rule is prose-only, with no test behind it.
