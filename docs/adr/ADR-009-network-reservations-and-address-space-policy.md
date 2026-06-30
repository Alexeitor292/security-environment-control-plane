# ADR-009 — Network reservations and address-space policy

- **Status:** Accepted
- **Date:** 2026-06-30
- **Milestone:** SECP-002A
- **Related:** Charter §8 (isolation), Invariants 11, 12, 17; ADR-006

## Context

Real per-team networks need non-overlapping address space. With concurrent exercises
targeting the same provider, two teams could be assigned the same CIDR, causing
collisions and broken isolation. This must be solved **before** any real network is
created, as a provider-neutral reservation, not a Proxmox detail.

## Decision

Introduce provider-neutral reservation models and a service:

- `AddressSpacePolicy` — approved address spaces for an `ExecutionTarget`: a list of
  CIDR blocks plus the allowed per-team subnet prefix length. Declared as target
  config policy.
- `NetworkReservation` — a reserved CIDR for `(execution_target_id, exercise_id,
  team_ref)` with `status` (`reserved` | `released`).

Rules:

- **Transactional, overlap-free**: reservations are created in a transaction; a
  uniqueness constraint on `(execution_target_id, cidr, status='reserved')` plus an
  explicit overlap check reject a CIDR that overlaps an existing active reservation
  on the same target. Concurrent attempts serialize; the loser retries the next free
  block or fails cleanly.
- **Approved-space validation**: for a real execution target, a requested per-team
  network must fall within an approved address space.
- **Deterministic allocation**: given a policy and a set of already-reserved blocks,
  allocation picks the next free `/<prefix>` deterministically.
- **Release lifecycle**: reservations are released only by explicit rules (exercise
  destroy or explicit release), audited.
- **Simulator unchanged**: the Simulator requires no execution target and keeps its
  deterministic per-team `/24` allocation; the reservation service is exercised by
  its own tests and wired for real targets in SECP-002B.
- **No real network is created** in SECP-002A.

## Consequences

**Positive:** isolation is guaranteed at the address-space layer before any real
infra exists; concurrency-safe; org-scoped and auditable.

**Negative / risks:** allocation/locking correctness is subtle. Mitigated by a DB
uniqueness constraint, an overlap check inside the transaction, and tests for
deterministic allocation, collision prevention, concurrency, release, and cross-org
denial.

**Placeholder:** reservations are not yet consumed by real provisioning (SECP-002B);
the loser-retry/backoff policy is minimal in SECP-002A.
