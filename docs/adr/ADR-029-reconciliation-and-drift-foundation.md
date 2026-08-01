# ADR-029 — Reconciliation and drift foundation

- **Status:** Accepted
- **Date:** 2026-07-31
- **Milestone:** SECP reconciliation and drift foundation
- **Related:** Charter §4 (orchestration owns state reconciliation and drift detection), §11
  (capability surface incl. `reconcile`), §17 (SECP-002C); Invariant 9 (no provider-specific core
  concepts); ADR-003 (plugin contract), ADR-008 (generic observed inventory and topology),
  ADR-020 §G (state-vs-provider disagreement fails closed to an operator decision)

## Context

The charter assigns state reconciliation and drift detection to the orchestration engine, and
SECP-002C is the milestone that applies them to real infrastructure. Nothing in the platform yet
expresses *what drift is*: `apply` writes resources and `status` reads them back, and the gap
between the two is described nowhere.

The risk in filling that gap is that reconciliation is the natural place for provider concepts to
leak into the core, for a comparison to quietly treat "the collector said nothing" as "they agree",
and for a planner to reach for a delete when it finds something it did not expect.

## Decision

Add `contracts/reconciliation/secp_reconciliation` — a pure, versioned contract (`v1`) covering
desired-versus-observed state, drift classification, reconciliation planning, and the reset-intent
and evidence documents — plus a simulator-only execution surface. Nothing here contacts a provider,
and no real-provider execution path is introduced.

### Provider-neutral state

Desired and observed state share one shape: an *element* (`network` / `node` / `edge` — ADR-008's
generic projection, which every provider populates) carrying *facets* named for the property being
compared (`address_space`, `address`, `node_class`), not for any provider's field. The one module
that touches the plugin contract is `v1/topology_adapter.py`; the rest of the package imports only
the standard library.

The two sides are compared, never merged, and their references are treated differently on purpose:
a desired element's reference is authored control-plane content, so it may appear in a finding, an
action or a plan; an observed element's reference and values are provider-supplied, so they appear
in no output at all.

### Drift classification

Five kinds, totally ordered by how much they block: `identity_conflict`, `indeterminate`,
`unmanaged`, `missing`, `divergent`. Each finding carries exactly one bounded reason from a closed
set that the kinds partition completely. There is no free-form drift description.

`indeterminate` is the load-bearing one. When the desired state declares a facet and the
observation is silent about it, the result is `indeterminate` — never "in sync". Reading silence as
agreement is the failure this vocabulary exists to make impossible.

### Refusal boundaries

Refusals carry only a bounded `reconciliation_*` code — no path, endpoint, address, key material,
provider value or raw exception — following the control plane's existing redacted-refusal
convention. Verification happens before comparison: an input whose provenance, instance identity,
provider, fidelity, freshness or internal consistency cannot be established refuses at the gate
rather than reaching classification. Classification then cannot refuse (it accepts only a verified
pair), and planning refuses again on drift no plan can honestly resolve — an identity conflict, an
indeterminate facet, or a change set exceeding the scope's declared budget.

### No removal, by construction

`ActionKind` has two members, `create` and `update`. An element observed inside the scope but
absent from the desired state is *deferred* and the plan's disposition becomes
`operator_decision_required`. This is not a policy the planner enforces — a removal is a shape the
plan cannot express — and it follows the charter's rule that adoption or removal of pre-existing
assets is an explicit opt-in workflow, never the default, and ADR-020's rule that a disagreement
between recorded and observed state is an operator decision rather than an automatic re-apply.

### Reset intent and evidence

Both are versioned, machine-readable and content-addressed, and both carry only versions, closed
codes, counts, digests and canonical timestamps. A reset intent is an authorization bound to an
exact `plan_digest`, mirroring how change-set approvals bind an exact `change_set_hash`; it is not
the payload. A refusal produces evidence too, recording the bounded code and whether a fresh
observation could plausibly clear it.

### Simulator-only execution

The only executor is `plugins/simulator/secp_plugin_simulator/reconciliation.py`, and it is
structurally incapable of reaching a provider rather than configured not to:

- every type in its public signatures — and the whole closure of those types under their own
  fields — is a builtin scalar, an enum or a frozen dataclass, so there is no parameter through
  which a port, context, transport or callable could arrive;
- the reconciliation packages import only pure-computation standard-library modules, with the
  plugin-contract seam declared as a single reviewed `(module, import)` exception;
- no code object in either package names an escape (`open`, `getattr`, `__import__`, `socket`,
  `connect`, `Popen`, …), checked on the loaded code objects rather than on source text, which
  closes the dynamic-dispatch gap a static import scan leaves open.

`ExecutionSurface` has exactly one member, `simulator`; the plan model cannot name another.

## Consequences

**Positive:** drift becomes an auditable distribution over closed vocabularies rather than prose;
an unverifiable input refuses instead of passing quietly; no reconciliation output can carry
provider naming; and the execution surface's isolation is a property tests can check rather than a
convention reviewers must remember.

**Negative / risks:** the vocabularies are deliberately narrow, so the first real provider will
need facets this version does not have — adding one is a contract-version decision, which is the
intended cost. Comparison is exact string equality on canonicalized facet values, so semantically
equal but textually different values (an address space written two ways) classify as divergent; a
normalizing collector is the answer, not a looser comparison.

**Not delivered here, deliberately:** no reconciliation against a real provider, no removal or
adoption of unmanaged resources, no scheduling or orchestration of reconciliation runs, no API or
persistence surface, and no change to any seal, approval gate or trust root.
