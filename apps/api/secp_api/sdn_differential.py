"""The SDN active/pending differential, kept as two sources and one derived conclusion.

Proxmox's ``?pending=1`` response is a MERGED view: for a ``new`` object only ``type`` and ``vnet``
are hoisted to the top level and everything else sits under ``pending``; for a ``changed`` object
the top level holds the RUNNING values and ``pending`` holds the ones activation would install.
Reading either half alone is wrong in a different direction — top-level-only sees an almost-empty
record for a create, and merged-only cannot say what a change would REPLACE.

So both views are retained and the action is DERIVED from the pair:

``create``     pending present, active absent
``delete``     active present, pending absent
``change``     both present and different
``unchanged``  both present and identical
``ambiguous``  anything else, and every case where the evidence for one of the above is missing

``ambiguous`` is not a fallback for tidiness. ``PUT /cluster/sdn`` applies every pending change on
the cluster, so an object SECP cannot classify is an object SECP would commit without knowing what
it does. Each ambiguity carries the reason it could not be resolved.

Three refusals exist because an object can look perfectly classified and still be untrustworthy:

* a ``create`` whose pre-Stage-1 absence evidence is missing might be an existing object SECP is
  about to adopt because it happens to share an identifier;
* a ``delete`` with no active-side representation is a deletion of something nobody observed, so
  what activation would remove is unknown;
* an identifier that appears twice in a family cannot be matched to one proof, and the join between
  objects and their ownership proofs is one-to-one by construction.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from secp_commissioning.canonical import sha256_digest

from secp_api.discovery_fact_commitment import canonical_value
from secp_api.discovery_fact_projection import safe_identifier

ACTION_CREATE = "create"
ACTION_CHANGE = "change"
ACTION_DELETE = "delete"
ACTION_UNCHANGED = "unchanged"
ACTION_AMBIGUOUS = "ambiguous"

#: Every action an object may be classified as. Closed, and ``ambiguous`` is a member rather than an
#: error so an unclassifiable object stays IN the pending set and keeps blocking exclusivity.
SDN_ACTIONS: tuple[str, ...] = (
    ACTION_CREATE,
    ACTION_CHANGE,
    ACTION_DELETE,
    ACTION_UNCHANGED,
    ACTION_AMBIGUOUS,
)

#: What Proxmox itself annotates a row with. Retained beside the derived action rather than trusted
#: as it: the annotation is one source's summary of the same pair of views.
_TARGET_STATE_DELETED = "deleted"


@dataclass(frozen=True)
class SdnObjectDifferential:
    """One pending object, as BOTH views and the conclusion drawn from them."""

    family: str
    object_id: str
    #: What Proxmox annotated the row with. Evidence, never the answer.
    target_state: str
    active_present: bool
    pending_present: bool
    active_digest: str
    pending_digest: str
    action: str
    ambiguity_reason: str = ""

    def canonical(self) -> dict:
        return {
            "family": self.family,
            "object_id": self.object_id,
            "target_state": self.target_state,
            "active_present": self.active_present,
            "pending_present": self.pending_present,
            "active_digest": self.active_digest,
            "pending_digest": self.pending_digest,
            "action": self.action,
            "ambiguity_reason": self.ambiguity_reason,
        }


def _digest(value: object) -> str:
    if not value:
        return ""
    return sha256_digest({"value": canonical_value(value)})


def derive_object_differential(family: str, row: Mapping[str, object]) -> SdnObjectDifferential:
    """Classify ONE object from its two views. Never from the target's annotation alone."""
    object_id = str(row.get("object_id") or "")
    target_state = str(row.get("state") or "")

    def _view(key: str) -> dict:
        value = row.get(key)
        return value if isinstance(value, dict) else {}

    active, pending = _view("active"), _view("observed")

    # "Present" means the view carries something beyond the bookkeeping keys the merge adds.
    active_present = bool(_meaningful(active))
    pending_present = bool(_meaningful(pending)) and target_state != _TARGET_STATE_DELETED

    active_digest, pending_digest = _digest(active), _digest(pending)

    reason = ""
    if not object_id:
        action, reason = ACTION_AMBIGUOUS, "object_identifier_absent"
    elif pending_present and not active_present:
        action = ACTION_CREATE
    elif active_present and not pending_present:
        action = ACTION_DELETE
    elif active_present and pending_present:
        action = ACTION_CHANGE if active_digest != pending_digest else ACTION_UNCHANGED
    else:
        # Neither view carries anything: the row exists, and nothing about it is knowable.
        action, reason = ACTION_AMBIGUOUS, "neither_view_carries_a_representation"

    # NOTE: "a delete whose active side is empty" cannot arise HERE — ``active_present`` is true
    # only when the view carries a key, which always yields a digest — so no branch for it exists in
    # the derivation. It is reachable at the GATE, where a PendingSdnObject can be presented with a
    # delete action and an empty active representation, and it is refused there. A branch that
    # cannot fire is worse than no branch: it reads as coverage.
    return SdnObjectDifferential(
        family=family,
        object_id=object_id,
        target_state=target_state,
        active_present=active_present,
        pending_present=pending_present,
        active_digest=active_digest,
        pending_digest=pending_digest,
        action=action,
        ambiguity_reason=reason,
    )


def _meaningful(view: Mapping[str, object]) -> bool:
    """Whether a view says anything about the object rather than only how it was labelled."""
    return any(key not in ("state", "family", "object_id") for key in view)


def derive_differentials(
    families: Mapping[str, Sequence[Mapping[str, object]]],
) -> tuple[SdnObjectDifferential, ...]:
    """Classify every observed pending row. The count out equals the count in, always.

    Nothing is filtered here — not the unidentifiable rows and not the ambiguous ones. An object
    dropped from this set is an object that stops blocking activation exclusivity, and the whole
    reason the pending set is enumerated is that ``PUT /cluster/sdn`` commits all of it.
    """
    out: list[SdnObjectDifferential] = []
    for scope in sorted(families):
        family = scope.split("@", 1)[0]
        rows = families[scope]
        if not isinstance(rows, (list, tuple)):
            continue
        for row in rows:
            if isinstance(row, Mapping):
                out.append(derive_object_differential(family, row))
    return tuple(out)


def differential_refusals(
    *,
    differentials: Sequence[SdnObjectDifferential],
    observed_row_count: int,
    active_visibility_complete: bool,
    pending_visibility_complete: bool,
    degraded_sources: Sequence[str] = (),
    absence_evidence_by_key: Mapping[tuple[str, str], str] | None = None,
) -> tuple[str, ...]:
    """Every reason this differential may not be acted on. ALL of them, not the first.

    An operator who clears one refusal only to meet the next has been told half the truth twice.
    """
    reasons: list[str] = []

    if not active_visibility_complete:
        reasons.append("sdn_active_visibility_incomplete")
    if not pending_visibility_complete:
        reasons.append("sdn_pending_visibility_incomplete")
    for source in sorted(set(degraded_sources)):
        reasons.append(f"sdn_source_degraded:{source}")

    if len(differentials) != observed_row_count:
        # The count is checked rather than trusted: a pending object that vanished between
        # observation and classification is one that stops blocking exclusivity.
        reasons.append(
            f"sdn_pending_object_merged_away:observed={observed_row_count}:"
            f"classified={len(differentials)}"
        )

    seen: dict[tuple[str, str], int] = {}
    for differential in differentials:
        key = (differential.family, differential.object_id)
        seen[key] = seen.get(key, 0) + 1
    for (family, object_id), count in sorted(seen.items()):
        if count > 1:
            reasons.append(
                f"sdn_identifier_not_unique:{family}:"
                f"{safe_identifier(object_id) if object_id else '<unidentified>'}"
            )

    absence = dict(absence_evidence_by_key or {})
    for differential in differentials:
        named = (
            safe_identifier(differential.object_id) if differential.object_id else "<unidentified>"
        )
        key = (differential.family, differential.object_id)
        if differential.action == ACTION_AMBIGUOUS:
            reasons.append(
                f"sdn_object_action_ambiguous:{differential.family}:"
                f"{named}:{differential.ambiguity_reason or 'unclassified'}"
            )
        if differential.action == ACTION_CREATE and not absence.get(key):
            # Without proof the object was absent before Stage 1, a "create" may be an existing
            # object SECP is about to adopt because it happens to share an identifier.
            reasons.append(f"sdn_create_without_absence_evidence:{differential.family}:{named}")
        if differential.action == ACTION_DELETE and not differential.active_digest:
            reasons.append(f"sdn_delete_without_active_evidence:{differential.family}:{named}")

    return tuple(dict.fromkeys(reasons))
