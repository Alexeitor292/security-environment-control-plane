"""The five-stage SDN activation model, and the window it exists to close.

Proxmox commits SDN configuration with ``PUT /cluster/sdn``, which applies **every** pending change
on the cluster. There is no scoping attribute on the provider's applier resource and no per-object
apply in the API — so SECP cannot commit only its own SDN objects, and no amount of care in the
renderer changes that.

The model does not pretend to scope it. It makes the real blast radius explicit and separately
authorised:

======= ==========================================================================================
Stage 1 Prepare SECP-owned SDN configuration. Nothing is activated.
Stage 2 Rediscover and hash the COMPLETE cluster-wide pending state — SECP's changes and everyone
        else's.
Stage 3 Separately authorise that exact activation, against that exact hash.
Stage 4 Activate.
Stage 5 Verify the active SDN, and only then deploy guests.
======= ==========================================================================================

**The window.** Stages 2 and 4 are separated in time, and the pending state is cluster-wide and
mutable by anybody with SDN.Allocate. Between the operator seeing what would be committed and the
commit happening, a foreign change can be staged. Without a binding, that change is committed under
an authorisation that never saw it — the operator approved a set of three objects and four were
applied.

So the authorisation binds the **hash of the complete pending set**, and stage 4 refuses when the
observed hash no longer matches. That turns a silent widening into a refusal an operator resolves by
re-observing and re-authorising.

**The authorisation must show foreign changes, not filter them out.** An operator authorising this
activation is authorising somebody else's staged work too. Presenting only SECP's objects would make
the decision look smaller than it is, which is the specific dishonesty this module is written
against.

Pure: no I/O, no clock. ``now`` and observations are parameters.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum

from secp_commissioning.canonical import sha256_digest

STAGE_PREPARED = "prepared"
STAGE_PENDING_OBSERVED = "pending_observed"
STAGE_ACTIVATION_AUTHORIZED = "activation_authorized"
STAGE_ACTIVATED = "activated"
STAGE_VERIFIED = "verified"

#: Ordered. A stage may only be entered from its immediate predecessor — there is no path that
#: reaches activation without an authorisation bound to an observation.
STAGE_ORDER: tuple[str, ...] = (
    STAGE_PREPARED,
    STAGE_PENDING_OBSERVED,
    STAGE_ACTIVATION_AUTHORIZED,
    STAGE_ACTIVATED,
    STAGE_VERIFIED,
)

#: How long an observation of the pending set may back an authorisation. Short on purpose: this is
#: the exact interval during which a foreign change can be staged unseen, and the hash binding
#: catches it only when the observation is actually re-taken.
DEFAULT_PENDING_OBSERVATION_TTL = timedelta(minutes=10)


class SdnActivationRefused(Exception):
    """Activation refused. Carries a closed reason code, never a host or credential."""


class SdnObjectOwnership(str, Enum):
    """How a pending SDN object relates to the operation being authorised.

    Deliberately not a boolean. A bool is caller-assertable — whoever builds the object declares
    ownership — and ownership is exactly the claim that must be *derived*. The value here is
    produced by :func:`classify_ownership` from binding proof, never passed in.
    """

    #: Every applicable binding agreed. The only value MVP activation tolerates.
    operation_owned = "operation_owned"
    #: Provably not ours.
    foreign = "foreign"
    #: SECP's, but a different range, operation, or generation — including an earlier failed or
    #: abandoned one. Distinct from ``foreign`` because it is a different remediation.
    other_secp_operation = "other_secp_operation"
    #: Proof was incomplete. NOT a soft ``foreign``: it means we do not know, and the whole point
    #: is that not knowing must refuse rather than default either way.
    unknown = "unknown"
    #: Never submitted for classification at all.
    unclassified = "unclassified"


#: Everything MVP activation refuses on. Only ``operation_owned`` is absent.
NON_EXCLUSIVE_OWNERSHIP: frozenset[SdnObjectOwnership] = frozenset(
    {
        SdnObjectOwnership.foreign,
        SdnObjectOwnership.other_secp_operation,
        SdnObjectOwnership.unknown,
        SdnObjectOwnership.unclassified,
    }
)


@dataclass(frozen=True)
class OperationBinding:
    """What the current Stage 1 operation is, as the thing ownership is proven AGAINST."""

    target_identity: str
    cluster_fingerprint: str
    range_identity: str
    operation_identity: str
    operation_generation: int
    stage1_workspace_hash: str
    stage1_plan_hash: str
    stage1_authorization_id: str
    stage1_execution_receipt: str


@dataclass(frozen=True)
class ObjectOwnershipProof:
    """The per-object evidence ownership is derived from.

    Every field is a binding the observed object must match. A missing or disagreeing binding
    yields ``unknown`` — never ``operation_owned``, and never ``foreign``, because "we could not
    prove it is ours" and "we proved it is somebody else's" are different facts with different
    remediations.

    Explicitly NOT evidence, and absent from this structure on purpose:

    * an identifier beginning with a SECP prefix — reproducible by any actor;
    * a VNet alias mentioning SECP — same;
    * attribute equality with the desired plan — two actors can render the same values;
    * the object appearing after a Stage 1 run — coincidence is not causation;
    * absence from one earlier incomplete observation — an incomplete view proves nothing;
    * presence in an OpenTofu state file without target-side corroboration.
    """

    # --- which operation this object is claimed for ---------------------------------------------
    claimed_target_identity: str = ""
    claimed_cluster_fingerprint: str = ""
    claimed_range_identity: str = ""
    claimed_operation_identity: str = ""
    claimed_operation_generation: int = -1

    # --- what Stage 1 said it would do ------------------------------------------------------------
    stage1_desired_object_id: str = ""
    stage1_object_family: str = ""
    stage1_expected_action: str = ""  # create | change | delete
    stage1_workspace_hash: str = ""
    stage1_plan_hash: str = ""
    stage1_authorization_id: str = ""
    stage1_execution_receipt: str = ""

    # --- what was observed ------------------------------------------------------------------------
    #: The signed post-Stage-1 pending observation this object was seen in.
    post_stage1_observation_signed: bool = False
    #: For a NEW object: a signed PRE-Stage-1 observation, with complete visibility, showing the
    #: identifier absent from BOTH active and pending configuration and unowned by another range.
    pre_stage1_absence_proven: bool = False
    #: For an EXISTING object: durable SECP provenance that the same range lineage created or
    #: adopted it. Names and attribute equality do not substitute.
    durable_provenance_record: str = ""

    #: Set when the object is provably somebody else's rather than merely unproven.
    proven_foreign: bool = False


@dataclass(frozen=True)
class PendingSdnObject:
    """One staged SDN change. Ownership is a derived classification, not a constructor argument."""

    family: str  # zones | vnets | subnets | controllers
    object_id: str
    #: ``new`` | ``changed`` | ``deleted`` — Proxmox's own classification.
    state: str
    #: Defaults to ``unclassified``: an object nobody submitted for classification must not read as
    #: ours, and must not read as somebody else's either.
    ownership: SdnObjectOwnership = SdnObjectOwnership.unclassified

    def digest_tuple(self) -> tuple[str, str, str, str]:
        return (self.family, self.object_id, self.state, self.ownership.value)


def classify_ownership(
    obj: PendingSdnObject, proof: ObjectOwnershipProof, operation: OperationBinding
) -> SdnObjectOwnership:
    """Derive ownership from proof. Returns ``unknown`` on any incomplete binding.

    The order matters: ``proven_foreign`` is checked first because a positive proof that the object
    belongs to somebody else is stronger information than our own binding failing, and the operator
    should be told the stronger thing.
    """
    if proof.proven_foreign:
        return SdnObjectOwnership.foreign

    # A different range, operation or generation is SECP's but not THIS operation's — including an
    # earlier failed or abandoned run, whose leftovers must never ride along on a new approval.
    if (
        proof.claimed_range_identity
        and proof.claimed_operation_identity
        and (
            proof.claimed_range_identity != operation.range_identity
            or proof.claimed_operation_identity != operation.operation_identity
            or proof.claimed_operation_generation != operation.operation_generation
        )
    ):
        return SdnObjectOwnership.other_secp_operation

    bindings_agree = (
        proof.claimed_target_identity == operation.target_identity
        and proof.claimed_cluster_fingerprint == operation.cluster_fingerprint
        and proof.claimed_range_identity == operation.range_identity
        and proof.claimed_operation_identity == operation.operation_identity
        and proof.claimed_operation_generation == operation.operation_generation
        and proof.stage1_workspace_hash == operation.stage1_workspace_hash
        and proof.stage1_plan_hash == operation.stage1_plan_hash
        and proof.stage1_authorization_id == operation.stage1_authorization_id
        and proof.stage1_execution_receipt == operation.stage1_execution_receipt
        and proof.stage1_desired_object_id == obj.object_id
        and proof.stage1_object_family == obj.family
        and proof.stage1_expected_action == obj.state
        and proof.post_stage1_observation_signed
    )
    if not bindings_agree or not all(
        (
            proof.claimed_target_identity,
            proof.claimed_cluster_fingerprint,
            proof.claimed_range_identity,
            proof.claimed_operation_identity,
            proof.stage1_workspace_hash,
            proof.stage1_plan_hash,
            proof.stage1_authorization_id,
            proof.stage1_execution_receipt,
        )
    ):
        return SdnObjectOwnership.unknown

    # A NEW object additionally needs proof the identifier was free before Stage 1 — otherwise SECP
    # may have adopted somebody else's object that happened to share the name.
    if obj.state == "new":
        return (
            SdnObjectOwnership.operation_owned
            if proof.pre_stage1_absence_proven
            else SdnObjectOwnership.unknown
        )

    # A CHANGE or DELETE touches an object that already existed, so name and attribute agreement
    # cannot establish that SECP was the one who created it. Durable provenance is required.
    return (
        SdnObjectOwnership.operation_owned
        if proof.durable_provenance_record
        else SdnObjectOwnership.unknown
    )


@dataclass(frozen=True)
class PendingSdnObservation:
    """The complete cluster-wide pending set at one instant.

    ``complete`` is the field that decides whether this observation may back an authorisation at
    all. A partial enumeration — some family denied, some endpoint unsupported — cannot establish
    what activation would commit, and an activation authorised on a partial view is authorised on a
    guess.
    """

    observed_at: datetime
    objects: tuple[PendingSdnObject, ...] = ()
    #: False when any SDN family could not be enumerated with confirmed authority.
    complete: bool = False
    #: Families that could not be read, with the observation state that explains why.
    unreadable_families: tuple[tuple[str, str], ...] = ()

    def pending_hash(self) -> str:
        """Hash of the COMPLETE pending set, ordered deterministically.

        Includes foreign objects. Hashing only SECP's own changes would produce a stable hash while
        the thing actually being committed changed underneath it — which is precisely the failure
        this hash exists to detect.
        """
        rows = sorted(obj.digest_tuple() for obj in self.objects)
        return sha256_digest({"pending": [list(row) for row in rows]})

    @property
    def non_exclusive_objects(self) -> tuple[PendingSdnObject, ...]:
        """Every object that is not provably this operation's.

        Foreign, another SECP operation's, unknown and unclassified are all here. For MVP the
        distinction between them affects only the message an operator reads — every one of them
        refuses.
        """
        return tuple(obj for obj in self.objects if obj.ownership in NON_EXCLUSIVE_OWNERSHIP)

    def ownership_counts(self) -> dict[str, int]:
        """The counts an operator is shown, by classification.

        Reported even though MVP refuses on any non-zero total: "one foreign object" and "eleven
        objects from an abandoned run" call for very different next actions, and a bare refusal
        would send someone hunting for the difference.
        """
        counts = {member.value: 0 for member in SdnObjectOwnership}
        for obj in self.objects:
            counts[obj.ownership.value] += 1
        counts["total"] = len(self.objects)
        return counts

    @property
    def is_empty(self) -> bool:
        return not self.objects


@dataclass(frozen=True)
class ActivationAuthorization:
    """An operator's approval of one exact activation.

    Binds the observation's hash, not the plan's. Two activations of the same SECP objects over
    different cluster-wide pending sets are different acts, and only one of them was approved.
    """

    authorized_pending_hash: str
    authorized_at: datetime
    authorized_by: str
    target_identity: str
    operation_identity: str = ""
    operation_generation: int = -1
    #: The counts the operator was shown, recorded so a later reviewer can establish what was
    #: disclosed rather than inferring it.
    disclosed_counts: dict[str, int] = field(default_factory=dict)
    observation_ttl: timedelta = DEFAULT_PENDING_OBSERVATION_TTL

    def __post_init__(self) -> None:
        """MVP invariant, enforced at CONSTRUCTION.

        An authorisation covering a foreign or unknown object is **structurally invalid** for the
        first MVP, not merely refused later by a checker somebody could move or make conditional.
        Making it unconstructable means no code path can produce one to be checked.

        Accepting the foreign-object residual is deliberately NOT available through ordinary Stage 3
        approval. A mixed-owner or break-glass activation is a different operation kind with its own
        authorisation contract, explicit cluster-wide acknowledgement and — most likely — dual
        approval. It is outside the MVP and must not be reachable by an operator clicking through
        this one.
        """
        for key in ("foreign", "other_secp_operation", "unknown", "unclassified"):
            if self.disclosed_counts.get(key, 0):
                raise SdnActivationRefused(
                    "cluster_pending_sdn_not_exclusive_to_operation:"
                    f"{key}={self.disclosed_counts[key]}"
                )


def activation_refusals(
    *,
    stage: str,
    authorization: ActivationAuthorization | None,
    observation: PendingSdnObservation | None,
    now: datetime,
    expected_target_identity: str,
) -> tuple[str, ...]:
    """Every reason activation must not proceed. Empty means it may.

    All reasons are returned, not the first — an operator who re-observes to clear a stale hash only
    to meet a target mismatch has been told half the truth twice.
    """
    reasons: list[str] = []

    if stage != STAGE_ACTIVATION_AUTHORIZED:
        # Activation is reachable only from an authorised state. Naming the stage makes the refusal
        # actionable rather than merely negative.
        reasons.append(f"sdn_activation_wrong_stage:{stage}")

    if authorization is None:
        reasons.append("sdn_activation_unauthorized")
    if observation is None:
        reasons.append("sdn_activation_no_pending_observation")
    if authorization is None or observation is None:
        return tuple(reasons)

    if not observation.complete:
        # A partial view cannot establish what activation would commit. Distinct from "nothing
        # pending" — this is "we do not know what is pending".
        reasons.append("sdn_activation_pending_state_incomplete")
        for family, state in observation.unreadable_families:
            reasons.append(f"sdn_pending_family_unreadable:{family}:{state}")

    # THE binding. A foreign change staged between observation and activation moves this hash.
    if observation.pending_hash() != authorization.authorized_pending_hash:
        reasons.append("sdn_activation_pending_state_changed")

    age = now - observation.observed_at
    if age < timedelta(0):
        reasons.append("sdn_activation_observation_clock_skew")
    elif age > authorization.observation_ttl:
        reasons.append("sdn_activation_observation_expired")

    if authorization.target_identity != expected_target_identity:
        reasons.append("sdn_activation_target_mismatch")

    # THE MVP RULE. Re-checked here as well as at construction, because the observation is re-taken
    # immediately before activation and an object can have changed classification in between — a
    # foreign object staged after authorisation is exactly the case that must not activate.
    non_exclusive = observation.non_exclusive_objects
    if non_exclusive:
        counts = observation.ownership_counts()
        reasons.append(
            "cluster_pending_sdn_not_exclusive_to_operation:"
            f"total={counts['total']},"
            f"operation_owned={counts['operation_owned']},"
            f"foreign={counts['foreign']},"
            f"other_secp_operation={counts['other_secp_operation']},"
            f"unknown={counts['unknown']},"
            f"unclassified={counts['unclassified']}"
        )

    # An authorisation that did not disclose what it would commit did not describe the act being
    # authorised, even if its hash matches.
    if authorization.disclosed_counts != observation.ownership_counts():
        reasons.append("sdn_activation_disclosure_mismatch")

    return tuple(dict.fromkeys(reasons))


def next_stage(current: str) -> str:
    """The single legal successor. Raises rather than returning a default."""
    if current not in STAGE_ORDER:
        raise SdnActivationRefused(f"sdn_activation_unknown_stage:{current}")
    index = STAGE_ORDER.index(current)
    if index + 1 >= len(STAGE_ORDER):
        raise SdnActivationRefused("sdn_activation_already_verified")
    return STAGE_ORDER[index + 1]


def guests_may_deploy(stage: str) -> bool:
    """Guests attach to VNets, so they may not deploy until the SDN is verified ACTIVE.

    Not merely activated: ``PUT /cluster/sdn`` returning success means the task was accepted, not
    that every node has reloaded and the bridges exist. A guest attached to a VNet that has not
    materialised on its node fails in a way that looks like a guest problem.
    """
    return stage == STAGE_VERIFIED


@dataclass(frozen=True)
class ActivationRecord:
    """What is retained about one activation, for the operator manifest and for audit."""

    stage: str
    pending_hash_at_authorization: str = ""
    pending_hash_at_activation: str = ""
    #: Full per-classification counts rather than a foreign tally: an operator reading an audit
    #: record needs to know whether the blocker was somebody else's work, an abandoned run of our
    #: own, or an unproven object.
    ownership_counts_at_activation: dict[str, int] = field(default_factory=dict)
    activated_at: datetime | None = None
    verified_at: datetime | None = None
    refusal_reasons: tuple[str, ...] = field(default_factory=tuple)
