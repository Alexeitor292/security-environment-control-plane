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


@dataclass(frozen=True)
class PendingSdnObject:
    """One staged SDN change, with its ownership established rather than assumed."""

    family: str  # zones | vnets | subnets | controllers
    object_id: str
    #: ``new`` | ``changed`` | ``deleted`` — Proxmox's own classification.
    state: str
    #: True only when SECP can positively establish the object as its own. Absence of a SECP marker
    #: makes this False, which is the safe direction: an object we cannot prove is ours is treated
    #: as foreign and shown to the operator.
    secp_owned: bool = False

    def digest_tuple(self) -> tuple[str, str, str, bool]:
        return (self.family, self.object_id, self.state, self.secp_owned)


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
    def foreign_objects(self) -> tuple[PendingSdnObject, ...]:
        """Everything that is not provably SECP's. The operator is authorising these too."""
        return tuple(obj for obj in self.objects if not obj.secp_owned)

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
    #: What the operator was shown. Recorded so a later reviewer can establish that the foreign
    #: changes were disclosed rather than filtered.
    disclosed_foreign_object_count: int = 0
    observation_ttl: timedelta = DEFAULT_PENDING_OBSERVATION_TTL


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

    # An authorisation that did not disclose the foreign objects it would commit did not describe
    # the act being authorised, even if its hash matches.
    if len(observation.foreign_objects) != authorization.disclosed_foreign_object_count:
        reasons.append("sdn_activation_foreign_disclosure_mismatch")

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
    foreign_object_count: int = 0
    activated_at: datetime | None = None
    verified_at: datetime | None = None
    refusal_reasons: tuple[str, ...] = field(default_factory=tuple)
