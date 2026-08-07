"""Control-plane verification of a signed discovery snapshot, and the six results it produces.

The property this module exists to hold: **a valid signature is not eligibility.** It proves a
specific worker executed a specific operation at a specific time against a specific target. It says
nothing about whether enough was observed to compile a plan — and for the ``/version``-only slice,
the honest answer is that almost nothing was. Collapsing authenticity and completeness into one
``verified`` flag is how a cryptographically impeccable snapshot of six facts comes to authorise a
plan that needs twenty.

So the projection reports six results separately, and the eligibility ones are computed from the
required-fact table rather than from the signature.

**The anchor never comes from the envelope.** An envelope that supplies its own expected key
verifies itself, which is not verification. The control plane locates the durable
``WorkerIdentityRegistration`` for the worker the *authorized operation* names, takes
``verification_anchor_fingerprint`` from there, and only then looks at what the envelope presented.
The envelope's key may be checked for CONSISTENCY with that anchor; it may never establish it.

Missing registration, or a registration with no anchor, fails closed. "We could not find the
expected key" is not "any key will do".
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import NoReturn, SupportsIndex

from secp_commissioning.canonical import sha256_digest
from secp_commissioning.enrollment_attestation import (
    AttestationError,
    DetachedAttestation,
    key_id_for,
    verify_detached,
)

#: Discovery's own attestation domain. A worker's enrollment proof-of-possession must never be
#: presentable as an observation of a cluster, and vice versa.
DISCOVERY_SNAPSHOT_DOMAIN = "secp.target-discovery.observation/v1"
DISCOVERY_SNAPSHOT_KIND = "target-discovery-snapshot"
DISCOVERY_CONTRACT_VERSION = "secp-discovery/contract/v1"

# --- the six results ------------------------------------------------------------------------------

SIGNATURE_VALID = "valid"
SIGNATURE_MISSING = "missing"
SIGNATURE_INVALID = "invalid"
SIGNATURE_UNREGISTERED_SIGNER = "unregistered_signer"
SIGNATURE_NO_REGISTERED_ANCHOR = "no_registered_anchor"

BINDING_MATCHED = "matched"
BINDING_MISMATCHED = "mismatched"

FRESHNESS_CURRENT = "current"
FRESHNESS_STALE = "stale"
FRESHNESS_CLOCK_SKEW = "clock_skew"
FRESHNESS_UNBOUNDED = "unbounded"
FRESHNESS_INVALID_WINDOW = "invalid_window"

ELIGIBILITY_ELIGIBLE = "eligible"
ELIGIBILITY_REFUSED = "refused"

#: How far ahead of the evaluating clock an observation may be stamped before it is a fault.
DEFAULT_ALLOWED_SKEW = timedelta(seconds=60)
#: How far ahead is so implausible that it is not skew but a broken or hostile clock.
MAX_PLAUSIBLE_FUTURE = timedelta(hours=1)


class DiscoveryVerificationError(Exception):
    """A closed reason code. Never a host, key, path or credential."""


# --- the canonical binding
# -------------------------------------------------------------------------


@dataclass(frozen=True)
class DiscoverySnapshotBinding:
    """Everything the worker's signature covers.

    The operation-manifest hash is bound alongside the facts hash for a reason that one hash cannot
    serve: the facts say *what was concluded*, the manifest says *what was asked and what came
    back*. Signing only the facts would leave the response digest, the rendered path and the parser
    identity unattested — so a snapshot could keep its conclusions while the request that produced
    them was rewritten.
    """

    discovery_contract_version: str
    operation_identity: str
    operation_generation: int
    organization_identity: str
    target_identity: str
    requested_target_authority: str
    worker_installation_id: str
    worker_role: str
    worker_release_fingerprint: str
    signer_fingerprint: str
    observation_started_at: str
    observation_completed_at: str
    freshness_bound_seconds: int
    facts_hash: str
    operation_manifest_hash: str
    projection_implementation_id: str
    #: ``(fact, observation_state)`` pairs for the required set. Inside the signature so a consumer
    #: cannot be told a fact was merely absent when the producer recorded it permission-denied.
    required_fact_observation_states: tuple[tuple[str, str], ...] = ()

    def canonical(self) -> dict:
        return {
            "discovery_contract_version": self.discovery_contract_version,
            "operation_identity": self.operation_identity,
            "operation_generation": self.operation_generation,
            "organization_identity": self.organization_identity,
            "target_identity": self.target_identity,
            "requested_target_authority": self.requested_target_authority,
            "worker_installation_id": self.worker_installation_id,
            "worker_role": self.worker_role,
            "worker_release_fingerprint": self.worker_release_fingerprint,
            "signer_fingerprint": self.signer_fingerprint,
            "observation_started_at": self.observation_started_at,
            "observation_completed_at": self.observation_completed_at,
            "freshness_bound_seconds": self.freshness_bound_seconds,
            "facts_hash": self.facts_hash,
            "operation_manifest_hash": self.operation_manifest_hash,
            "projection_implementation_id": self.projection_implementation_id,
            "required_fact_observation_states": [
                list(pair) for pair in self.required_fact_observation_states
            ],
        }

    def digest(self) -> str:
        return sha256_digest(self.canonical())


#: The role a worker must claim to run Proxmox discovery. It is a property of the PROVIDER
#: DISCOVERY CONTRACT, not of the worker's enrollment record, and this is a deliberate decision
#: rather than a convenience.
#:
#: Worker enrollment storage is provider-neutral — machine-enforced, by
#: ``tests/test_pr5h_architecture_guards.py`` and ``apps/management/tests/test_provider_neutrality``
#: — so a ``worker_role`` column holding ``proxmox_privileged`` would put a Proxmox concept into
#: exactly the tree that forbids one. Declaring it here instead means the expected role is not
#: loadable, not configurable and not suppliable: there is no argument for it and no row that
#: carries it, so a caller cannot make the claim agree with itself.
REQUIRED_WORKER_ROLE = "proxmox_privileged"


@dataclass(frozen=True)
class ExpectedWorkerRegistration:
    """The durable WORKER registration the control plane loads. NEVER built from the envelope.

    Deliberately narrow: this record answers only "which worker, with which key, running which
    release". It does not carry the target, and it does not carry the role.

    * **The target is not here** because it comes from the durable authorized operation, which is a
      different row with a different lifecycle. Carrying it in both places meant a caller supplying
      a registration could contradict the operation, and the verifier already takes
      ``expected_target_identity`` separately — so the field was a second, unreconciled source for
      one fact. The old ``is_valid_for_target`` flag was the same problem wearing a boolean: it made
      "this registration may be used against this target" something a constructor asserted rather
      than something the loader established.
    * **The role is not here** because it belongs to the provider discovery contract
      (:data:`REQUIRED_WORKER_ROLE`) and enrollment storage is provider-neutral.

    What remains are exactly the three facts the control plane durably knows about a worker, plus
    the organization that scopes them.
    """

    worker_installation_id: str
    worker_release_fingerprint: str
    #: ``WorkerIdentityRegistration.verification_anchor_fingerprint``. The control plane stores only
    #: the fingerprint, so the envelope supplies the key and this is what it must derive.
    verification_anchor_fingerprint: str
    organization_identity: str


# --- the opaque authority
# ---------------------------------------------------------------------------

_VERIFIED_SNAPSHOT_TOKEN = object()


class VerifiedDiscoverySnapshot:
    """Proof that a snapshot verified. Issued ONLY by :func:`verify_discovery_snapshot`.

    Modelled on the repository's existing opaque-authority idiom — private-token construction,
    refused serialization, redacted repr — rather than a boolean anyone can set. A
    ``verified: bool`` on a public record is a field a caller assigns; this is a thing only the
    verifier can make.

    Bound to the exact snapshot and manifest hashes, so an authority for one snapshot cannot be
    offered for another.

    **Four escapes are closed explicitly**, because a token check in ``__init__`` alone is not a
    construction guard — an adversarial review demonstrated all of them:

    * ``object.__new__(cls)`` skips ``__init__`` entirely and yields an instance that satisfies
      every ``isinstance`` check its consumers make, so ``__new__`` carries the token check too;
    * a subclass can define its own ``__init__`` and never call this one, so subclassing is refused;
    * without ``__setattr__``, the ``__binding`` slot on an honestly issued authority is freely
      reassignable, so an authority for a refused snapshot can be repointed at a clean binding;
    * ``__delattr__`` would leave an authority whose binding raises on read rather than refusing.
    """

    __slots__ = ("__binding",)

    def __init_subclass__(cls, **kwargs: object) -> NoReturn:
        raise DiscoveryVerificationError(
            "VerifiedDiscoverySnapshot cannot be subclassed; a subclass could define an __init__ "
            "that never runs the issuance check while still satisfying isinstance"
        )

    def __new__(
        cls, token: object = None, *args: object, **kwargs: object
    ) -> VerifiedDiscoverySnapshot:
        if token is not _VERIFIED_SNAPSHOT_TOKEN:
            raise DiscoveryVerificationError(
                "VerifiedDiscoverySnapshot cannot be constructed directly; it is issued only by "
                "the control-plane verifier"
            )
        return super().__new__(cls)

    def __init__(self, token: object, binding: DiscoverySnapshotBinding) -> None:
        if token is not _VERIFIED_SNAPSHOT_TOKEN:
            raise DiscoveryVerificationError(
                "VerifiedDiscoverySnapshot cannot be constructed directly; it is issued only by "
                "the control-plane verifier"
            )
        object.__setattr__(self, "_VerifiedDiscoverySnapshot__binding", binding)

    def __setattr__(self, name: str, value: object) -> NoReturn:
        raise DiscoveryVerificationError(
            "VerifiedDiscoverySnapshot is immutable; repointing an issued authority at another "
            "binding would make it authority for a snapshot nobody verified"
        )

    def __delattr__(self, name: str) -> NoReturn:
        raise DiscoveryVerificationError("VerifiedDiscoverySnapshot is immutable")

    @property
    def binding(self) -> DiscoverySnapshotBinding:
        return object.__getattribute__(self, "_VerifiedDiscoverySnapshot__binding")  # type: ignore[no-any-return]

    def __repr__(self) -> str:
        return "VerifiedDiscoverySnapshot(<redacted>)"

    __str__ = __repr__

    def __format__(self, format_spec: str) -> str:
        return self.__repr__()

    def __getstate__(self) -> NoReturn:
        raise DiscoveryVerificationError("VerifiedDiscoverySnapshot cannot be serialized")

    def __reduce__(self) -> NoReturn:
        raise DiscoveryVerificationError("VerifiedDiscoverySnapshot cannot be pickled")

    def __reduce_ex__(self, protocol: SupportsIndex) -> NoReturn:
        raise DiscoveryVerificationError("VerifiedDiscoverySnapshot cannot be pickled")


# --- the projection
# ----------------------------------------------------------------------------------


@dataclass(frozen=True)
class DiscoveryVerificationProjection:
    """Six separate results. Deliberately not one ``verified`` flag.

    ``compilation_eligibility`` and ``apply_eligibility`` are computed from the required-fact table,
    never from the signature. For a ``/version``-only run both are ``refused``, and that is the
    correct answer rather than a limitation to be worked around.
    """

    signature: str
    identity_and_target_binding: str
    freshness: str
    required_fact_completeness: str
    compilation_eligibility: str
    apply_eligibility: str
    reasons: tuple[str, ...] = field(default_factory=tuple)
    missing_compilation_facts: tuple[tuple[str, str], ...] = ()
    missing_apply_facts: tuple[tuple[str, str], ...] = ()

    @property
    def authenticated(self) -> bool:
        """Authenticity alone. Never read this as permission to compile or apply."""
        return self.signature == SIGNATURE_VALID and (
            self.identity_and_target_binding == BINDING_MATCHED
        )


def _freshness(binding: DiscoverySnapshotBinding, *, now: datetime, allowed_skew: timedelta) -> str:
    started = _parse(binding.observation_started_at)
    completed = _parse(binding.observation_completed_at)
    if completed is None:
        # Not "current until proven otherwise" — a snapshot that cannot be aged at all.
        return FRESHNESS_UNBOUNDED
    if binding.freshness_bound_seconds <= 0:
        return FRESHNESS_INVALID_WINDOW
    if started is not None and completed < started:
        return FRESHNESS_INVALID_WINDOW
    if completed - now > MAX_PLAUSIBLE_FUTURE:
        return FRESHNESS_INVALID_WINDOW
    if completed - now > allowed_skew:
        # A clock ahead of ours is a fault. Reporting it as fresh would turn a broken clock into a
        # guarantee, and the error runs in the direction where a stale cluster looks current.
        return FRESHNESS_CLOCK_SKEW
    if (now - completed).total_seconds() > binding.freshness_bound_seconds:
        # Arrival time is NOT observation time: a newly received envelope carrying an old
        # observation is still stale.
        return FRESHNESS_STALE
    return FRESHNESS_CURRENT


def _parse(value: str) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def verify_discovery_snapshot(
    *,
    binding: DiscoverySnapshotBinding,
    attestation: object,
    registration: ExpectedWorkerRegistration | None,
    expected_operation_identity: str,
    expected_operation_generation: int,
    expected_target_identity: str,
    expected_organization_identity: str,
    facts_hash: str,
    operation_manifest_hash: str,
    compilation_required_facts: tuple[str, ...],
    apply_required_facts: tuple[str, ...],
    now: datetime,
    allowed_skew: timedelta = DEFAULT_ALLOWED_SKEW,
) -> tuple[DiscoveryVerificationProjection, VerifiedDiscoverySnapshot | None]:
    """Verify, then project. Returns the authority ONLY when authenticity and binding both hold.

    There is no ``expected_key`` parameter and no ``signature_valid`` parameter. The anchor comes
    from ``registration``, which the caller loaded from durable storage for the worker the
    authorized operation names — not from the envelope, and not from an argument a caller could
    choose to make agree.
    """
    reasons: list[str] = []

    # 1-3. Locate the registration and take the anchor from it. Missing either fails closed.
    if registration is None:
        return (
            _refused(SIGNATURE_NO_REGISTERED_ANCHOR, ("discovery_worker_registration_missing",)),
            None,
        )
    if not registration.verification_anchor_fingerprint:
        return (
            _refused(SIGNATURE_NO_REGISTERED_ANCHOR, ("discovery_verification_anchor_missing",)),
            None,
        )
    # There is no ``is_valid_for_target`` check here any more, and its absence is the point. It was
    # a boolean a constructor asserted; whether a registration may be used against this operation's
    # target is now established by the LOADER, which either produces a registration for the worker
    # the authorized operation names or produces none at all.

    # 4. Signer identity, against the DURABLE anchor.
    if not isinstance(attestation, DetachedAttestation):
        return (_refused(SIGNATURE_MISSING, ("discovery_attestation_absent",)), None)

    expected_key_id = registration.verification_anchor_fingerprint
    if attestation.key_id != expected_key_id:
        reasons.append("discovery_signer_not_the_registered_worker")
    if key_id_for(attestation.public_key_hex) != attestation.key_id:
        reasons.append("discovery_presented_key_does_not_derive_its_own_id")
    if binding.signer_fingerprint and binding.signer_fingerprint != attestation.key_id:
        reasons.append("discovery_binding_names_a_different_signer")
    if reasons:
        return (_refused(SIGNATURE_UNREGISTERED_SIGNER, tuple(reasons)), None)

    # 5-6. Reconstruct the canonical binding and verify the detached signature over its digest.
    try:
        verify_detached(
            attestation,
            domain=DISCOVERY_SNAPSHOT_DOMAIN,
            kind=DISCOVERY_SNAPSHOT_KIND,
            digest=binding.digest(),
            expected_key_id=expected_key_id,
        )
    except AttestationError as exc:
        return (_refused(SIGNATURE_INVALID, (f"discovery_attestation_invalid:{exc}",)), None)

    # 7. Bindings. Every mismatch is collected; an operator fixing one at a time learns slowly.
    binding_reasons: list[str] = []
    for label, actual, expected in (
        (
            "worker_installation",
            binding.worker_installation_id,
            registration.worker_installation_id,
        ),
        # Against the CONTRACT CONSTANT, not against a loaded or supplied value. There is no
        # expected-role argument and no column holding one, so the claim has nothing to agree with
        # except the reviewed constant.
        ("worker_role", binding.worker_role, REQUIRED_WORKER_ROLE),
        (
            "worker_release",
            binding.worker_release_fingerprint,
            registration.worker_release_fingerprint,
        ),
        ("target", binding.target_identity, expected_target_identity),
        ("organization", binding.organization_identity, expected_organization_identity),
        ("operation", binding.operation_identity, expected_operation_identity),
    ):
        if actual != expected:
            binding_reasons.append(f"discovery_binding_mismatch:{label}")
    if binding.operation_generation != expected_operation_generation:
        binding_reasons.append("discovery_binding_mismatch:operation_generation")
    if binding.facts_hash != facts_hash:
        binding_reasons.append("discovery_facts_changed_after_signing")
    if binding.operation_manifest_hash != operation_manifest_hash:
        binding_reasons.append("discovery_operation_manifest_changed_after_signing")
    if binding.discovery_contract_version != DISCOVERY_CONTRACT_VERSION:
        binding_reasons.append("discovery_contract_version_mismatch")

    binding_state = BINDING_MATCHED if not binding_reasons else BINDING_MISMATCHED

    # 8. Freshness, on the control plane's clock.
    freshness = _freshness(binding, now=now, allowed_skew=allowed_skew)

    # 9. Completeness, from the required-fact table. INDEPENDENT of the signature.
    states = dict(binding.required_fact_observation_states)
    missing_compilation = tuple(
        (fact, states.get(fact, "not_requested"))
        for fact in compilation_required_facts
        if states.get(fact) != "observed"
    )
    missing_apply = tuple(
        (fact, states.get(fact, "not_requested"))
        for fact in apply_required_facts
        if states.get(fact) != "observed"
    )
    completeness = "complete" if not missing_compilation and not missing_apply else "incomplete"

    authentic = binding_state == BINDING_MATCHED
    fresh = freshness == FRESHNESS_CURRENT

    # 10. Eligibility is a SEPARATE conclusion. A valid signature over six facts is a valid
    # signature over six facts.
    compilation = (
        ELIGIBILITY_ELIGIBLE
        if (authentic and fresh and not missing_compilation)
        else ELIGIBILITY_REFUSED
    )
    apply_eligibility = (
        ELIGIBILITY_ELIGIBLE
        if (authentic and fresh and not missing_compilation and not missing_apply)
        else ELIGIBILITY_REFUSED
    )

    projection = DiscoveryVerificationProjection(
        signature=SIGNATURE_VALID,
        identity_and_target_binding=binding_state,
        freshness=freshness,
        required_fact_completeness=completeness,
        compilation_eligibility=compilation,
        apply_eligibility=apply_eligibility,
        reasons=tuple(binding_reasons),
        missing_compilation_facts=missing_compilation,
        missing_apply_facts=missing_apply,
    )

    authority = VerifiedDiscoverySnapshot(_VERIFIED_SNAPSHOT_TOKEN, binding) if authentic else None
    return projection, authority


def _refused(signature_state: str, reasons: tuple[str, ...]) -> DiscoveryVerificationProjection:
    """Every downstream result is refused when authenticity could not be established.

    Not "unknown": a snapshot whose producer cannot be established supports no decision, and
    reporting eligibility as anything other than refused would invite one.
    """
    return DiscoveryVerificationProjection(
        signature=signature_state,
        identity_and_target_binding=BINDING_MISMATCHED,
        freshness=FRESHNESS_UNBOUNDED,
        required_fact_completeness="incomplete",
        compilation_eligibility=ELIGIBILITY_REFUSED,
        apply_eligibility=ELIGIBILITY_REFUSED,
        reasons=reasons,
    )
