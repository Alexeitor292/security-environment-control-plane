"""Stage 2: a verified discovery snapshot becomes the canonical pending-SDN document.

The defect this module now closes: ``PendingSdnDocument.signature_verified`` was a plain dataclass
field, and this builder set it to ``True`` while reading ``visibility_complete`` and the entire
pending object set out of caller-supplied mappings the signature never covered. A caller holding a
genuine authority whose binding stated ``pending_sdn_state = permission_denied`` — the worker's
signed statement that it was NOT allowed to see SDN pending state — could hand in contradicting
mappings and obtain a document reporting ``signature_verified=True``, ``visibility_complete=True``,
``unreadable_families=()``. ``issue_activation_authorization`` gates on exactly those two booleans,
so the refusal the worker signed for was converted into "nothing is pending" and the cluster-wide
``PUT /cluster/sdn`` blast radius was judged against a pending set nobody observed.

Three things make that unreachable now:

1. **The booleans are not data.** ``signature_verified`` and ``visibility_complete`` are read-only
   properties of :class:`~secp_api.sdn_activation_stages.PendingSdnDocument`, backed by an
   :class:`AuthenticatedPendingContent` that only :func:`authenticate_pending_content` can produce.
   There is no field to stamp and no keyword to pass.
2. **The content must be the content that was signed.** The builder recomputes the fact commitment
   from the observations, required facts and contributions it was handed and refuses unless the
   digest equals ``authority.binding.facts_hash``. Raw mappings that were never signed do not
   authenticate, whatever they claim.
3. **Visibility comes from inside the signature.** ``visibility_complete`` is read from the signed
   ``required_fact_observation_states``, not from the caller's projection — so a binding that says
   ``permission_denied`` cannot yield a document that says the pending state is fully visible.

Identity and freshness are likewise read off the binding: target, operation, worker, release, and
``observed_at`` from the signed ``observation_completed_at``. Nothing about WHEN or WHERE is a
parameter, because the activation gate enforces staleness and cluster-binding on exactly those.

Nothing observed is dropped. A pending object whose identifier key is missing is kept with an empty
id and marked unidentified: it still occupies the cluster, and dropping it would shrink the pending
set that activation exclusivity is judged on, turning a contaminated cluster into a clean-looking
one.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime
from typing import NoReturn

from secp_commissioning.canonical import sha256_digest

from secp_api.discovery_fact_commitment import (
    FactContribution,
    build_fact_commitment,
    canonical_value,
)
from secp_api.discovery_observation import Observation
from secp_api.discovery_verification import VerifiedDiscoverySnapshot
from secp_api.sdn_activation_stages import (
    AuthenticatedPendingContent,
    PendingSdnDocument,
    PendingSdnObject,
    pending_content_token,
)
from secp_api.sdn_differential import derive_object_differential

#: Re-exported from the single control-plane declaration. The plane boundary forbids importing the
#: worker's copy, so a restatement across planes is unavoidable — but a test imports BOTH and
#: asserts they are equal, and inside this plane there is exactly one.
from secp_api.sdn_pending_families import PENDING_FAMILIES  # noqa: F401

#: Where each family's pending rows are recorded by the projection. Subnets are keyed per vnet
#: because there is no cluster-wide subnet index.
_SUBNET_PREFIX = "subnets@"

UNIDENTIFIED = "unidentified_pending_object"

#: The signed observation state that licenses a "the pending SDN state is fully visible" claim.
_OBSERVED = "observed"

PENDING_SDN_FACT = "pending_sdn_state"


class PendingObservationError(Exception):
    """A pending document could not be derived. A closed reason code."""


def authenticate_pending_content(
    *,
    authority: VerifiedDiscoverySnapshot,
    observations: Mapping[str, Observation],
    required_facts: Mapping[str, Observation],
    contributions: Mapping[str, Sequence[FactContribution]],
) -> AuthenticatedPendingContent:
    """Bind content to a verified snapshot, or refuse. The ONLY producer of the authenticated type.

    The check is a recomputation, not a comparison of labels: the fact commitment is rebuilt from
    the content offered and its digest must equal the ``facts_hash`` the worker signed. Content that
    was never signed therefore cannot be authenticated no matter how it is described, and content
    signed for a different target, cluster, operation or generation fails too — all five are inside
    the commitment.
    """
    if not isinstance(authority, VerifiedDiscoverySnapshot):
        raise PendingObservationError("pending_content_requires_a_verified_snapshot")

    binding = authority.binding
    commitment = build_fact_commitment(
        observations=observations,
        required_facts=required_facts,
        contributions=contributions,
        organization_identity=binding.organization_identity,
        target_identity=binding.target_identity,
        cluster_fingerprint=_signed_cluster_fingerprint(observations),
        operation_identity=binding.operation_identity,
        operation_generation=binding.operation_generation,
        expected_node_identities=_expected_nodes(observations),
    )
    if commitment.digest() != binding.facts_hash:
        raise PendingObservationError("pending_content_does_not_match_the_signed_facts")

    return AuthenticatedPendingContent(
        pending_content_token(),
        facts_hash=binding.facts_hash,
        pending_sdn_state=_signed_state(binding, PENDING_SDN_FACT),
    )


def _expected_nodes(observations: Mapping[str, Observation]) -> tuple[str, ...]:
    """The worker's derivation, restated so the recomputed commitment can match. Pinned by test."""
    names = observations.get("node_names")
    if names is None or not names.is_usable or not isinstance(names.value, (tuple, list)):
        return ()
    return tuple(sorted(str(n) for n in names.value))


def _signed_state(binding: object, fact: str) -> str:
    """The state the WORKER signed for one required fact.

    Read from inside the signature rather than from the caller's projection: the projection is
    recomputable by anyone, and the whole failure was a caller's recomputation contradicting the
    worker's attested one.
    """
    for name, state in getattr(binding, "required_fact_observation_states", ()):
        if name == fact:
            return str(state)
    return ""


def _signed_cluster_fingerprint(observations: Mapping[str, Observation]) -> str:
    """Recompute the fingerprint exactly as the worker did, so the digest can match.

    Kept beside the recomputation rather than imported from the worker: the control plane may not
    import worker internals, and a test pins the two implementations against each other.
    """
    identity = observations.get("cluster_identity")
    if identity is None or not identity.is_usable:
        return ""
    return sha256_digest({"cluster_identity": canonical_value(identity.value)})


def build_pending_sdn_document(
    *,
    authority: VerifiedDiscoverySnapshot,
    observations: Mapping[str, Observation],
    required_facts: Mapping[str, Observation],
    contributions: Mapping[str, Sequence[FactContribution]],
) -> PendingSdnDocument:
    """Derive the Stage 2 document. The only production construction site.

    Takes no ``signature_verified``, no ``visibility_complete``, no ``objects``, no
    ``target_identity``, no ``cluster_fingerprint`` and no ``observed_at``. Every one of those is
    either derived from content the signature covers or read off the binding, because every one of
    them is something the activation gate later enforces.
    """
    content = authenticate_pending_content(
        authority=authority,
        observations=observations,
        required_facts=required_facts,
        contributions=contributions,
    )
    binding = authority.binding

    raw_pending = observations.get(PENDING_SDN_FACT)
    families = raw_pending.value if raw_pending is not None and raw_pending.is_usable else {}
    if not isinstance(families, dict):
        families = {}

    return PendingSdnDocument(
        observed_at=_observed_at(binding),
        target_identity=binding.target_identity,
        cluster_fingerprint=_signed_cluster_fingerprint(observations),
        observation_identity=binding.operation_identity,
        worker_installation_id=binding.worker_installation_id,
        worker_release_fingerprint=binding.worker_release_fingerprint,
        objects=_objects(families),
        authentication=content,
        unreadable_families=_unreadable(families, content, observations),
    )


def _observed_at(binding: object) -> datetime:
    """The signed completion time. Freshness is enforced on this, so it may not be a parameter."""
    stamped = str(getattr(binding, "observation_completed_at", ""))
    try:
        return datetime.fromisoformat(stamped)
    except ValueError:
        raise PendingObservationError("signed_observation_time_unparseable") from None


def _objects(families: Mapping[str, object]) -> tuple[PendingSdnObject, ...]:
    """Every observed pending row, with its action DERIVED from the two views.

    The count out equals the count in. Nothing is filtered — not the unidentifiable rows, not the
    ambiguous ones — because an object dropped here is an object that stops blocking activation
    exclusivity, and ``PUT /cluster/sdn`` commits all of them.
    """
    endpoints = {scope: _endpoint(scope) for scope in families}
    out: list[PendingSdnObject] = []
    for differential, scope, row in _rows_with_scope(families):
        identifier = differential.object_id
        out.append(
            PendingSdnObject(
                family=differential.family,
                object_id=identifier,
                action=differential.action,
                target_state=differential.target_state,
                ambiguity_reason=differential.ambiguity_reason,
                active_present=differential.active_present,
                pending_present=differential.pending_present,
                # Digests rather than the values themselves: the document is hashed and shown to an
                # operator, and a raw SDN config can carry addressing an operator's audit log
                # should not silently accumulate.
                normalized_active_representation=differential.active_digest,
                normalized_pending_representation=differential.pending_digest,
                source_endpoint=endpoints[scope],
                observation_state="observed" if identifier else UNIDENTIFIED,
                raw_result_digest=_digest(row),
            )
        )
    return tuple(out)


def _rows_with_scope(families: Mapping[str, object]):
    """Walk every row once, keeping the scope it came from so its endpoint stays attributable."""
    for scope in sorted(families):
        rows = families[scope]
        if not isinstance(rows, (list, tuple)):
            continue
        family = scope.split("@", 1)[0]
        for row in rows:
            if isinstance(row, dict):
                yield derive_object_differential(family, row), scope, row


def observed_row_count(families: Mapping[str, object]) -> int:
    """How many pending rows the target actually reported, before any classification."""
    total = 0
    for rows in families.values():
        if isinstance(rows, (list, tuple)):
            total += sum(1 for row in rows if isinstance(row, dict))
    return total


def _endpoint(scope: str) -> str:
    """The reviewed path this family came from. Recorded, never used to build a request."""
    if scope.startswith(_SUBNET_PREFIX):
        return f"/cluster/sdn/vnets/{scope[len(_SUBNET_PREFIX) :]}/subnets"
    return f"/cluster/sdn/{scope}"


def _unreadable(
    families: Mapping[str, object],
    content: AuthenticatedPendingContent,
    observations: Mapping[str, Observation],
) -> tuple[tuple[str, str], ...]:
    """Every family that was NOT enumerated, with the SIGNED state that explains why.

    An operator refused for incomplete visibility needs to know which family to grant for; the
    refusal reason alone says only that something was missing. The state comes from the binding, so
    the diagnostic and the gate cannot disagree about why.
    """
    state = content.pending_sdn_state or "not_requested"
    if state != _OBSERVED:
        # The signed state says the pending read was not usable. Naming a subset of families as the
        # problem would be a guess; every family is unreadable because the whole read was.
        return tuple((family, state) for family in PENDING_FAMILIES)
    missing = [
        family for family in PENDING_FAMILIES if not _covered(families, family, observations)
    ]
    return tuple((family, state) for family in missing)


def _covered(
    families: Mapping[str, object], family: str, observations: Mapping[str, Observation]
) -> bool:
    """Whether a family was enumerated, including the case where there was nothing to enumerate.

    Subnets have no cluster-wide index, so coverage means "walked for every vnet". A cluster with no
    vnets has no subnets to walk, and reporting that as unreadable would contradict the completeness
    the required-fact projection computes from the same facts — a document that says visibility is
    complete while naming a family as unreadable is one an operator is right not to trust.
    """
    if family != "subnets":
        return family in families
    if any(scope.startswith(_SUBNET_PREFIX) for scope in families):
        return True
    vnets = observations.get("existing_vnets")
    return (
        vnets is not None and vnets.is_usable and isinstance(vnets.value, dict) and not vnets.value
    )


def _digest(value: object) -> str:
    if not value:
        return ""
    return sha256_digest({"value": canonical_value(value)})


def _unreachable() -> NoReturn:  # pragma: no cover - documents an impossible branch
    raise PendingObservationError("unreachable")
