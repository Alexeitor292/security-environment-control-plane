"""Stage 2: a verified discovery snapshot becomes the canonical pending-SDN document.

:class:`PendingSdnDocument` carries two booleans that decide whether an activation may be
authorised at all — ``signature_verified`` and ``visibility_complete``. On the dataclass they are
fields, and a field is something a caller assigns. This module is the only place a production
document comes into existence, and here both are CONCLUSIONS:

``signature_verified``
    True only when a :class:`VerifiedDiscoverySnapshot` was supplied — the opaque authority the
    control-plane verifier issues, which cannot be constructed, pickled or forged. The document's
    identity fields are read off that authority's binding rather than taken as parameters, so a
    document cannot claim a target the signature did not cover.
``visibility_complete``
    True only when the required-fact projection found ``pending_sdn_state`` usable. That is already
    the strict condition — the SDN read authority was demonstrated, every family was enumerated, and
    every observed vnet was walked for subnets — so completeness here is the same completeness
    compilation is gated on rather than a second, weaker opinion.

Nothing observed is dropped. A pending object whose identifier key is missing is kept with an empty
id and marked unidentified: it still occupies the cluster, and dropping it would shrink the pending
set that activation exclusivity is judged on, turning a contaminated cluster into a clean-looking
one.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime

from secp_commissioning.canonical import sha256_digest

from secp_api.discovery_observation import Observation
from secp_api.discovery_verification import VerifiedDiscoverySnapshot
from secp_api.sdn_activation_stages import PendingSdnDocument, PendingSdnObject

#: The families a complete enumeration must cover. Mirrors the worker's SDN_PENDING_FAMILIES; the
#: control plane may not import worker modules, so the list is restated and pinned by a test that
#: reads both.
PENDING_FAMILIES: tuple[str, ...] = ("zones", "vnets", "subnets", "controllers")

#: Where each family's pending rows are recorded by the projection. Subnets are keyed per vnet
#: because there is no cluster-wide subnet index.
_SUBNET_PREFIX = "subnets@"

UNIDENTIFIED = "unidentified_pending_object"


class PendingObservationError(Exception):
    """A pending document could not be derived. A closed reason code."""


def build_pending_sdn_document(
    *,
    authority: VerifiedDiscoverySnapshot,
    required_facts: Mapping[str, Observation],
    raw_observations: Mapping[str, Observation],
    cluster_fingerprint: str,
    observed_at: datetime,
) -> PendingSdnDocument:
    """Derive the Stage 2 document. The only production construction site.

    Takes the authority object rather than a ``signature_verified`` flag: the caller cannot assert
    that a snapshot verified, it can only hand over the thing the verifier issued.
    """
    if not isinstance(authority, VerifiedDiscoverySnapshot):
        raise PendingObservationError("pending_document_requires_a_verified_snapshot")

    binding = authority.binding
    pending_fact = required_facts.get("pending_sdn_state")
    visibility_complete = pending_fact is not None and pending_fact.is_usable

    raw_pending = raw_observations.get("pending_sdn_state")
    families = raw_pending.value if raw_pending is not None and raw_pending.is_usable else {}
    if not isinstance(families, dict):
        families = {}

    objects = _objects(families)
    return PendingSdnDocument(
        observed_at=observed_at,
        target_identity=binding.target_identity,
        cluster_fingerprint=cluster_fingerprint,
        observation_identity=binding.operation_identity,
        worker_installation_id=binding.worker_installation_id,
        worker_release_fingerprint=binding.worker_release_fingerprint,
        objects=objects,
        # Both derived, neither supplied.
        signature_verified=True,
        visibility_complete=visibility_complete,
        unreadable_families=_unreadable(families, pending_fact, raw_observations),
    )


def _objects(families: Mapping[str, object]) -> tuple[PendingSdnObject, ...]:
    out: list[PendingSdnObject] = []
    for scope in sorted(families):
        rows = families[scope]
        if not isinstance(rows, (list, tuple)):
            continue
        family = scope.split("@", 1)[0]
        endpoint = _endpoint(scope)
        for row in rows:
            if not isinstance(row, dict):
                continue
            identifier = str(row.get("object_id") or "")
            out.append(
                PendingSdnObject(
                    family=family,
                    object_id=identifier,
                    action=str(row.get("state") or ""),
                    # Digests rather than the values themselves: the document is hashed and shown to
                    # an operator, and a raw SDN config can carry addressing an operator's audit log
                    # should not silently accumulate.
                    normalized_active_representation=_digest(row.get("active")),
                    normalized_pending_representation=_digest(row.get("observed")),
                    source_endpoint=endpoint,
                    observation_state="observed" if identifier else UNIDENTIFIED,
                    raw_result_digest=_digest(row),
                )
            )
    return tuple(out)


def _endpoint(scope: str) -> str:
    """The reviewed path this family came from. Recorded, never used to build a request."""
    if scope.startswith(_SUBNET_PREFIX):
        return f"/cluster/sdn/vnets/{scope[len(_SUBNET_PREFIX) :]}/subnets"
    return f"/cluster/sdn/{scope}"


def _unreadable(
    families: Mapping[str, object],
    pending_fact: Observation | None,
    raw_observations: Mapping[str, Observation],
) -> tuple[tuple[str, str], ...]:
    """Every family that was NOT enumerated, with the state that explains why.

    An operator refused for incomplete visibility needs to know which family to grant for; the
    refusal reason alone says only that something was missing.
    """
    state = pending_fact.state.value if pending_fact is not None else "not_requested"
    missing = [
        family for family in PENDING_FAMILIES if not _covered(families, family, raw_observations)
    ]
    return tuple((family, state) for family in missing)


def _covered(
    families: Mapping[str, object], family: str, raw_observations: Mapping[str, Observation]
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
    vnets = raw_observations.get("existing_vnets")
    return (
        vnets is not None and vnets.is_usable and isinstance(vnets.value, dict) and not vnets.value
    )


def _digest(value: object) -> str:
    if not value:
        return ""
    return sha256_digest({"value": _canonicalisable(value)})


def _canonicalisable(value: object) -> object:
    """Tuples and nested mappings both appear here; normalise to JSON-safe shapes before hashing."""
    if isinstance(value, dict):
        return {
            str(k): _canonicalisable(v) for k, v in sorted(value.items(), key=lambda kv: str(kv[0]))
        }
    if isinstance(value, (list, tuple)):
        return [_canonicalisable(item) for item in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return repr(value)
