"""Pure publication composition contract (ADR-016 / SECP-B10, PR A).

Framework-free and database-free. It composes a caller's non-topology
``controlplane.security/v1alpha2`` definition with the server-fetched approved
topology into a final composed EnvironmentDefinition, computes the canonical
environment content hash over the WHOLE definition object, and derives the
server-owned publication fingerprint — exactly as locked by ADR-016. It performs
NO persistence, holds NO database session, allocates NO version number, and
contacts NO infrastructure. Publication persistence, the API route, permissions,
audit, and the SELECT FOR UPDATE / idempotency lookup belong to later slices.

Every failure raises :class:`PublicationContractError` carrying an authoritative
closed string code (never backend exception text).

Allowed imports only: standard library, ``secp_scenario_schema``, the pure
``secp_api.topology_authoring_contract``, and Pydantic. It imports no SQLAlchemy,
FastAPI, session, ORM model, router, worker, provider, transport, HTTP client,
subprocess, socket, configuration, or secret resolver.
"""

from __future__ import annotations

import copy
import json
import uuid
from dataclasses import dataclass
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError
from secp_scenario_schema import canonicalize, content_hash, validate_definition
from secp_scenario_schema.v1alpha2.models import (
    API_VERSION as V1ALPHA2_API_VERSION,
)
from secp_scenario_schema.v1alpha2.models import (
    PUBLICATION_CONTRACT_VERSION,
    TopologyDocument,
)
from secp_scenario_schema.validator import SchemaValidationError

from secp_api.topology_authoring_contract import (
    TopologyDocumentError,
)
from secp_api.topology_authoring_contract import (
    canonicalize as topology_canonicalize,
)
from secp_api.topology_authoring_contract import (
    content_hash as topology_content_hash,
)
from secp_api.topology_authoring_contract import (
    validate_document as validate_topology_document,
)

_UNSUPPORTED_ROLE_KINDS = frozenset({"service", "gateway"})


class PublicationContractError(Exception):
    """A rejected publication composition. Carries only a closed code.

    These codes are intentionally NOT added to the global API error enums in this
    slice; that belongs to the later persistence/API slices.
    """

    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(code)
        self.code = code
        # detail is for tests/logs only — an API layer would serialize the code.
        self.detail = detail


class PublicationProvenanceInput(BaseModel):
    """Server-supplied stable provenance identities/hashes (never caller-trusted
    topology). UUID-validated identities and exact-format hash fields."""

    model_config = ConfigDict(extra="forbid")

    topology_document_id: uuid.UUID
    topology_revision_id: uuid.UUID
    topology_validation_result_id: uuid.UUID
    topology_validation_result_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    base_environment_version_id: uuid.UUID | None = None
    # Server-supplied; must be the single supported publication-contract version.
    # An unsupported/missing/unknown value makes the whole provenance input fail
    # closed as version_publish_provenance_invalid.
    publication_contract_version: Literal["secp.publication/v1"] = PUBLICATION_CONTRACT_VERSION


@dataclass(frozen=True)
class ComposedPublication:
    """Deeply immutable result of a successful composition.

    The authoritative composed definition is retained as canonical immutable JSON
    (a str — never a mutable dict/list). ``final_definition`` materializes a fresh
    deep copy on every access, so a caller mutating one returned dict can never
    diverge the result's canonical snapshot from ``environment_content_hash`` or
    ``publication_fingerprint``. Contains no version number, EnvironmentVersion id,
    actor, timestamp, audit id, plan, or workflow state."""

    environment_content_hash: str
    publication_fingerprint: str
    topology_content_hash: str
    publication_contract_version: str
    # The canonical (ADR-002) JSON of the final composed definition: the sole
    # authoritative hashed snapshot. An immutable str — never a caller publication
    # input; consumed only through the ``final_definition`` property.
    _canonical_definition_json: str

    @property
    def final_definition(self) -> dict[str, Any]:
        """A fresh deep copy of the composed definition on every access."""
        return json.loads(self._canonical_definition_json)


def reconstruct_canonical_topology(
    topology_document_content: Any,
    *,
    expected_content_hash: str | None = None,
) -> tuple[dict[str, Any], str]:
    """Validate + canonically reconstruct a topology document.

    Validates through the authoritative topology contract, reconstructs the
    canonical object using exactly ``topology_authoring_contract.canonicalize``'s
    semantic ordering (nodes/edges/networks/zones by id; each zone member_ids
    sorted), recomputes the topology content hash, optionally requires equality
    with an expected/stored hash, and verifies the result is the exact typed
    v1alpha2 topology object. Never uses raw caller list order.
    """
    try:
        normalized = validate_topology_document(topology_document_content)
    except TopologyDocumentError as exc:
        raise PublicationContractError("version_publish_topology_invalid", exc.code) from exc

    canonical_object = json.loads(topology_canonicalize(normalized))
    recomputed = topology_content_hash(normalized)
    if expected_content_hash is not None and recomputed != expected_content_hash:
        raise PublicationContractError("version_publish_topology_hash_mismatch")

    # The reconstructed object must be the exact typed topology object v1alpha2
    # expects — not merely "some canonicalized dict".
    try:
        TopologyDocument.model_validate(canonical_object)
    except ValidationError as exc:
        raise PublicationContractError("version_publish_topology_invalid", str(exc)) from exc
    return canonical_object, recomputed


def check_shared_field_consistency(definition: dict[str, Any], topology: dict[str, Any]) -> None:
    """Deterministic exact-equality consistency between a non-topology definition
    and the canonical topology object (ADR-016 §D5). Topology nodes are logical
    role nodes, not per-team/per-count instances. No case folding, slug fallback,
    label matching, fuzzy matching, defaulting, silent dropping, or fabrication;
    any missing/duplicate/ambiguous/contradictory condition fails closed."""
    spec = definition["spec"]
    roles = spec["roles"]
    declared_networks = spec["networks"]
    nodes = topology["nodes"]
    topo_networks = topology["networks"]
    edges = topology["edges"]

    network_node_ids = {n["id"] for n in nodes if n["kind"] == "network"}
    non_network_nodes = {n["id"]: n for n in nodes if n["kind"] != "network"}

    # --- roles <-> non-network nodes (exact one-to-one) -------------------------
    for role in roles:
        if role["kind"] in _UNSUPPORTED_ROLE_KINDS:
            raise PublicationContractError("version_publish_unsupported_role_kind", role["kind"])

    role_names = [r["name"] for r in roles]
    if len(role_names) != len(set(role_names)):
        raise PublicationContractError(
            "version_publish_role_topology_mismatch", "duplicate role name"
        )
    if set(role_names) != set(non_network_nodes):
        raise PublicationContractError(
            "version_publish_role_topology_mismatch", "role/node set mismatch"
        )
    for role in roles:
        node = non_network_nodes[role["name"]]
        if node["kind"] != role["kind"]:
            raise PublicationContractError("version_publish_role_topology_mismatch", "node kind")
        if node["network"] != role["network"]:
            raise PublicationContractError("version_publish_role_topology_mismatch", "node network")

    # --- declared networks <-> topology networks + network nodes (one-to-one) ---
    net_names = [n["name"] for n in declared_networks]
    if len(net_names) != len(set(net_names)):
        raise PublicationContractError(
            "version_publish_network_topology_mismatch", "duplicate network name"
        )
    topo_net_by_id: dict[str, dict[str, Any]] = {}
    for tn in topo_networks:
        if tn["id"] in topo_net_by_id:
            raise PublicationContractError(
                "version_publish_network_topology_mismatch", "duplicate topology network"
            )
        topo_net_by_id[tn["id"]] = tn
    if set(net_names) != set(topo_net_by_id):
        raise PublicationContractError(
            "version_publish_network_topology_mismatch", "network set mismatch"
        )
    if set(net_names) != network_node_ids:
        raise PublicationContractError(
            "version_publish_network_topology_mismatch", "network-node set mismatch"
        )
    for declared in declared_networks:
        tn = topo_net_by_id[declared["name"]]
        if tn["cidr"] is not None and tn["cidr"] != declared.get("baseCidr"):
            raise PublicationContractError("version_publish_network_topology_mismatch", "cidr")
        if tn["isolated"] is not None and tn["isolated"] != declared.get("isolated", True):
            raise PublicationContractError("version_publish_network_topology_mismatch", "isolated")

    # --- network-attachment edges (exact one per non-network node) --------------
    attachments: dict[str, list[str]] = {}
    for edge in edges:
        if edge["kind"] != "network":
            continue
        if edge["source"] not in non_network_nodes:
            raise PublicationContractError(
                "version_publish_network_topology_mismatch", "edge source is not a host node"
            )
        if edge["target"] not in network_node_ids:
            raise PublicationContractError(
                "version_publish_network_topology_mismatch", "edge target is not a network node"
            )
        attachments.setdefault(edge["source"], []).append(edge["target"])
    for name, node in non_network_nodes.items():
        targets = attachments.get(name, [])
        if len(targets) == 0:
            raise PublicationContractError(
                "version_publish_network_topology_mismatch", "missing attachment"
            )
        if len(targets) > 1:
            raise PublicationContractError(
                "version_publish_network_topology_mismatch", "ambiguous attachment"
            )
        if targets[0] != node["network"]:
            raise PublicationContractError(
                "version_publish_network_topology_mismatch", "incorrect network-edge target"
            )


def compose_published_definition(
    *,
    definition: dict[str, Any],
    topology_document_content: Any,
    expected_topology_content_hash: str,
    provenance: dict[str, Any],
    destination_template_id: str,
) -> ComposedPublication:
    """Compose a final immutable v1alpha2 EnvironmentDefinition + hashes.

    Rejects caller-supplied topology/provenance, requires apiVersion v1alpha2,
    validates the non-topology definition, canonically reconstructs the topology
    and requires the expected hash, runs the exact consistency checks, injects the
    canonical topology and server-derived provenance into a NEW object (caller
    input is never mutated), validates the final composed definition, and computes
    the environment content hash and publication fingerprint (ADR-016).
    """
    try:
        if not isinstance(definition, dict):
            raise PublicationContractError("version_publish_definition_invalid", "not a mapping")

        spec_in = definition.get("spec")
        if isinstance(spec_in, dict):
            if "topology" in spec_in:
                raise PublicationContractError("version_publish_topology_in_payload_forbidden")
            if "publicationProvenance" in spec_in:
                raise PublicationContractError("version_publish_provenance_in_payload_forbidden")

        if definition.get("apiVersion") != V1ALPHA2_API_VERSION:
            raise PublicationContractError("version_publish_definition_invalid", "apiVersion")

        try:
            validate_definition(definition)
        except SchemaValidationError as exc:
            raise PublicationContractError("version_publish_definition_invalid", str(exc)) from exc

        try:
            prov = PublicationProvenanceInput.model_validate(provenance)
        except (ValidationError, ValueError, TypeError) as exc:
            raise PublicationContractError("version_publish_provenance_invalid", str(exc)) from exc

        try:
            template_uuid = uuid.UUID(str(destination_template_id))
        except (ValueError, TypeError, AttributeError) as exc:
            raise PublicationContractError(
                "version_publish_provenance_invalid", "template_id"
            ) from exc

        canonical_topology, topo_hash = reconstruct_canonical_topology(
            topology_document_content, expected_content_hash=expected_topology_content_hash
        )
        check_shared_field_consistency(definition, canonical_topology)

        provenance_block = {
            "topology_document_id": str(prov.topology_document_id),
            "topology_revision_id": str(prov.topology_revision_id),
            "topology_content_hash": topo_hash,
            "topology_validation_result_id": str(prov.topology_validation_result_id),
            "topology_validation_result_hash": prov.topology_validation_result_hash,
            "base_environment_version_id": (
                str(prov.base_environment_version_id)
                if prov.base_environment_version_id is not None
                else None
            ),
            "publication_contract_version": prov.publication_contract_version,
        }

        final_definition = copy.deepcopy(definition)
        final_definition["spec"]["topology"] = canonical_topology
        final_definition["spec"]["publicationProvenance"] = provenance_block

        try:
            validate_definition(final_definition)
        except SchemaValidationError as exc:  # defensive: composed output must validate
            raise PublicationContractError("version_publish_definition_invalid", str(exc)) from exc

        canonical_definition_json = canonicalize(final_definition)
        environment_content_hash = content_hash(final_definition)
        publication_fingerprint = content_hash(
            {
                "template_id": str(template_uuid),
                "environment_content_hash": environment_content_hash,
            }
        )
        return ComposedPublication(
            environment_content_hash=environment_content_hash,
            publication_fingerprint=publication_fingerprint,
            topology_content_hash=topo_hash,
            publication_contract_version=prov.publication_contract_version,
            _canonical_definition_json=canonical_definition_json,
        )
    except PublicationContractError:
        raise
    except Exception as exc:
        # Fail closed at the public boundary: no jsonschema / pydantic
        # ValidationError / SchemaValidationError / KeyError / TypeError /
        # ValueError may escape directly — all normalize to a closed code.
        raise PublicationContractError("version_publish_definition_invalid", str(exc)) from exc
