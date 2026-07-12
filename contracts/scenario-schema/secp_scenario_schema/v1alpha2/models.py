"""Pydantic models for the controlplane.security/v1alpha2 environment schema.

Additive successor to v1alpha1 (ADR-016 / SECP-B10). It carries forward every
v1alpha1 field and behavior unchanged (the shared field models are imported from
v1alpha1) and adds two typed OPTIONAL blocks under ``spec``:

* ``spec.topology`` — the canonical topology object. Its shape and bounds MIRROR
  the authoritative ``secp.topology/v1`` document produced by
  ``apps/api/secp_api/topology_authoring_contract.py``. This is a pure contract
  package and must not import ``secp_api`` (layering), so the constants below are
  kept in sync with that contract, which remains authoritative during
  reconstruction.
* ``spec.publicationProvenance`` — the stable, hash-covered provenance block
  locked by ADR-016.

Both blocks are schema-optional (ordinary schema validation may run on a
non-topology publication input before composition); the publication composition
contract requires both in its final output.
"""

from __future__ import annotations

from enum import Enum
from typing import Annotated, Final, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from secp_scenario_schema.v1alpha1.models import Metadata
from secp_scenario_schema.v1alpha1.models import Spec as SpecV1alpha1

API_VERSION = "controlplane.security/v1alpha2"

# The single locked publication-contract version (ADR-016 / SECP-B10). Defined
# once here (as a precise Literal constant so it can be the default of a Literal
# field) and consumed by the publication contract implementation and tests.
PUBLICATION_CONTRACT_VERSION: Final[Literal["secp.publication/v1"]] = "secp.publication/v1"

# Mirrors CANONICAL_SCHEMA_VERSION in secp_api.topology_authoring_contract. The
# current publication contract supports exactly this topology schema version; a
# different topology version is never silently accepted.
TOPOLOGY_SCHEMA_VERSION = "secp.topology/v1"

# Bounds/patterns mirrored from the authoritative topology contract (kept in
# sync). Never weaken relative to that contract.
_TOP_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$"
_TOP_IP_PATTERN = r"^\d{1,3}(\.\d{1,3}){3}$"
_TOP_CIDR_PATTERN = r"^\d{1,3}(\.\d{1,3}){3}/\d{1,2}$"
_TOP_MAX_LABEL = 120
_TOP_MAX_STRING = 200

_UUID_PATTERN = r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
_HASH_PATTERN = r"^sha256:[0-9a-f]{64}$"


class _Base(BaseModel):
    model_config = ConfigDict(extra="forbid")


class TopologyNodeKind(str, Enum):
    attacker = "attacker"
    target = "target"
    sensor = "sensor"
    network = "network"


class TopologyEdgeKind(str, Enum):
    network = "network"
    monitors = "monitors"
    reaches = "reaches"


class TopologyNode(_Base):
    id: str = Field(pattern=_TOP_ID_PATTERN)
    kind: TopologyNodeKind
    label: str = Field(max_length=_TOP_MAX_LABEL)
    role: Annotated[str, Field(max_length=_TOP_MAX_STRING)] | None = None
    ip: Annotated[str, Field(pattern=_TOP_IP_PATTERN)] | None = None
    network: Annotated[str, Field(max_length=_TOP_MAX_STRING)] | None = None
    x: int | float
    y: int | float


class TopologyEdge(_Base):
    id: str = Field(pattern=_TOP_ID_PATTERN)
    source: str = Field(pattern=_TOP_ID_PATTERN)
    target: str = Field(pattern=_TOP_ID_PATTERN)
    kind: TopologyEdgeKind


class TopologyNetwork(_Base):
    id: str = Field(pattern=_TOP_ID_PATTERN)
    label: str = Field(max_length=_TOP_MAX_LABEL)
    cidr: Annotated[str, Field(pattern=_TOP_CIDR_PATTERN)] | None = None
    isolated: bool | None = None


class TopologyZone(_Base):
    id: str = Field(pattern=_TOP_ID_PATTERN)
    label: str = Field(max_length=_TOP_MAX_LABEL)
    kind: Annotated[str, Field(max_length=_TOP_MAX_STRING)] | None = None
    member_ids: list[Annotated[str, Field(pattern=_TOP_ID_PATTERN)]] = Field(default_factory=list)


class TopologyDocument(_Base):
    """The exact canonical secp.topology/v1 document shape."""

    schema_version: Literal["secp.topology/v1"]
    nodes: list[TopologyNode] = Field(default_factory=list)
    edges: list[TopologyEdge] = Field(default_factory=list)
    networks: list[TopologyNetwork] = Field(default_factory=list)
    zones: list[TopologyZone] = Field(default_factory=list)


class PublicationProvenance(_Base):
    """Stable, hash-covered provenance block (ADR-016 §D7/§D10). It holds only
    stable publication inputs and the contract version — never the new version
    id, a timestamp, created_by, an audit-event id, a correlation id, or a
    caller idempotency key."""

    topology_document_id: str = Field(pattern=_UUID_PATTERN)
    topology_revision_id: str = Field(pattern=_UUID_PATTERN)
    topology_content_hash: str = Field(pattern=_HASH_PATTERN)
    topology_validation_result_id: str = Field(pattern=_UUID_PATTERN)
    topology_validation_result_hash: str = Field(pattern=_HASH_PATTERN)
    base_environment_version_id: Annotated[str, Field(pattern=_UUID_PATTERN)] | None = None
    publication_contract_version: Literal["secp.publication/v1"]


class Spec(SpecV1alpha1):
    """v1alpha1 spec carried forward, plus the two additive optional blocks."""

    topology: TopologyDocument | None = None
    publicationProvenance: PublicationProvenance | None = None


class EnvironmentDefinition(_Base):
    apiVersion: str
    kind: str
    metadata: Metadata
    spec: Spec

    @model_validator(mode="after")
    def _check_kind_and_version(self) -> EnvironmentDefinition:
        if self.apiVersion != API_VERSION:
            raise ValueError(
                f"unsupported apiVersion '{self.apiVersion}', expected '{API_VERSION}'"
            )
        if self.kind != "Environment":
            raise ValueError(f"unsupported kind '{self.kind}', expected 'Environment'")
        return self
