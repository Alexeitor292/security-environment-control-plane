"""Pydantic models for the controlplane.security/v1alpha1 environment schema.

These provide typed access and a second layer of validation (cross-field
semantics the JSON Schema cannot easily express) on top of the JSON Schema.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, ConfigDict, Field, model_validator

API_VERSION = "controlplane.security/v1alpha1"


class IsolationPolicy(str, Enum):
    strict = "strict"
    shared = "shared"


class CidrStrategy(str, Enum):
    per_team = "per-team"
    shared = "shared"


class RoleKind(str, Enum):
    attacker = "attacker"
    target = "target"
    sensor = "sensor"
    service = "service"
    gateway = "gateway"


class _Base(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Metadata(_Base):
    name: str = Field(pattern=r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$", max_length=63)
    displayName: str | None = None
    description: str | None = None
    labels: dict[str, str] = Field(default_factory=dict)


class Teams(_Base):
    count: int = Field(ge=1, le=64)
    isolationPolicy: IsolationPolicy


class Network(_Base):
    name: str = Field(pattern=r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$")
    cidrStrategy: CidrStrategy
    baseCidr: str | None = None
    isolated: bool = True


class Role(_Base):
    name: str = Field(pattern=r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$")
    kind: RoleKind
    image: str
    network: str
    count: int = Field(default=1, ge=1, le=16)
    vulnerabilityPacks: list[str] = Field(default_factory=list)


class VulnerabilityPackRef(_Base):
    ref: str
    version: str | None = None


class Telemetry(_Base):
    providers: list[str] = Field(min_length=1)


class Objective(_Base):
    id: str = Field(pattern=r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$")
    description: str
    points: int = Field(default=0, ge=0)


class Validation(_Base):
    provider: str
    objectives: list[Objective] = Field(min_length=1)


class ResetPolicy(_Base):
    strategy: str = "rebuild-from-baseline"


class DestroyPolicy(_Base):
    strategy: str = "full-teardown"


class Spec(_Base):
    teams: Teams
    networks: list[Network] = Field(min_length=1)
    roles: list[Role] = Field(min_length=1)
    vulnerabilityPacks: list[VulnerabilityPackRef] = Field(default_factory=list)
    telemetry: Telemetry | None = None
    validation: Validation | None = None
    requiredPlugins: list[str] = Field(min_length=1)
    resetPolicy: ResetPolicy = Field(default_factory=ResetPolicy)
    destroyPolicy: DestroyPolicy = Field(default_factory=DestroyPolicy)

    @model_validator(mode="after")
    def _roles_reference_declared_networks(self) -> Spec:
        declared = {n.name for n in self.networks}
        for role in self.roles:
            if role.network not in declared:
                raise ValueError(
                    f"role '{role.name}' references undeclared network "
                    f"'{role.network}' (declared: {sorted(declared)})"
                )
        return self


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
