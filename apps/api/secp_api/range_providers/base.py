"""The provider-neutral range boundary.

A provider is handed an immutable :class:`RangeSpec` plus an :class:`OperationContext` to report
progress through, and returns observations. It never opens a database session, never decides a
lifecycle state, and never formats a user-facing verdict — those are the service's job. Keeping
that split is what makes ``local_docker`` replaceable by a real provider later without touching the
lifecycle model.

The vocabulary that matters here is :class:`TeardownResourceOutcome`. It has three members, not
two, because "I removed it and then looked and saw nothing" and "I could not look" are different
claims. A provider that cannot reach its control API MUST report ``unproven`` — never ``removed``.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from typing import Protocol

from secp_api.range_enums import RangeResourceKind, RangeStepStatus


class TeardownResourceOutcome(str, Enum):
    """What a teardown proved about ONE resource."""

    #: Confirmed absent by a probe that was itself demonstrably working.
    removed = "removed"
    #: Confirmed still present.
    present = "present"
    #: Not observable. The resource may or may not exist.
    unproven = "unproven"


@dataclass(frozen=True)
class ComponentSpec:
    """One deployable component of a range."""

    key: str
    name: str
    role: str
    image: str
    container_port: int | None = None
    protocol: str = "http"
    path: str = "/"
    env: dict[str, str] = field(default_factory=dict)
    #: Seconds to wait for the component to be observed responding before giving up.
    readiness_timeout_seconds: int = 180


@dataclass(frozen=True)
class RangeSpec:
    """Everything a provider needs to build one range instance."""

    range_id: str
    #: Short slug embedded in every resource name.
    resource_prefix: str
    components: tuple[ComponentSpec, ...]


@dataclass(frozen=True)
class ProviderHealth:
    """Whether the provider's control API is reachable right now."""

    reachable: bool
    #: Stable identity of the control API endpoint, used to detect that a later probe is talking to
    #: a DIFFERENT backend than the one that created the resources. ``None`` when unreachable.
    endpoint_id: str | None = None
    version: str | None = None
    detail: str | None = None


@dataclass(frozen=True)
class ResourceObservation:
    """One resource as the provider actually observed it."""

    kind: RangeResourceKind
    name: str
    component_key: str | None = None
    external_id: str | None = None
    image: str | None = None
    image_digest: str | None = None
    owner_label: str = ""
    host_port: int | None = None
    #: True only when the provider received an actual response from the thing, never merely
    #: because a create call exited zero.
    verified: bool = False
    detail: dict = field(default_factory=dict)


@dataclass(frozen=True)
class DeployResult:
    ok: bool
    resources: tuple[ResourceObservation, ...] = ()
    failure_code: str | None = None
    failure_message: str | None = None


@dataclass(frozen=True)
class TeardownObservation:
    """One resource's teardown outcome, plus the probe health that makes it interpretable."""

    kind: RangeResourceKind
    name: str
    external_id: str | None
    outcome: TeardownResourceOutcome
    detail: str | None = None


@dataclass(frozen=True)
class TeardownResult:
    """The full teardown record.

    ``probe_reachable`` is the health of the EXISTENCE CHECK at the moment it ran — deliberately
    re-measured after the removal attempts rather than reused from before them, because the whole
    hazard is that the removal and the check fail together.
    """

    probe_reachable: bool
    observations: tuple[TeardownObservation, ...] = ()
    reason: str | None = None


@dataclass
class RecordedStep:
    key: str
    label: str
    status: RangeStepStatus = RangeStepStatus.pending
    detail: str | None = None
    at: str | None = None


class OperationContext:
    """The provider's only channel back to the service: declare steps, then report on them.

    Every mutation goes through ``on_change`` so the service can persist progress as it happens.
    The provider cannot reach further than this — it has no session and no models.
    """

    def __init__(
        self,
        steps: list[RecordedStep],
        on_change: Callable[[list[RecordedStep], str | None], None],
        on_event: Callable[[str, str, str, dict], None],
    ) -> None:
        self._steps = steps
        self._on_change = on_change
        self._on_event = on_event
        self._phase: str | None = None

    @property
    def steps(self) -> list[RecordedStep]:
        return self._steps

    def _find(self, key: str) -> RecordedStep | None:
        for step in self._steps:
            if step.key == key:
                return step
        return None

    def begin(self, key: str, *, phase: str | None = None) -> None:
        step = self._find(key)
        if step is not None:
            step.status = RangeStepStatus.running
        if phase is not None:
            self._phase = phase
        self._on_change(self._steps, self._phase)

    def finish(
        self,
        key: str,
        status: RangeStepStatus,
        *,
        detail: str | None = None,
    ) -> None:
        step = self._find(key)
        if step is not None:
            step.status = status
            step.detail = detail
        self._on_change(self._steps, self._phase)

    def event(
        self,
        kind: str,
        message: str,
        *,
        level: str = "info",
        data: dict | None = None,
    ) -> None:
        self._on_event(kind, message, level, data or {})


class RangeProvider(Protocol):
    """The contract every range provider implements."""

    name: str

    def health(self) -> ProviderHealth:
        """Is the control API reachable? Cheap, side-effect free, and safe to call at any time."""
        ...

    def plan_steps(self, spec: RangeSpec, kind: str) -> list[RecordedStep]:
        """Declare the steps this operation will run, before running any of them."""
        ...

    def deploy(self, spec: RangeSpec, ctx: OperationContext) -> DeployResult:
        """Create the range's resources and verify readiness BY OBSERVATION."""
        ...

    def reset(
        self,
        spec: RangeSpec,
        existing: tuple[ResourceObservation, ...],
        ctx: OperationContext,
    ) -> DeployResult:
        """Return the range to its initial deployed state deterministically."""
        ...

    def destroy(
        self,
        spec: RangeSpec,
        existing: tuple[ResourceObservation, ...],
        ctx: OperationContext,
    ) -> TeardownResult:
        """Remove every resource this range owns — and nothing else — then prove the outcome."""
        ...
