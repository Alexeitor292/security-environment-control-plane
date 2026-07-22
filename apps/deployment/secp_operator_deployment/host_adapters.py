"""Read-only real-host commissioning adapters (SECP-PR5D).

The reviewed deployment topology is: the OPERATOR is prepared/disabled systemd service material; the
ORDINARY worker is an existing DOCKER container; ordinary readiness is the EXACT pinned health
contract — never merely systemd ``ActiveState`` or Docker running-state. These adapters model that
faithfully and produce ONE coherent, consistency-checked observation (design B): a bounded sequence
of read-only observations with before/after revalidation of the operator unit AND the ordinary
container — including GENERATION markers (systemd ``InvocationID`` +
``StateChangeTimestampMonotonic``; Docker ``RestartCount`` / ``StartedAt`` / ``FinishedAt`` /
``Pid``) so an ABA restart that returns to the same visible running state is REFUSED, not accepted.
Any missing / partial / bad / changed / timed-out / inconsistent observation returns the
fail-closed evidence. No mutation verb exists.

Every host executable is invoked ONLY through the pinned, bounded, streaming command seam
(:mod:`host_process` + :mod:`pinned_exec`): the container runtime and the service inspector are
object-pinned by path+digest; the ordinary health contract runs via ``<container-runtime> exec
<container> <health-argv>`` (so the only host binary is the pinned container runtime, and the health
probe is the worker's own reviewed contract, not a host helper that could contact
Temporal/PostgreSQL). Host-facts composition reuses ``secp_commissioning.inspect_host`` — no
plan/install/status/evidence logic is duplicated here. The deployment-owned
:class:`HostObservationEvidence` is the strong, exact-typed observation the read-only verifier
consumes; a ``ServiceStateSnapshot`` is derived from it for the reused ``inspect_host`` seam.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass

from secp_commissioning.status import ServiceStateSnapshot

from secp_operator_deployment import DeploymentPackageError
from secp_operator_deployment.host_process import CommandRunner, RealCommandRunner
from secp_operator_deployment.identities import ExpectedDeploymentIdentities
from secp_operator_deployment.pinned_exec import ExecutablePin
from secp_operator_deployment.profile import DeploymentProfile

_SHA_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
# The operator observation is ONE `systemctl show` reading exactly these properties (one bounded
# call per observation, not three independently timed calls). LoadState/ActiveState/UnitFileState
# are classified; InvocationID + StateChangeTimestampMonotonic are GENERATION markers compared
# verbatim.
_OPERATOR_PROPERTIES = (
    "LoadState",
    "ActiveState",
    "UnitFileState",
    "InvocationID",
    "StateChangeTimestampMonotonic",
)
_INVOCATION_ID = re.compile(r"[0-9a-f]{32}")  # 128-bit systemd invocation id (empty when never run)
_MONOTONIC = re.compile(r"[0-9]{1,20}")  # microseconds since boot
# The ordinary container is ONE `docker inspect --format` reading id + running + GENERATION
# markers.
_CONTAINER_FORMAT = (
    "{{.Id}} {{.State.Running}} {{.RestartCount}} "
    "{{.State.StartedAt}} {{.State.FinishedAt}} {{.State.Pid}}"
)
_TS = r"\d{4}-\d{2}-\d{2}T[0-9:.]+(?:Z|[+-]\d{2}:\d{2})"
# Strict closed grammar: full 64-lowercase-hex id, running bool, restart count, StartedAt,
# FinishedAt, Pid — exactly six space-separated fields, nothing else. A short/uppercase/non-hex id,
# missing/extra field, malformed timestamp/int, extra line or whitespace fails closed.
_DOCKER_INSPECT_LINE = re.compile(
    rf"[0-9a-f]{{64}} (?:true|false) \d{{1,9}} {_TS} {_TS} \d{{1,10}}"
)
_MAX_OUTPUT_BYTES = 64 * 1024
_CONTAINER_TIMEOUT_SECONDS = 10
_SERVICE_TIMEOUT_SECONDS = 10
_HEALTH_TIMEOUT_SECONDS = 20
_OBSERVATION_WINDOW_SECONDS = 30


# --------------------------------------------------------------------------- container-runtime
# adapter


@dataclass(frozen=True)
class LocalContainerRuntimeAdapter:
    """Answers ONLY whether an exact ``sha256:`` image digest is present in the LOCAL store, via the
    pinned container runtime: never pulls, never resolves a tag/floating reference."""

    container_runtime: ExecutablePin
    runner: CommandRunner
    timeout_seconds: int = _CONTAINER_TIMEOUT_SECONDS
    max_output_bytes: int = _MAX_OUTPUT_BYTES

    def image_present(self, digest: str) -> bool:
        if not (isinstance(digest, str) and _SHA_DIGEST.match(digest)):
            raise DeploymentPackageError("image_reference_not_exact_digest")
        result = self.runner.run(
            self.container_runtime,
            ("image", "inspect", "--format", "{{.Id}}", digest),
            timeout_seconds=self.timeout_seconds,
            max_output_bytes=self.max_output_bytes,
        )
        if result.exit_code != 0:
            return False  # absent locally; the inspect fails closed and NEVER pulls
        if result.stdout.strip() == digest:
            return True
        raise DeploymentPackageError("image_runtime_output_malformed")


# --------------------------------------------------------------------------- strong observation
# evidence


@dataclass(frozen=True)
class _OperatorObservation:
    """One bounded systemd observation of the operator unit, including generation markers."""

    load_state: str
    active_state: str
    unit_file_state: str
    invocation_id: str
    state_change_monotonic: str


@dataclass(frozen=True)
class _ContainerObservation:
    """One bounded Docker observation of the ordinary container, including generation markers. An
    absent container is ``present=False`` with empty markers, so absent-before == absent-after."""

    present: bool
    container_id: str
    running: bool
    restart_count: str
    started_at: str
    finished_at: str
    pid: str


@dataclass(frozen=True)
class HostObservationEvidence:
    """The deployment-owned, exact-typed result of ONE coherent read-only host observation.
    ``coherent`` is True only when the operator unit AND the ordinary container (including their
    GENERATION markers) were byte-identical before and after the health probe within the bounded
    window — so an ABA restart that returns to the same visible running state yields
    ``coherent=False``. The read-only verifier requires this EXACT type; a ``ServiceStateSnapshot``
    is derived for the reused ``inspect_host``."""

    inspected: bool
    coherent: bool
    operator_present: bool
    operator_enabled: bool
    operator_running: bool
    ordinary_running: bool

    def to_service_state_snapshot(self) -> ServiceStateSnapshot:
        return ServiceStateSnapshot(
            inspected=self.inspected,
            operator_present=self.operator_present,
            operator_enabled=self.operator_enabled,
            operator_running=self.operator_running,
            ordinary_running=self.ordinary_running,
        )


def _unavailable_evidence() -> HostObservationEvidence:
    # Fail closed: not inspected / not coherent; operator conservatively ACTIVE, ordinary DOWN →
    # every gate refuses.
    return HostObservationEvidence(
        inspected=False,
        coherent=False,
        operator_present=True,
        operator_enabled=True,
        operator_running=True,
        ordinary_running=False,
    )


def _unavailable_snapshot() -> ServiceStateSnapshot:
    return _unavailable_evidence().to_service_state_snapshot()


@dataclass(frozen=True)
class WorkerGenerationObservation:
    """A narrowly-scoped INTERNAL projection of ONE coherent host observation.

    ``HostObservationEvidence`` intentionally exposes only booleans; this projection additionally
    carries the raw generation facts (ordinary container id / running / RestartCount / StartedAt /
    FinishedAt / Pid / health + the operator systemd InvocationID and states) so an out-of-package
    coherent observer (the SECP-PR5G management host observer) can derive its opaque ABA generation
    marker WITHOUT running a second Docker/systemd parser.  It is NEVER serialized into any public
    evidence/status/API model: it has no ``canonical()`` and the management observer hashes these
    facts into an opaque marker, exposing only that marker.  ``evidence()`` re-derives the exact
    ``HostObservationEvidence`` so the two observations stay byte-identical."""

    inspected: bool
    coherent: bool
    operator_present: bool
    operator_enabled: bool
    operator_running: bool
    ordinary_running: bool
    ordinary_present: bool
    ordinary_container_id: str
    ordinary_restart_count: str
    ordinary_started_at: str
    ordinary_finished_at: str
    ordinary_pid: str
    ordinary_healthy: bool
    operator_invocation_id: str
    operator_load_state: str
    operator_active_state: str
    operator_unit_file_state: str
    operator_state_change_monotonic: str

    def evidence(self) -> HostObservationEvidence:
        return HostObservationEvidence(
            inspected=self.inspected,
            coherent=self.coherent,
            operator_present=self.operator_present,
            operator_enabled=self.operator_enabled,
            operator_running=self.operator_running,
            ordinary_running=self.ordinary_running,
        )


def _unavailable_generation() -> WorkerGenerationObservation:
    # Same fail-closed posture as _unavailable_evidence (operator conservatively ACTIVE, ordinary
    # DOWN, not coherent) with empty raw generation facts.
    return WorkerGenerationObservation(
        inspected=False,
        coherent=False,
        operator_present=True,
        operator_enabled=True,
        operator_running=True,
        ordinary_running=False,
        ordinary_present=False,
        ordinary_container_id="",
        ordinary_restart_count="",
        ordinary_started_at="",
        ordinary_finished_at="",
        ordinary_pid="",
        ordinary_healthy=False,
        operator_invocation_id="",
        operator_load_state="",
        operator_active_state="",
        operator_unit_file_state="",
        operator_state_change_monotonic="",
    )


# --------------------------------------------------------------------------- service-state adapter


@dataclass(frozen=True)
class LocalServiceStateAdapter:
    """One coherent, read-only observation of the operator systemd unit + the ordinary Docker
    container + the exact pinned ordinary health contract, returned as ONE HostObservationEvidence.

    Exposes no start/stop/restart/enable/disable/reload/mask verb; never touches the ordinary
    worker. ``ordinary_running`` means the container is present AND running AND its EXACT pinned
    health contract passes (running-state alone is never treated as application health)."""

    operator_service: str
    ordinary_container: str
    ordinary_health_command: tuple[str, ...]
    container_runtime: ExecutablePin
    service_inspector: ExecutablePin
    runner: CommandRunner
    timeout_seconds: int = _SERVICE_TIMEOUT_SECONDS
    window_seconds: int = _OBSERVATION_WINDOW_SECONDS

    def _operator_observation(self) -> _OperatorObservation:
        # ONE `systemctl show` for all five properties (not three independently timed calls), so
        # the generation markers and states are read as a single coherent snapshot.
        result = self.runner.run(
            self.service_inspector,
            ("show", "--property", ",".join(_OPERATOR_PROPERTIES), self.operator_service),
            timeout_seconds=self.timeout_seconds,
            max_output_bytes=_MAX_OUTPUT_BYTES,
        )
        if result.exit_code != 0:
            raise DeploymentPackageError("service_query_failed")
        fields = _parse_show(result.stdout)
        invocation = fields["InvocationID"]
        if invocation != "" and _INVOCATION_ID.fullmatch(invocation) is None:
            raise DeploymentPackageError("service_observation_malformed")
        if _MONOTONIC.fullmatch(fields["StateChangeTimestampMonotonic"]) is None:
            raise DeploymentPackageError("service_observation_malformed")
        return _OperatorObservation(
            load_state=fields["LoadState"],
            active_state=fields["ActiveState"],
            unit_file_state=fields["UnitFileState"],
            invocation_id=invocation,
            state_change_monotonic=fields["StateChangeTimestampMonotonic"],
        )

    def _container_observation(self) -> _ContainerObservation:
        result = self.runner.run(
            self.container_runtime,
            ("inspect", "--format", _CONTAINER_FORMAT, self.ordinary_container),
            timeout_seconds=self.timeout_seconds,
            max_output_bytes=_MAX_OUTPUT_BYTES,
        )
        if result.exit_code != 0:
            return _ContainerObservation(
                present=False,
                container_id="",
                running=False,
                restart_count="",
                started_at="",
                finished_at="",
                pid="",
            )
        raw = result.stdout
        if raw.endswith("\n"):
            raw = raw[:-1]
        if _DOCKER_INSPECT_LINE.fullmatch(raw) is None:
            raise DeploymentPackageError("container_runtime_output_malformed")
        cid, running, restart, started, finished, pid = raw.split(" ")
        return _ContainerObservation(
            present=True,
            container_id=cid,
            running=running == "true",
            restart_count=restart,
            started_at=started,
            finished_at=finished,
            pid=pid,
        )

    def _health(self) -> bool:
        # Run the EXACT pinned ordinary health contract INSIDE the container (read-only probe).
        # Exit 0 is healthy; anything else is unhealthy.
        result = self.runner.run(
            self.container_runtime,
            ("exec", self.ordinary_container, *self.ordinary_health_command),
            timeout_seconds=_HEALTH_TIMEOUT_SECONDS,
            max_output_bytes=_MAX_OUTPUT_BYTES,
        )
        return result.exit_code == 0

    def _coherent(self) -> WorkerGenerationObservation:
        start = time.monotonic()
        try:
            # --- primary observation (operator + container, each ONE bounded call) ---
            op_before = self._operator_observation()
            ct_before = self._container_observation()
            healthy = self._health() if (ct_before.present and ct_before.running) else False
            # --- revalidation (design B): the operator unit AND the container, INCLUDING their
            #     generation markers, must be byte-identical before/after. An ABA restart (same
            #     running state but changed RestartCount/StartedAt/Pid, or a new systemd
            #     InvocationID / StateChangeTimestampMonotonic) is NOT coherent. ---
            op_after = self._operator_observation()
            ct_after = self._container_observation()
        except DeploymentPackageError:
            return _unavailable_generation()

        if time.monotonic() - start > self.window_seconds:
            return _unavailable_generation()  # observation window exceeded → not coherent
        if op_before != op_after:
            return _unavailable_generation()  # operator unit/generation changed mid-collection
        if ct_before != ct_after:
            return _unavailable_generation()  # ordinary container (or its generation) changed → ABA

        operator_present = _classify_load(op_before.load_state)
        operator_running = _classify_active(op_before.active_state)
        operator_enabled = _classify_unit_file_state(op_before.unit_file_state)
        if None in (operator_present, operator_running, operator_enabled):
            return _unavailable_generation()

        # The health probe ran against ct_before's generation; because ct_before == ct_after, that
        # generation is unchanged, so the health result validly applies to the observed container.
        ordinary_running = ct_before.present and ct_before.running and healthy

        return WorkerGenerationObservation(
            inspected=True,
            coherent=True,
            operator_present=bool(operator_present),
            operator_enabled=bool(operator_enabled),
            operator_running=bool(operator_running),
            ordinary_running=bool(ordinary_running),
            ordinary_present=ct_before.present,
            ordinary_container_id=ct_before.container_id,
            ordinary_restart_count=ct_before.restart_count,
            ordinary_started_at=ct_before.started_at,
            ordinary_finished_at=ct_before.finished_at,
            ordinary_pid=ct_before.pid,
            ordinary_healthy=healthy,
            operator_invocation_id=op_before.invocation_id,
            operator_load_state=op_before.load_state,
            operator_active_state=op_before.active_state,
            operator_unit_file_state=op_before.unit_file_state,
            operator_state_change_monotonic=op_before.state_change_monotonic,
        )

    def observe(self) -> HostObservationEvidence:
        return self._coherent().evidence()

    def observe_generation(self) -> WorkerGenerationObservation:
        """ONE coherent observation exposing the internal generation projection (raw facts + the
        derived ``HostObservationEvidence`` booleans) for the management host observer — so it never
        runs a second Docker/systemd parser."""
        return self._coherent()

    def snapshot(self) -> ServiceStateSnapshot:
        # Derived 5-bool snapshot for the reused commissioning ``inspect_host`` seam.
        return self.observe().to_service_state_snapshot()


def _parse_show(raw: str) -> dict[str, str]:
    """Parse ``systemctl show`` ``Key=Value`` output into a strict closed dict: exactly the
    requested
    properties, each present exactly once, no unexpected key. Values may be empty (e.g.
    InvocationID of a never-started unit)."""
    lines = raw.split("\n")
    if lines and lines[-1] == "":
        lines = lines[:-1]
    fields: dict[str, str] = {}
    for line in lines:
        key, sep, value = line.partition("=")
        if sep != "=" or key in fields:
            raise DeploymentPackageError("service_observation_malformed")
        fields[key] = value
    if set(fields) != set(_OPERATOR_PROPERTIES):
        raise DeploymentPackageError("service_observation_malformed")
    return fields


def _classify_load(value: str) -> bool | None:
    if value == "loaded":
        return True
    if value in ("not-found", "masked", "bad-setting", "error"):
        return False
    return None


def _classify_active(value: str) -> bool | None:
    if value == "active":
        return True
    if value in ("inactive", "failed", "deactivating", "activating"):
        return False
    return None


def _classify_unit_file_state(value: str) -> bool | None:
    if value in ("enabled", "enabled-runtime", "alias", "static", "indirect"):
        return True
    if value in ("disabled", "masked", "not-found", "linked", "generated", "transient"):
        return False
    return None


# --------------------------------------------------------------------------- composition helpers


def _container_pin(profile: DeploymentProfile) -> ExecutablePin:
    return ExecutablePin(
        path=profile.container_runtime_executable,
        digest=profile.container_runtime_executable_digest,
    )


def _inspector_pin(profile: DeploymentProfile) -> ExecutablePin:
    return ExecutablePin(
        path=profile.service_inspector_executable,
        digest=profile.service_inspector_executable_digest,
    )


def build_real_host_adapters(
    profile: DeploymentProfile,
    expected: ExpectedDeploymentIdentities,
    *,
    command_runner: CommandRunner | None = None,
) -> tuple[LocalContainerRuntimeAdapter, LocalServiceStateAdapter]:
    """Construct the read-only container-runtime + service-state adapters from the trusted profile,
    which must already AGREE with the independent ``expected`` pins (executable path+digest
    included). Constructing them contacts nothing (no command runs until a method is called)."""
    from secp_operator_deployment.identities import require_profile_agreement

    require_profile_agreement(profile, expected)  # the profile is never the sole authority
    runner = command_runner if command_runner is not None else RealCommandRunner()
    container_pin = _container_pin(profile)
    container = LocalContainerRuntimeAdapter(container_runtime=container_pin, runner=runner)
    service = LocalServiceStateAdapter(
        operator_service=profile.operator_service_name,
        ordinary_container=profile.ordinary_container_name,
        ordinary_health_command=tuple(profile.ordinary_health_command),
        container_runtime=container_pin,
        service_inspector=_inspector_pin(profile),
        runner=runner,
    )
    return container, service


def real_host_facts(
    *,
    descriptor: object,
    locations: object,
    profile: DeploymentProfile,
    expected: ExpectedDeploymentIdentities,
    filesystem: object | None = None,
    command_runner: CommandRunner | None = None,
):  # noqa: ANN201
    """Compose the real read-only adapters into ``HostFacts`` by REUSING the existing
    ``secp_commissioning.inspect_host`` — no plan/install/status/evidence logic is duplicated, and
    every PR5C gate the plan engine applies to these facts is preserved unchanged."""
    from secp_commissioning.runtime import RealFilesystem
    from secp_commissioning.status import inspect_host

    fs = filesystem if filesystem is not None else RealFilesystem()
    container, service = build_real_host_adapters(profile, expected, command_runner=command_runner)
    return inspect_host(
        descriptor=descriptor,  # type: ignore[arg-type]
        locations=locations,  # type: ignore[arg-type]
        fs=fs,  # type: ignore[arg-type]
        container_runtime=container,
        service_state=service,
    )
