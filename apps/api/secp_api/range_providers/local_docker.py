"""The local Docker range provider — EPHEMERAL DEVELOPMENT/DEMO USE ONLY.

UNRESOLVED ARCHITECTURE EXCEPTION — READ FIRST
-----------------------------------------------
This module executes ``docker`` from inside the API process. That conflicts with Charter
Invariants 6/7 and ADR-005: ``secp_api`` must not perform privileged infrastructure execution, and
``tests/test_architecture_boundary.py`` fails on exactly this file (``subprocess`` is in
``HARD_FORBIDDEN_MODULES``) and on ``services/ranges.py`` calling ``provider.reset``/
``provider.destroy``. A Docker socket is root-equivalent on the host, so the invariant applies in
substance and not merely in letter.

That guard has deliberately NOT been relaxed. Adding a ``RESTRICTED_MODULES`` seam entry for this
file would be a charter-level exception, and that is an owner's decision rather than something to
grant while writing the feature. Two honest resolutions exist:

1. Dispatch range operations through the worker boundary like every other privileged action, and
   implement :class:`~secp_api.range_providers.base.RangeProvider` there. The provider protocol was
   built for this: it holds no database session and returns only observations, so the move is
   mechanical.
2. Record an explicit, reviewed charter exception for a development-only provider and add the seam
   entry with that justification alongside the existing ``httpx``/OIDC one.

Until one is chosen, the provider is SEALED BY DEFAULT (``SECP_RANGE_LOCAL_DOCKER``, refused in
production outright) so a deployment cannot acquire this capability by accident.

It creates a dedicated bridge network per range, launches the pinned intentionally-vulnerable
images onto it, publishes each component on a loopback-only ephemeral host port, and verifies
readiness by actually talking to the service. It records the container/network ids and the resolved
image digests that were really used, resets deterministically, and removes exactly what it created.

SAFETY PROPERTIES THIS MODULE IS RESPONSIBLE FOR
------------------------------------------------
1. **Only loopback.** Every published port binds ``127.0.0.1`` explicitly. Intentionally vulnerable
   software is never offered to the LAN.
2. **Only our own resources.** Every resource is stamped at creation with
   ``secp.range.owner=secp-range`` and ``secp.range.id=<range uuid>``. Removal is by recorded
   external id, and only after re-reading that id's labels and confirming BOTH match this range.
   There is no name-glob removal, no ``prune``, and no removal path that takes a filter instead of
   a specific id. A resource this control plane did not create cannot be selected.
3. **No invented success.** ``verified`` is set only when an HTTP response was actually received
   from the component. A container that started but never answered is not ready.
4. **No invented absence.** See :mod:`secp_api.range_providers.docker_cli`. When the daemon cannot
   be observed, teardown reports ``unproven``, never ``removed``.
"""

from __future__ import annotations

import logging
import time
import urllib.error
import urllib.request
from dataclasses import replace

from secp_api.range_enums import RangeResourceKind, RangeStepStatus
from secp_api.range_providers.base import (
    DeployResult,
    OperationContext,
    ProviderHealth,
    RangeSpec,
    RecordedStep,
    ResourceObservation,
    TeardownObservation,
    TeardownResourceOutcome,
    TeardownResult,
)
from secp_api.range_providers.docker_cli import (
    PULL_TIMEOUT_SECONDS,
    DockerCommandError,
    DockerUnavailableError,
    daemon_health,
    image_digest,
    inspect_json,
    object_exists,
    run,
)

logger = logging.getLogger("secp.api.range.docker")

#: Stamped on every resource. The teardown selector requires it.
OWNER_LABEL_KEY = "secp.range.owner"
OWNER_LABEL_VALUE = "secp-range"
RANGE_ID_LABEL_KEY = "secp.range.id"

#: Vulnerable software is bound to loopback only — never 0.0.0.0.
BIND_HOST = "127.0.0.1"

#: Bounded resources per range container so a runaway demo cannot exhaust the host.
CONTAINER_MEMORY = "1g"
CONTAINER_PIDS_LIMIT = "512"

_READINESS_POLL_SECONDS = 3.0


def _network_name(prefix: str) -> str:
    return f"secp-range-{prefix}"


def _container_name(prefix: str, component_key: str) -> str:
    return f"secp-range-{prefix}-{component_key}"


def _owner_label(range_id: str) -> str:
    return f"{OWNER_LABEL_KEY}={OWNER_LABEL_VALUE},{RANGE_ID_LABEL_KEY}={range_id}"


def _probe_http(url: str, timeout: float = 5.0) -> tuple[bool, str]:
    """Did the service answer? Any HTTP status counts — a 401/302/500 is still the app talking.

    A connection error is a genuine "not up yet"; an HTTP error response is not.
    """
    request = urllib.request.Request(url, method="GET")  # noqa: S310 - fixed loopback scheme
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
            return True, f"HTTP {response.status}"
    except urllib.error.HTTPError as exc:
        return True, f"HTTP {exc.code}"
    except (urllib.error.URLError, TimeoutError, ConnectionError, OSError) as exc:
        return False, str(exc)


class LocalDockerProvider:
    """Provider name ``local_docker``. See the module docstring for its safety obligations."""

    name = "local_docker"

    # --- health -------------------------------------------------------------

    def health(self) -> ProviderHealth:
        state = daemon_health()
        return ProviderHealth(
            reachable=state.reachable,
            endpoint_id=state.daemon_id,
            version=state.version,
            detail=state.detail,
        )

    # --- step planning ------------------------------------------------------

    def plan_steps(self, spec: RangeSpec, kind: str) -> list[RecordedStep]:
        if kind == "destroy":
            steps = [
                RecordedStep(key="preflight", label="Check the Docker daemon is reachable"),
            ]
            steps += [
                RecordedStep(key=f"remove:{component.key}", label=f"Remove {component.name}")
                for component in spec.components
            ]
            steps.append(RecordedStep(key="remove:network", label="Remove the isolated network"))
            steps.append(
                RecordedStep(key="verify:residue", label="Verify every owned resource is gone")
            )
            return steps

        steps = [RecordedStep(key="preflight", label="Check the Docker daemon is reachable")]
        if kind == "reset":
            steps += [
                RecordedStep(key=f"remove:{component.key}", label=f"Remove {component.name}")
                for component in spec.components
            ]
        else:
            steps.append(RecordedStep(key="network", label="Create the isolated network"))
        for component in spec.components:
            steps.append(RecordedStep(key=f"pull:{component.key}", label=f"Pull {component.name}"))
        for component in spec.components:
            steps.append(
                RecordedStep(key=f"start:{component.key}", label=f"Start {component.name}")
            )
        for component in spec.components:
            steps.append(
                RecordedStep(
                    key=f"verify:{component.key}", label=f"Verify {component.name} responds"
                )
            )
        return steps

    # --- deploy -------------------------------------------------------------

    def deploy(self, spec: RangeSpec, ctx: OperationContext) -> DeployResult:
        return self._bring_up(spec, ctx, create_network=True)

    def reset(
        self,
        spec: RangeSpec,
        existing: tuple[ResourceObservation, ...],
        ctx: OperationContext,
    ) -> DeployResult:
        """Deterministic reset: destroy and recreate the containers on the SAME network.

        Recreating from the same pinned images rather than restarting means the range returns to
        its initial state, not to whatever state the previous run left on the container filesystem.
        """
        ctx.begin("preflight", phase="preflight")
        health = self.health()
        if not health.reachable:
            ctx.finish("preflight", RangeStepStatus.failed, detail=health.detail)
            return DeployResult(
                ok=False,
                failure_code="provider_unavailable",
                failure_message="the Docker daemon is not reachable",
            )
        ctx.finish("preflight", RangeStepStatus.succeeded, detail=f"docker {health.version}")

        network = next((r for r in existing if r.kind is RangeResourceKind.network), None)
        for component in spec.components:
            key = f"remove:{component.key}"
            ctx.begin(key, phase="reset")
            resource = next(
                (
                    r
                    for r in existing
                    if r.kind is RangeResourceKind.container and r.component_key == component.key
                ),
                None,
            )
            if resource is None:
                ctx.finish(key, RangeStepStatus.succeeded, detail="nothing recorded to remove")
                continue
            outcome = self._remove_one(spec, resource, RangeResourceKind.container)
            if outcome.outcome is not TeardownResourceOutcome.removed:
                # STOP. Recreating a component whose predecessor is still there (or whose fate is
                # unknown) means starting a container over the top of one we could not remove: the
                # run fails on a name conflict and leaves the old container alive while the
                # operation reports on the new one. Fail the reset here, cleanly and loudly,
                # instead of half-applying it.
                ctx.finish(key, RangeStepStatus.unproven, detail=outcome.detail)
                return DeployResult(
                    ok=False,
                    failure_code="reset_predecessor_not_removed",
                    failure_message=(
                        f"{component.name}: the existing container could not be confirmed removed "
                        f"({outcome.detail}); the reset was stopped rather than recreating over it"
                    ),
                )
            ctx.finish(key, RangeStepStatus.succeeded, detail=outcome.detail)

        kept = (network,) if network is not None else ()
        result = self._bring_up(spec, ctx, create_network=network is None, existing_network=network)
        if result.ok:
            return DeployResult(ok=True, resources=(*kept, *result.resources))
        return result

    def _bring_up(
        self,
        spec: RangeSpec,
        ctx: OperationContext,
        *,
        create_network: bool,
        existing_network: ResourceObservation | None = None,
    ) -> DeployResult:
        observations: list[ResourceObservation] = []

        if create_network:
            ctx.begin("preflight", phase="preflight")
            health = self.health()
            if not health.reachable:
                ctx.finish("preflight", RangeStepStatus.failed, detail=health.detail)
                return DeployResult(
                    ok=False,
                    failure_code="provider_unavailable",
                    failure_message="the Docker daemon is not reachable",
                )
            ctx.finish("preflight", RangeStepStatus.succeeded, detail=f"docker {health.version}")

            ctx.begin("network", phase="network")
            net_name = _network_name(spec.resource_prefix)
            try:
                created = run(
                    [
                        "network",
                        "create",
                        "--driver",
                        "bridge",
                        "--label",
                        f"{OWNER_LABEL_KEY}={OWNER_LABEL_VALUE}",
                        "--label",
                        f"{RANGE_ID_LABEL_KEY}={spec.range_id}",
                        net_name,
                    ]
                )
            except (DockerUnavailableError, DockerCommandError) as exc:
                ctx.finish("network", RangeStepStatus.failed, detail=str(exc))
                return DeployResult(
                    ok=False,
                    failure_code="network_create_failed",
                    failure_message=str(exc),
                )
            network_obs = ResourceObservation(
                kind=RangeResourceKind.network,
                name=net_name,
                external_id=created.stdout or None,
                owner_label=_owner_label(spec.range_id),
                verified=True,
                detail={"driver": "bridge"},
            )
            observations.append(network_obs)
            ctx.finish("network", RangeStepStatus.succeeded, detail=net_name)
            ctx.event(
                "network_created",
                f"Created the isolated network {net_name}",
                data={"network": net_name, "external_id": created.stdout},
            )
        else:
            net_name = (
                existing_network.name
                if existing_network is not None
                else _network_name(spec.resource_prefix)
            )

        for component in spec.components:
            key = f"pull:{component.key}"
            ctx.begin(key, phase="pull")
            try:
                run(["pull", component.image], timeout=PULL_TIMEOUT_SECONDS)
            except (DockerUnavailableError, DockerCommandError) as exc:
                ctx.finish(key, RangeStepStatus.failed, detail=str(exc))
                return DeployResult(
                    ok=False,
                    resources=tuple(observations),
                    failure_code="image_pull_failed",
                    failure_message=f"{component.image}: {exc}",
                )
            digest = image_digest(component.image)
            ctx.finish(key, RangeStepStatus.succeeded, detail=digest or component.image)

        started: list[ResourceObservation] = []
        for component in spec.components:
            key = f"start:{component.key}"
            ctx.begin(key, phase="start")
            name = _container_name(spec.resource_prefix, component.key)
            args = [
                "run",
                "--detach",
                "--name",
                name,
                "--network",
                net_name,
                "--label",
                f"{OWNER_LABEL_KEY}={OWNER_LABEL_VALUE}",
                "--label",
                f"{RANGE_ID_LABEL_KEY}={spec.range_id}",
                "--restart",
                "no",
                "--memory",
                CONTAINER_MEMORY,
                "--pids-limit",
                CONTAINER_PIDS_LIMIT,
            ]
            for env_key, env_value in component.env.items():
                args += ["--env", f"{env_key}={env_value}"]
            if component.container_port is not None:
                # Loopback-only, ephemeral host port. Never 0.0.0.0.
                args += ["--publish", f"{BIND_HOST}::{component.container_port}"]
            args.append(component.image)

            try:
                created = run(args, timeout=120)
            except (DockerUnavailableError, DockerCommandError) as exc:
                ctx.finish(key, RangeStepStatus.failed, detail=str(exc))
                return DeployResult(
                    ok=False,
                    resources=tuple(observations + started),
                    failure_code="container_start_failed",
                    failure_message=f"{component.name}: {exc}",
                )

            container_id = created.stdout or None
            host_port = self._published_port(name, component.container_port)
            observation = ResourceObservation(
                kind=RangeResourceKind.container,
                name=name,
                component_key=component.key,
                external_id=container_id,
                image=component.image,
                image_digest=image_digest(component.image),
                owner_label=_owner_label(spec.range_id),
                host_port=host_port,
                verified=False,
                detail={"network": net_name, "bind_host": BIND_HOST},
            )
            started.append(observation)
            short_id = container_id[:12] if container_id else "?"
            ctx.finish(key, RangeStepStatus.succeeded, detail=f"{name} ({short_id})")
            ctx.event(
                "container_started",
                f"Started {component.name} as {name}",
                data={"component_key": component.key, "host_port": host_port},
            )

        verified: list[ResourceObservation] = []
        for component in spec.components:
            key = f"verify:{component.key}"
            ctx.begin(key, phase="verify")
            observation = next(o for o in started if o.component_key == component.key)
            ok, detail = self._verify_component(component, observation)
            if not ok:
                ctx.finish(key, RangeStepStatus.failed, detail=detail)
                verified.append(observation)
                return DeployResult(
                    ok=False,
                    resources=tuple(observations + verified + started[len(verified) :]),
                    failure_code="readiness_not_observed",
                    failure_message=f"{component.name} never responded: {detail}",
                )
            verified.append(replace(observation, verified=True))
            ctx.finish(key, RangeStepStatus.succeeded, detail=detail)
            ctx.event(
                "resource_verified",
                f"{component.name} responded on {BIND_HOST}:{observation.host_port} ({detail})",
                data={"component_key": component.key},
            )

        return DeployResult(ok=True, resources=tuple(observations + verified))

    def _published_port(self, container_name: str, container_port: int | None) -> int | None:
        if container_port is None:
            return None
        try:
            result = run(["port", container_name, f"{container_port}/tcp"], check=False)
        except DockerUnavailableError:
            return None
        if not result.ok or not result.stdout:
            return None
        # e.g. "127.0.0.1:34011"
        first = result.stdout.splitlines()[0].strip()
        _, _, port = first.rpartition(":")
        try:
            return int(port)
        except ValueError:
            return None

    def _verify_component(self, component, observation: ResourceObservation) -> tuple[bool, str]:
        """Readiness BY OBSERVATION.

        For a component with an HTTP surface this is an actual request/response. For one without,
        it is the container being observed in the ``running`` state at the end of the window — not
        merely at the instant after ``docker run`` returned, which proves nothing about a process
        that exits a second later.
        """
        deadline = time.monotonic() + component.readiness_timeout_seconds
        last_detail = "not observed"
        url = (
            f"{component.protocol}://{BIND_HOST}:{observation.host_port}{component.path}"
            if observation.host_port is not None
            else None
        )
        while time.monotonic() < deadline:
            payload = inspect_json("container", observation.name)
            state = ((payload or {}).get("State") or {}) if payload else {}
            status = str(state.get("Status") or "unknown")
            if status in {"exited", "dead"}:
                exit_code = state.get("ExitCode")
                return False, f"container {status} (exit {exit_code})"
            if url is None:
                if status == "running":
                    # Require the running state to PERSIST, so a container that dies immediately
                    # after start is not mistaken for a healthy one.
                    time.sleep(_READINESS_POLL_SECONDS)
                    payload = inspect_json("container", observation.name)
                    again = str((((payload or {}).get("State")) or {}).get("Status") or "unknown")
                    if again == "running":
                        return True, "running"
                last_detail = f"container {status}"
            else:
                ok, detail = _probe_http(url)
                if ok:
                    return True, detail
                last_detail = detail
            time.sleep(_READINESS_POLL_SECONDS)
        return False, last_detail

    # --- destroy ------------------------------------------------------------

    def destroy(
        self,
        spec: RangeSpec,
        existing: tuple[ResourceObservation, ...],
        ctx: OperationContext,
    ) -> TeardownResult:
        """Remove every recorded resource, then PROVE the outcome with a probe whose own health is
        established after the removals, not before them."""
        ctx.begin("preflight", phase="preflight")
        health = self.health()
        if not health.reachable:
            # The daemon is down. We cannot remove anything, and — this is the whole point — we
            # equally cannot check whether anything is there. Reporting "clean" here would be the
            # classic false negative: the check fails for the same reason the removal did.
            ctx.finish("preflight", RangeStepStatus.unproven, detail=health.detail)
            observations = tuple(
                TeardownObservation(
                    kind=resource.kind,
                    name=resource.name,
                    external_id=resource.external_id,
                    outcome=TeardownResourceOutcome.unproven,
                    detail="the Docker daemon was unreachable, so absence was not observed",
                )
                for resource in existing
            )
            for component in spec.components:
                ctx.finish(f"remove:{component.key}", RangeStepStatus.unproven)
            ctx.finish("remove:network", RangeStepStatus.unproven)
            ctx.finish("verify:residue", RangeStepStatus.unproven)
            ctx.event(
                "teardown_unproven",
                "The Docker daemon was unreachable during teardown. Removal was not performed and "
                "absence was NOT proved — the existence check shares a failure mode with the "
                "removal, so its silence is not evidence. Resources may still exist.",
                level="warning",
            )
            return TeardownResult(
                probe_reachable=False,
                observations=observations,
                reason=(
                    "the Docker daemon was unreachable; the removal and the existence check share "
                    "that failure mode, so absence was not proved"
                ),
            )
        ctx.finish("preflight", RangeStepStatus.succeeded, detail=f"docker {health.version}")

        containers = [r for r in existing if r.kind is RangeResourceKind.container]
        networks = [r for r in existing if r.kind is RangeResourceKind.network]

        # A component with NO recorded resource contributes no observation at all. It must not
        # contribute a synthetic "removed" one either: counting "we never created it" as "we
        # confirmed it is gone" inflates the evidence with a resource that was never at risk, and
        # makes a teardown look better-attested than it is.
        outcomes: list[TeardownObservation] = []
        for component in spec.components:
            key = f"remove:{component.key}"
            ctx.begin(key, phase="remove")
            resource = next((r for r in containers if r.component_key == component.key), None)
            if resource is None:
                ctx.finish(key, RangeStepStatus.succeeded, detail="nothing recorded to remove")
                continue
            outcome = self._remove_one(spec, resource, RangeResourceKind.container)
            outcomes.append(outcome)
            ctx.finish(key, _step_status_for(outcome.outcome), detail=outcome.detail)

        # Containers that no longer map to a component of the current spec still belong to us.
        for resource in containers:
            if any(o.name == resource.name for o in outcomes):
                continue
            outcomes.append(self._remove_one(spec, resource, RangeResourceKind.container))

        ctx.begin("remove:network", phase="remove")
        network_outcomes = [
            self._remove_one(spec, network, RangeResourceKind.network) for network in networks
        ]
        outcomes.extend(network_outcomes)
        if network_outcomes:
            worst = min(network_outcomes, key=lambda o: _OUTCOME_SEVERITY[o.outcome])
            ctx.finish("remove:network", _step_status_for(worst.outcome), detail=worst.detail)
        else:
            ctx.finish("remove:network", RangeStepStatus.succeeded, detail="no network recorded")

        # THE PROBE'S OWN HEALTH, MEASURED AFTER THE REMOVALS. If the daemon went away in between,
        # every "gone" we just recorded becomes unproven — we no longer have a working observer.
        ctx.begin("verify:residue", phase="verify")
        post_health = daemon_health()
        if not post_health.reachable:
            ctx.finish("verify:residue", RangeStepStatus.unproven, detail=post_health.detail)
            return TeardownResult(
                probe_reachable=False,
                observations=tuple(
                    TeardownObservation(
                        kind=o.kind,
                        name=o.name,
                        external_id=o.external_id,
                        outcome=TeardownResourceOutcome.unproven,
                        detail="the daemon stopped answering before absence could be confirmed",
                    )
                    for o in outcomes
                ),
                reason=(
                    "the Docker daemon stopped answering during teardown, so the existence check "
                    "could not run and absence was not proved"
                ),
            )
        if (
            health.endpoint_id is not None
            and post_health.daemon_id is not None
            and health.endpoint_id != post_health.daemon_id
        ):
            # A different daemon would answer "no such object" for everything we own. That answer
            # is about ITS world, not ours, so it proves nothing about our resources.
            ctx.finish(
                "verify:residue",
                RangeStepStatus.unproven,
                detail="the Docker endpoint changed identity mid-teardown",
            )
            return TeardownResult(
                probe_reachable=False,
                observations=tuple(
                    TeardownObservation(
                        kind=o.kind,
                        name=o.name,
                        external_id=o.external_id,
                        outcome=TeardownResourceOutcome.unproven,
                        detail="a different Docker endpoint answered the existence check",
                    )
                    for o in outcomes
                ),
                reason=(
                    "the Docker endpoint changed identity between removal and verification, so its "
                    "'not found' answers describe a different daemon and prove nothing here"
                ),
            )

        final = tuple(self._confirm_absent(o) for o in outcomes)
        unproven = sum(1 for o in final if o.outcome is TeardownResourceOutcome.unproven)
        present = sum(1 for o in final if o.outcome is TeardownResourceOutcome.present)
        if unproven:
            status = RangeStepStatus.unproven
        elif present:
            status = RangeStepStatus.failed
        else:
            status = RangeStepStatus.succeeded
        ctx.finish(
            "verify:residue",
            status,
            detail=f"{len(final) - present - unproven}/{len(final)} confirmed removed",
        )
        return TeardownResult(probe_reachable=True, observations=final)

    def _remove_one(
        self,
        spec: RangeSpec,
        resource: ResourceObservation,
        kind: RangeResourceKind,
    ) -> TeardownObservation:
        """Remove ONE recorded resource, after confirming we own it.

        The ownership re-check is the safety property: the id came from our own records, but we
        still read the live object's labels and refuse to remove anything that is not stamped with
        this range's id. A recycled or mistyped id therefore cannot take an unrelated container
        with it.
        """
        reference = resource.external_id or resource.name
        noun = "container" if kind is RangeResourceKind.container else "network"

        exists = object_exists(noun, reference)
        if exists is None:
            return TeardownObservation(
                kind=kind,
                name=resource.name,
                external_id=resource.external_id,
                outcome=TeardownResourceOutcome.unproven,
                detail="could not observe whether this resource exists",
            )
        if exists is False:
            return TeardownObservation(
                kind=kind,
                name=resource.name,
                external_id=resource.external_id,
                outcome=TeardownResourceOutcome.removed,
                detail="already absent",
            )

        payload = inspect_json(noun, reference) or {}
        labels = _labels_of(payload, kind)
        if (
            labels.get(OWNER_LABEL_KEY) != OWNER_LABEL_VALUE
            or labels.get(RANGE_ID_LABEL_KEY) != spec.range_id
        ):
            # REFUSE. This id exists but is not ours. Never remove it.
            logger.warning(
                "refusing to remove %s %s: ownership labels do not match range %s",
                noun,
                reference,
                spec.range_id,
            )
            return TeardownObservation(
                kind=kind,
                name=resource.name,
                external_id=resource.external_id,
                outcome=TeardownResourceOutcome.present,
                detail=("refused to remove: this resource is not labelled as owned by this range"),
            )

        try:
            if kind is RangeResourceKind.container:
                run(["rm", "--force", "--volumes", reference], timeout=120, check=False)
            else:
                run(["network", "rm", reference], timeout=60, check=False)
        except DockerUnavailableError as exc:
            return TeardownObservation(
                kind=kind,
                name=resource.name,
                external_id=resource.external_id,
                outcome=TeardownResourceOutcome.unproven,
                detail=f"removal could not be performed: {exc}",
            )
        return TeardownObservation(
            kind=kind,
            name=resource.name,
            external_id=resource.external_id,
            outcome=TeardownResourceOutcome.removed,
            detail="removal requested",
        )

    def _confirm_absent(self, observation: TeardownObservation) -> TeardownObservation:
        """Re-observe one resource. Never upgrades an answer we could not make."""
        if observation.outcome is TeardownResourceOutcome.present:
            return observation
        noun = "container" if observation.kind is RangeResourceKind.container else "network"
        reference = observation.external_id or observation.name
        exists = object_exists(noun, reference)
        if exists is None:
            return TeardownObservation(
                kind=observation.kind,
                name=observation.name,
                external_id=observation.external_id,
                outcome=TeardownResourceOutcome.unproven,
                detail="the existence check could not be trusted, so absence was not proved",
            )
        if exists:
            return TeardownObservation(
                kind=observation.kind,
                name=observation.name,
                external_id=observation.external_id,
                outcome=TeardownResourceOutcome.present,
                detail="still present after removal",
            )
        return TeardownObservation(
            kind=observation.kind,
            name=observation.name,
            external_id=observation.external_id,
            outcome=TeardownResourceOutcome.removed,
            detail="confirmed absent",
        )


def _labels_of(payload: dict, kind: RangeResourceKind) -> dict:
    if kind is RangeResourceKind.container:
        config = payload.get("Config")
        labels = (config or {}).get("Labels") if isinstance(config, dict) else None
    else:
        labels = payload.get("Labels")
    return labels if isinstance(labels, dict) else {}


#: Lower is worse. Used to report the WORST outcome across a set rather than the first one, so a
#: single unproven or still-present resource is never hidden behind a sibling that went cleanly.
_OUTCOME_SEVERITY: dict[TeardownResourceOutcome, int] = {
    TeardownResourceOutcome.present: 0,
    TeardownResourceOutcome.unproven: 1,
    TeardownResourceOutcome.removed: 2,
}


def _step_status_for(outcome: TeardownResourceOutcome) -> RangeStepStatus:
    if outcome is TeardownResourceOutcome.removed:
        return RangeStepStatus.succeeded
    if outcome is TeardownResourceOutcome.present:
        return RangeStepStatus.failed
    return RangeStepStatus.unproven
