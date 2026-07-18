"""Read-only observed host facts + the injectable host-probe seam (SECP-PR5E).

A :class:`HostView` is a NONSECRET snapshot of locally observed facts (OS/arch/root, Docker/Compose
presence, the ordinary container's generation-checked identity, the operator service state, health,
and which managed objects already exist). It carries NO secret, NO host address, and NO raw
env/inspect
content. The production probe reads only LOCAL facts (never contacting infrastructure); tests
inject a
:class:`StaticHostProbe` with a deterministic view. The engine plans/verifies against the VIEW, so
the security logic is fully testable without root, Docker, or a network.
"""

from __future__ import annotations

import os
import platform
from dataclasses import dataclass, field
from typing import Protocol


@dataclass(frozen=True)
class ContainerObservation:
    """One generation-checked ordinary-container observation (ABA-safe: identity + generation)."""

    present: bool
    container_id: str  # full 64-hex id, or "" when absent
    running: bool
    image_digest: str  # "sha256:..." of the running image, or ""
    restart_count: str
    started_at: str
    pid: str
    healthy: bool


@dataclass(frozen=True)
class ServiceObservation:
    """One operator systemd unit observation."""

    present: bool
    enabled: bool
    running: bool
    invocation_id: str


@dataclass(frozen=True)
class HostView:
    """A nonsecret snapshot of observed host facts used for planning + verification."""

    os_name: str
    arch: str
    is_root: bool
    docker_present: bool
    compose_present: bool
    # True only when the underlying observation was generation-coherent (no ABA restart, no PID
    # change mid-collection). A False value fails closed like the PR5D adapter's incoherent
    # snapshot.
    coherent: bool = True
    # worker-role observations (empty/absent for controller-only planning)
    ordinary: ContainerObservation | None = None
    operator: ServiceObservation | None = None
    operator_package_trusted: bool = False
    # controller-role observations: component -> running image content digest
    controller_containers: dict[str, str] = field(default_factory=dict)
    controller_privileged: tuple[str, ...] = ()  # unknown/foreign privileged services
    migration_identity: str = ""
    # which managed evidence/identity already exists on disk (path binding -> exists)
    existing_bindings: tuple[str, ...] = ()


class HostProbe(Protocol):
    def observe(self) -> HostView: ...


@dataclass(frozen=True)
class StaticHostProbe:
    """A test/DI probe that returns a fixed :class:`HostView`."""

    view: HostView

    def observe(self) -> HostView:
        return self.view


def _arch() -> str:
    machine = platform.machine().lower()
    if machine in ("x86_64", "amd64"):
        return "x86_64"
    if machine in ("aarch64", "arm64"):
        return "arm64"
    return machine or "unknown"


class LocalHostProbe:
    """Production probe: reads ONLY local platform facts. It does NOT inspect Docker/systemd or
    contact
    anything (that observation is wired from the reviewed PR5C/PR5D read-only adapters on a real
    host
    and is out of scope for this local-facts probe). Off a supported host it reports an unprepared
    view so planning fails closed."""

    def observe(self) -> HostView:
        try:
            is_root = hasattr(os, "geteuid") and os.geteuid() == 0  # type: ignore[attr-defined]
        except Exception:
            is_root = False
        return HostView(
            os_name=platform.system().lower(),
            arch=_arch(),
            is_root=bool(is_root),
            docker_present=False,
            compose_present=False,
        )
