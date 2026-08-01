"""The disposable two-host fleet: create it, prove it, destroy it.

A "host" here is a privileged container running systemd as PID 1 with its OWN Docker Engine inside.
That combination is what makes the acceptance real rather than simulated: the management adapters
call ``systemctl daemon-reload`` and get a real systemd answer, and they call ``docker load`` /
``docker compose up`` / ``docker inspect`` against a daemon that belongs to that host alone. Two
hosts therefore have genuinely separate container namespaces, image stores and unit trees — which
is the whole point of a TWO-host acceptance.

Everything the fleet touches is named under a single run-scoped prefix and is removed by
:meth:`HostFleet.destroy`, including on the failure paths. ``destroy`` is idempotent and reports
what it could not remove rather than pretending it succeeded, because a leaked privileged container
with a nested Docker daemon is the most expensive thing this harness could leave behind.

The nested daemon needs volume-backed ``/var/lib/docker`` and ``/var/lib/containerd``: the outer
daemon's overlayfs cannot host the inner daemon's overlayfs, and the failure mode without the
volumes is an obscure ``invalid argument`` on the first inner ``docker run``.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from secp_acceptance import AcceptanceError
from secp_acceptance.evidence import FleetRecord, observation_digest
from secp_acceptance.shell import Result, docker, run

#: Roles are fixed. There is no "add a third host" verb: the acceptance is defined over exactly one
#: controller and one worker, and a variable fleet would make the evidence document's fleet identity
#: meaningless.
ROLE_CONTROLLER = "controller"
ROLE_WORKER = "worker"
ROLES: tuple[str, ...] = (ROLE_CONTROLLER, ROLE_WORKER)

#: In-fleet DNS names. ``.test`` is the RFC 6761 reserved suffix; the repo's endpoint guard allows
#: it precisely so fixtures cannot accidentally name a resolvable host.
HOST_DNS = {ROLE_CONTROLLER: "controller.secp.test", ROLE_WORKER: "worker.secp.test"}

_SYSTEMD_READY_STATES = ("running", "degraded")
_READY_TIMEOUT_SECONDS = 180
_POLL_SECONDS = 2.0


@dataclass(frozen=True)
class Host:
    """One disposable host. Holds its container NAME, never its container id.

    The distinction matters for the evidence: a container id is a per-run value that says nothing to
    a later reader, while the name is derived from the run prefix and the role, so it is stable and
    safe to hash into the fleet identity.
    """

    role: str
    container: str
    dns_name: str

    def exec(
        self, argv: tuple[str, ...] | list[str], *, timeout: int = 600, check: bool = False
    ) -> Result:
        """Run one command INSIDE this host."""
        return docker("exec", self.container, *argv, timeout=timeout, check=check)

    def exec_as_script(self, script: str, *, timeout: int = 900, check: bool = False) -> Result:
        """Run a multi-line POSIX shell script inside this host.

        The script is a HARNESS-authored constant delivered on stdin to ``sh -s``; it never
        interpolates an argument the harness received from a host, a container, or a report. That
        keeps the "no shell string built from untrusted input" property of
        :mod:`secp_acceptance.shell` intact while still allowing the multi-step provisioning a real
        host installation needs.
        """
        return run(
            ("docker", "exec", "-i", self.container, "sh", "-euo", "pipefail", "-s"),
            timeout=timeout,
            check=check,
            stdin_bytes=script.encode("utf-8"),
        )

    def write_file(self, path: str, content: bytes, *, mode: str = "0644") -> None:
        """Install a file inside the host from harness-held bytes, without a shell heredoc."""
        result = run(
            ("docker", "exec", "-i", self.container, "sh", "-c", 'cat > "$0"', path),
            timeout=120,
            stdin_bytes=content,
        )
        if not result.ok:
            raise AcceptanceError("acceptance_host_command_failed")
        self.exec(("chmod", mode, path), check=True)
        self.exec(("chown", "root:root", path), check=True)

    def read_file(self, path: str, *, timeout: int = 120) -> bytes:
        result = self.exec(("cat", path), timeout=timeout)
        if not result.ok:
            raise AcceptanceError("acceptance_observation_unavailable")
        return result.stdout.encode("utf-8")


@dataclass
class HostFleet:
    """The run-scoped fleet. Construct, :meth:`create`, use, then always :meth:`destroy`."""

    prefix: str
    image: str = "secp-acceptance-host:local"
    hosts: dict[str, Host] = field(default_factory=dict)
    created: int = 0
    destroyed: int = 0
    image_identity: str = ""

    # --- naming -------------------------------------------------------------------------

    @property
    def network(self) -> str:
        return f"{self.prefix}-net"

    def container_name(self, role: str) -> str:
        return f"{self.prefix}-{role}"

    def _volumes(self, role: str) -> tuple[str, str]:
        return f"{self.prefix}-{role}-docker", f"{self.prefix}-{role}-containerd"

    # --- lifecycle ----------------------------------------------------------------------

    def build_image(self, *, context: str, dockerfile: str) -> None:
        """Build the disposable host image.

        The build CONTEXT is deliberately the small ``infra/acceptance`` directory, not the repo
        root: the host image copies no product source (the repo is delivered to a running host
        afterwards, so a source edit does not invalidate a multi-minute image layer), and uploading
        the whole repo as context on every run would cost more than the build itself.
        """
        result = docker("build", "-t", self.image, "-f", dockerfile, context, timeout=1800)
        if not result.ok:
            raise AcceptanceError("acceptance_host_image_build_failed")
        inspected = docker("image", "inspect", "--format", "{{.Id}}", self.image, timeout=60)
        if not inspected.ok:
            raise AcceptanceError("acceptance_host_image_build_failed")
        self.image_identity = observation_digest({"host_image": inspected.stdout.strip()})

    def create(self) -> None:
        """Create the network and both hosts, and wait until each is genuinely usable.

        "Usable" means systemd reached a terminal boot state AND the inner Docker daemon answers.
        Waiting on the container merely existing would let every later stage fail with a confusing
        error that has nothing to do with the thing being tested.
        """
        if not docker("network", "create", self.network, timeout=60).ok:
            raise AcceptanceError("acceptance_host_create_failed")
        for role in ROLES:
            self._create_host(role)
        for role in ROLES:
            self._await_ready(self.hosts[role])

    def _create_host(self, role: str) -> None:
        name = self.container_name(role)
        docker_vol, containerd_vol = self._volumes(role)
        for volume in (docker_vol, containerd_vol):
            if not docker("volume", "create", volume, timeout=60).ok:
                raise AcceptanceError("acceptance_host_create_failed")
        result = docker(
            "run",
            "--detach",
            "--name",
            name,
            "--hostname",
            HOST_DNS[role],
            "--network",
            self.network,
            "--network-alias",
            HOST_DNS[role],
            # systemd needs a writable cgroup hierarchy and its own /run; the nested daemon needs
            # the privileges to create network namespaces and mount overlays.
            "--privileged",
            "--cgroupns=host",
            "--tmpfs",
            "/run",
            "--tmpfs",
            "/run/lock",
            "--volume",
            "/sys/fs/cgroup:/sys/fs/cgroup:rw",
            "--volume",
            f"{docker_vol}:/var/lib/docker",
            "--volume",
            f"{containerd_vol}:/var/lib/containerd",
            self.image,
            timeout=300,
        )
        if not result.ok:
            raise AcceptanceError("acceptance_host_create_failed")
        self.created += 1
        self.hosts[role] = Host(role=role, container=name, dns_name=HOST_DNS[role])

    def _await_ready(self, host: Host) -> None:
        deadline = time.monotonic() + _READY_TIMEOUT_SECONDS
        systemd_state = ""
        while time.monotonic() < deadline:
            probe = host.exec(("systemctl", "is-system-running"), timeout=30)
            systemd_state = probe.stdout.strip()
            if systemd_state in _SYSTEMD_READY_STATES:
                break
            time.sleep(_POLL_SECONDS)
        if systemd_state not in _SYSTEMD_READY_STATES:
            raise AcceptanceError("acceptance_host_systemd_not_running")
        while time.monotonic() < deadline:
            if host.exec(("docker", "info", "--format", "{{.ID}}"), timeout=60).ok:
                return
            time.sleep(_POLL_SECONDS)
        raise AcceptanceError("acceptance_host_dockerd_not_active")

    def observe_readiness(self, host: Host) -> dict[str, object]:
        """The bounded readiness projection a fleet check records.

        Deliberately narrow: boot state, whether the inner daemon answers, whether it is a DIFFERENT
        daemon from the other host's, and the service-manager version. No container id, no address,
        no inner image list.
        """
        systemd = host.exec(("systemctl", "is-system-running"), timeout=30)
        daemon = host.exec(("docker", "info", "--format", "{{.ID}}"), timeout=60)
        version = host.exec(("systemctl", "--version"), timeout=30)
        return {
            "role": host.role,
            "systemd_state": systemd.stdout.strip(),
            "dockerd_answers": daemon.ok,
            "daemon_identity": observation_digest({"daemon": daemon.stdout.strip()}),
            "systemd_major": version.stdout.split("\n", 1)[0].strip()[:32],
        }

    def daemons_are_distinct(self) -> tuple[bool, dict[str, object]]:
        """Prove the two hosts do NOT share one container runtime.

        This is the premise every later isolation claim rests on. If both hosts spoke to the same
        daemon, "the worker host installed the worker" and "the controller host runs the API" would
        be statements about one machine wearing two names, and the operator-queue isolation proof
        would be measuring a single Docker world.
        """
        ids = {}
        for role in ROLES:
            probe = self.hosts[role].exec(("docker", "info", "--format", "{{.ID}}"), timeout=60)
            if not probe.ok or not probe.stdout.strip():
                raise AcceptanceError("acceptance_observation_unavailable")
            ids[role] = probe.stdout.strip()
        distinct = ids[ROLE_CONTROLLER] != ids[ROLE_WORKER]
        return distinct, {
            "distinct_daemons": distinct,
            "controller_daemon": observation_digest({"d": ids[ROLE_CONTROLLER]}),
            "worker_daemon": observation_digest({"d": ids[ROLE_WORKER]}),
        }

    def destroy(self) -> tuple[bool, dict[str, object]]:
        """Remove every object this fleet created. Idempotent; reports residual honestly."""
        residual: list[str] = []
        for role in ROLES:
            name = self.container_name(role)
            if docker("rm", "--force", "--volumes", name, timeout=300).ok:
                self.destroyed += 1
            elif self._exists("container", name):
                residual.append(f"container:{role}")
        for role in ROLES:
            for volume in self._volumes(role):
                docker("volume", "rm", "--force", volume, timeout=120)
                if self._exists("volume", volume):
                    residual.append(f"volume:{role}")
        docker("network", "rm", self.network, timeout=120)
        if self._exists("network", self.network):
            residual.append("network")
        return not residual, {"residual": sorted(set(residual)), "destroyed": self.destroyed}

    def _exists(self, kind: str, name: str) -> bool:
        return docker(kind, "inspect", name, timeout=60).ok

    # --- evidence -----------------------------------------------------------------------

    def record(self) -> FleetRecord:
        return FleetRecord(
            host_image_identity=self.image_identity or observation_digest({"host_image": "absent"}),
            controller_host_identity=observation_digest(
                {"role": ROLE_CONTROLLER, "name": self.container_name(ROLE_CONTROLLER)}
            ),
            worker_host_identity=observation_digest(
                {"role": ROLE_WORKER, "name": self.container_name(ROLE_WORKER)}
            ),
            network_identity=observation_digest({"network": self.network}),
            hosts_created=self.created,
            hosts_destroyed=self.destroyed,
            nested_container_runtime=True,
            real_service_manager=True,
        )

    def controller(self) -> Host:
        return self._host(ROLE_CONTROLLER)

    def worker(self) -> Host:
        return self._host(ROLE_WORKER)

    def _host(self, role: str) -> Host:
        host = self.hosts.get(role)
        if host is None:
            raise AcceptanceError("acceptance_host_create_failed")
        return host


__all__ = [
    "HOST_DNS",
    "ROLES",
    "ROLE_CONTROLLER",
    "ROLE_WORKER",
    "Host",
    "HostFleet",
]
