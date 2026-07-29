"""Typed controller-enrollment finalization compose/mount contract (SECP-PR5H-B2, 2b-3b-iii).

The reviewed, code-owned facts of how each finalization surface reaches the controller stack, as
TYPED structures (never free-form YAML fragments a caller supplies):

* the two API-plane one-shots (``provision_enrollment_signer_role_once``,
  ``activate_controller_identity_once``) each receive exactly ONE extra mount — its fixed handoff,
  bind-mounted READ-ONLY — and run ``--rm`` (removed after completion) with ``--no-deps``;
* the ordinary (non-root) API receives ONLY the signer-enablement MARKER, read-only, at its fixed
  path; it receives NEITHER handoff, NEITHER private key, NOR any DB credential;
* the root-gated broker gets the enrollment private key (read-only) + the DB plaintext (only through
  the systemd ``LoadCredential`` tmpfs) — never the API's business.

:func:`assert_no_secret_reaches_ordinary_api` is the guard proving no secret-bearing host path is
ever
mounted into the ordinary API. :func:`render_broker_reviewed_unit` renders the fixed broker unit
(with
its ``LoadCredential`` + the fixed ``BROKER_ENTRYPOINT``) as a content-bound :class:`ReviewedUnit`.
"""

from __future__ import annotations

from dataclasses import dataclass

from secp_commissioning.controller_enrollment_signer import CONTROLLER_ENROLLMENT_KEY_PATH
from secp_commissioning.enrollment_signer_binding_digest import (
    ENROLLMENT_SIGNER_READINESS_GATE_CONTAINER_PATH as READINESS_GATE_CONTAINER_PATH,
)

from secp_management import ManagementError
from secp_management.adapters import ReviewedUnit
from secp_management.enrollment_signer_db import ENROLLMENT_SIGNER_CREDENTIAL_ID
from secp_management.layout import ManagementLocations
from secp_management.systemd import render_enrollment_signer_broker_service, unit_identity
from secp_management.topology import BROKER_ENTRYPOINT


@dataclass(frozen=True)
class OneShotMount:
    """A fixed, code-owned bind mount: a root-controlled host path exposed at a fixed container
    path.
    Finalization mounts are ALWAYS read-only (``read_only=True``) — nothing the installer hands a
    container is writable by it."""

    host_path: str
    container_path: str
    read_only: bool = True

    def as_compose_volume(self) -> str:
        """The ``docker compose run --volume`` spec, e.g. ``/host/x:/run/y:ro``."""
        return f"{self.host_path}:{self.container_path}" + (":ro" if self.read_only else "")


def _loc(locations: ManagementLocations | None) -> ManagementLocations:
    return locations if locations is not None else ManagementLocations()


def secret_host_paths(locations: ManagementLocations | None = None) -> tuple[str, ...]:
    """Every secret-bearing host path the ordinary (non-root) API must NEVER receive as a mount: the
    0600 enrollment private key, the controller-API TLS server private key, the SCRAM-plaintext
    credential source, and both transient one-shot handoffs (each carries a verifier / identity fact
    the API must not read)."""
    loc = _loc(locations)
    return (
        CONTROLLER_ENROLLMENT_KEY_PATH,
        loc.controller_server_key_path(),
        loc.enrollment_signer_credential_path(),
        loc.provisioning_handoff_host_path(),
        loc.activation_handoff_host_path(),
    )


def provisioning_oneshot_mount(locations: ManagementLocations | None = None) -> OneShotMount:
    loc = _loc(locations)
    return OneShotMount(
        loc.provisioning_handoff_host_path(), loc.provisioning_handoff_container_path()
    )


def activation_oneshot_mount(locations: ManagementLocations | None = None) -> OneShotMount:
    loc = _loc(locations)
    return OneShotMount(loc.activation_handoff_host_path(), loc.activation_handoff_container_path())


def api_marker_mount(locations: ManagementLocations | None = None) -> OneShotMount:
    """The ONLY finalization mount the ordinary API receives: the signer-enablement marker,
    read-only,
    host path == container path (``/etc/secp/controller/enrollment-signer.enabled``)."""
    loc = _loc(locations)
    path = loc.api_signer_marker_path()
    return OneShotMount(path, path)


def api_readiness_gate_mount(locations: ManagementLocations | None = None) -> OneShotMount:
    """The readiness-origin GATE mount: read-only, host path -> the fixed API container path.

    This is the ONE authorization-only secret the ordinary API may receive (2b-3c-c). It carries no
    identity, key, credential or database material -- it only proves that a caller of the fixed
    readiness route is the root management installer."""
    loc = _loc(locations)
    return OneShotMount(loc.api_signer_readiness_gate_path(), READINESS_GATE_CONTAINER_PATH)


def assert_no_secret_reaches_ordinary_api(
    api_host_mounts: tuple[str, ...], *, locations: ManagementLocations | None = None
) -> None:
    """Prove no FORBIDDEN secret-bearing host path is mounted into the ordinary API.

    ``api_host_mounts`` is the set of host paths mounted into the ordinary API service. The
    enrollment private key, the controller TLS server key, the SCRAM credential source and both
    transient one-shot handoffs remain forbidden and fail closed
    (``finalization_secret_mount_reaches_api``).

    EXACTLY ONE authorization-only secret is permitted: the readiness-origin gate
    (:func:`api_readiness_gate_mount`), which authenticates the root installer to the fixed
    readiness route and carries no identity, key, credential or database material. It is
    deliberately absent from :func:`secret_host_paths` for that reason; anything else is refused."""
    secrets = set(secret_host_paths(locations))
    for host_path in api_host_mounts:
        if host_path in secrets:
            raise ManagementError("finalization_secret_mount_reaches_api")


def render_broker_reviewed_unit(locations: ManagementLocations | None = None) -> ReviewedUnit:
    """Render the fixed root-gated broker unit — ``ExecStart=BROKER_ENTRYPOINT`` (no argument),
    ``LoadCredential`` of the dedicated-role SCRAM secret, present-but-disabled (started explicitly
    by
    the installer, never enabled from an HTTP request) — as a content-bound
    :class:`ReviewedUnit`."""
    loc = _loc(locations)
    text = render_enrollment_signer_broker_service(
        exec_argv=BROKER_ENTRYPOINT,
        load_credential=(ENROLLMENT_SIGNER_CREDENTIAL_ID, loc.enrollment_signer_credential_path()),
        wanted_by=None,
    )
    return ReviewedUnit(identity=unit_identity(text), content=text.encode("utf-8"))


__all__ = [
    "OneShotMount",
    "activation_oneshot_mount",
    "api_marker_mount",
    "api_readiness_gate_mount",
    "assert_no_secret_reaches_ordinary_api",
    "provisioning_oneshot_mount",
    "render_broker_reviewed_unit",
    "secret_host_paths",
]
