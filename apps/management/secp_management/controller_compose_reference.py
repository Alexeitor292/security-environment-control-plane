"""The reference controller Compose template a conforming SIGNED release must carry (2b-3c-c).

This is NOT a renderer and NOT an installer input: the installer never authors or mutates Compose
YAML — it installs the signed artifact verbatim. This module exists so that

* the management test suites can sign and install a template that exercises the REAL contract
  instead of the placeholder comment that made a green CI prove nothing about the mount, and
* a release engineer has one reviewable, byte-deterministic statement of what
  :func:`~secp_management.controller_compose_validation.assert_controller_compose_contract`
  requires, expressed in the same path constants the validator imports.

It carries no secret value, no deployment host name, no credential, no registry reference and no
image tag: only the service names in the caller's declared scope and the two reviewed read-only
binds. A release is free to carry a richer template — the contract constrains what MUST be true of
``services.api``, not what else a release may declare.
"""

from __future__ import annotations

from typing import Final

from secp_commissioning.enrollment_signer_binding_digest import (
    ENROLLMENT_SIGNER_READINESS_GATE_CONTAINER_PATH,
    ENROLLMENT_SIGNER_READINESS_GATE_HOST_PATH,
)
from secp_commissioning.enrollment_signer_marker import ENROLLMENT_SIGNER_MARKER_PATH

from secp_management.controller_compose_validation import CONTROLLER_API_SERVICE

#: Deterministic two-space-indented YAML. Written literally rather than dumped, so the bytes a test
#: signs are the bytes a reviewer reads, and no serializer setting can silently change them.
_MOUNT_BLOCK: Final = f"""\
    volumes:
      - type: bind
        source: {ENROLLMENT_SIGNER_MARKER_PATH}
        target: {ENROLLMENT_SIGNER_MARKER_PATH}
        read_only: true
        bind:
          create_host_path: false
      - type: bind
        source: {ENROLLMENT_SIGNER_READINESS_GATE_HOST_PATH}
        target: {ENROLLMENT_SIGNER_READINESS_GATE_CONTAINER_PATH}
        read_only: true
        bind:
          create_host_path: false
"""


def reference_controller_compose(*, services: tuple[str, ...] = (CONTROLLER_API_SERVICE,)) -> bytes:
    """A byte-deterministic controller Compose template satisfying the contract.

    ``services`` names the reviewed controller services in the caller's scope; the API service is
    always present and always carries both reviewed read-only binds. No secret, host name,
    credential or registry reference is ever emitted."""
    names = (CONTROLLER_API_SERVICE,) + tuple(s for s in services if s != CONTROLLER_API_SERVICE)
    lines = ["services:"]
    for name in names:
        lines.append(f"  {name}:")
        lines.append("    restart: unless-stopped")
        if name == CONTROLLER_API_SERVICE:
            lines.append(_MOUNT_BLOCK.rstrip("\n"))
    return ("\n".join(lines) + "\n").encode("utf-8")


__all__ = ["reference_controller_compose"]
