"""Typed HTTPS discovery operations. One type per exact reviewed request.

There is no ``get(path)`` on this surface. Orchestration selects an operation TYPE; the type renders
its own path from a reviewed template, and a caller has nowhere to put a path, a query parameter or
a method. That is the difference between a request that cannot be misdirected and one that is
checked for misdirection.

First-MVP scope is deliberately one operation. ``/version`` is the right one to establish the seam
with: it needs no privilege at all, it is side-effect-free, and it carries the exact patch version
that provider compatibility is decided on — so the vertical slice proves the whole path while asking
the target for the least it can.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar

#: Bound into signed evidence so a snapshot names the code that interpreted it. A parse produced by
#: a different implementation is a different observation even from identical bytes.
VERSION_PARSER_IMPLEMENTATION_ID = "secp.proxmox-discovery.version-parser/v1"
VERSION_NORMALIZER_IMPLEMENTATION_ID = "secp.proxmox-discovery.version-normalizer/v1"


@dataclass(frozen=True)
class GetVersionOperation:
    """``GET /version`` — the Proxmox API's own view of its version.

    Takes no parameters, so there is nothing a caller can influence. The path template and the
    rendered path are identical here precisely because it interpolates nothing; operations that do
    take a segment will differ, and both are signed so a reviewer sees the permitted shape as well
    as the instance.
    """

    operation_code: ClassVar[str] = "api_version"
    path_template: ClassVar[str] = "/version"
    observation_field_codes: ClassVar[tuple[str, ...]] = (
        "pve_version_full",
        "pve_version_major",
        "pve_version_minor",
        "pve_version_patch",
        "pve_release",
        "pve_repoid",
    )

    def rendered_path(self) -> str:
        return self.path_template

    def query_parameters(self) -> tuple[tuple[str, str], ...]:
        return ()


#: Every operation the first-MVP production composition may execute. Orchestration picks from this
#: set; it cannot construct a request outside it.
FIRST_MVP_OPERATIONS: tuple[type, ...] = (GetVersionOperation,)
