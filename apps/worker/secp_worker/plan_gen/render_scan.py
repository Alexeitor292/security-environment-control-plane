"""Controlled-live render-safety scanner (SECP-002B-1B-PR5B, ADR-022 §4).

A PURE, deterministic, versioned gate that a controlled-live plan-only workspace MUST pass before it
is ever materialized or fed to a real OpenTofu process. It exists so the review of "what the live
renderer may emit" is enforced in code, not by inspection.

It is deliberately fail-closed and allowlist-first: it refuses the fake fixture provider path (so
the inert B1-A adapter can NEVER reach a controlled-live plan), refuses every dangerous OpenTofu
construct (provisioners, local/remote-exec, external data sources, local backend, remote source
fetch, unpinned providers, registry fallback), refuses secret-looking literals, and requires the
EXACT reviewed provider source + an EXACT ``= <version>`` pin and only the supported resource types.

This module performs NO I/O, imports NO worker/process/provider code, and never runs OpenTofu. It
operates on already-rendered in-memory file text only. It does not by itself unseal anything.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# Bump on ANY change to the refusal rules. Bound into the workspace hash + result provenance so a
# scanner change invalidates prior evidence.
CONTROLLED_LIVE_RENDER_SCANNER_VERSION = "secp-002b-1b-pr5b/controlled-live-render-scan/v1"

# The ONE reviewed controlled-live provider. Never "latest", never a fixture, never a registry URL.
CONTROLLED_LIVE_PROVIDER_SOURCE = "bpg/proxmox"

# Fixture identifiers from the inert B1-A adapter. Their presence PROVES the text is the fake path,
# which can never be promoted to controlled-live (ADR-022 §2 / task §2).
_FAKE_IDENTIFIERS = (
    "example.test",
    "fake/labproxmox",
    "labproxmox",
    "0.0.0-fake",
    "labfake_",
)

# Dangerous OpenTofu constructs that a plan-only, no-side-effect workspace must never contain.
_FORBIDDEN_CONSTRUCTS = (
    'provisioner "',
    "local-exec",
    "remote-exec",
    'data "external"',
    'data "http"',
    'backend "local"',
    "file(",  # arbitrary local file read
    "templatefile(",  # arbitrary template expansion
    "fileexists(",
    "abspath(",
    "pathexpand(",
    "getenv(",  # environment interpolation
    "$${",  # escaped interpolation smuggling
)

# A registry/remote source fetch anywhere is refused: providers/modules come only from the exact
# offline mirror, never a URL or a bare registry path.
_REMOTE_SOURCE_RE = re.compile(
    r'source\s*=\s*"[^"]*(://|registry\.|github\.com|git::)', re.IGNORECASE
)

# Any secret-looking literal ASSIGNMENT (a quoted value on the RHS). The identifier may be prefixed
# (``api_token``, ``pm_api_token``, ``db_password``), so match any identifier ENDING in a secret
# word followed by a quoted VALUE. A ``var.pm_api_token`` reference (unquoted RHS) never matches; a
# ``variable "x"`` declaration or ``sensitive = true`` is fine.
_SECRET_LITERAL_RE = re.compile(
    r"(?i)[a-z0-9_]*"
    r"(?:token|password|passwd|secret|api[_-]?key|apikey|credential|private[_-]?key)"
    r'[a-z0-9_]*\s*=\s*"[^"]+"'
)

# A pinned provider version must be exactly ``= X.Y.Z`` (optionally with pre-release), never a
# range,
# ">=", "~>", "latest", or unpinned.
_EXACT_VERSION_RE = re.compile(r'version\s*=\s*"=\s*\d+\.\d+\.\d+[0-9A-Za-z.+-]*"')
# Any version constraint that is NOT an exact pin (used to refuse ranges/latest/unpinned).
_ANY_VERSION_RE = re.compile(r'version\s*=\s*"([^"]*)"')

# A ``resource "TYPE" "NAME"`` declaration.
_RESOURCE_RE = re.compile(r'resource\s+"([^"]+)"\s+"[^"]+"')
# A ``data "TYPE" "NAME"`` declaration.
_DATA_RE = re.compile(r'data\s+"([^"]+)"\s+"[^"]+"')
# A ``required_providers { NAME = { source = "..." ... } }`` source line.
_SOURCE_RE = re.compile(r'source\s*=\s*"([^"]+)"')


class ControlledLiveRenderRefused(Exception):
    """A rendered controlled-live workspace violated the render-safety contract.

    Carries a bounded, closed reason code only — never the offending file text or any value.
    """

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


@dataclass(frozen=True)
class RenderScanContract:
    """The exact reviewed expectations for a controlled-live workspace (from immutable profile).

    ``provider_source`` MUST be the exact reviewed source; ``provider_version`` is the exact pin
    from the immutable ``ToolchainProfile``; ``supported_resource_types`` is the closed allowlist of
    resource types the initial narrow module may declare; ``allowed_data_sources`` is the (usually
    empty) closed allowlist of data-source types.
    """

    provider_source: str
    provider_version: str
    supported_resource_types: frozenset[str]
    allowed_data_sources: frozenset[str] = frozenset()
    scanner_version: str = CONTROLLED_LIVE_RENDER_SCANNER_VERSION


def controlled_live_render_scan(files: dict[str, str], *, contract: RenderScanContract) -> None:
    """Refuse any controlled-live workspace that violates the render-safety contract (fail-closed).

    Raises :class:`ControlledLiveRenderRefused` with a bounded reason code. It never echoes file
    content. A workspace that passes has: the exact reviewed provider source + an exact version pin,
    only the supported resource types, only allowlisted data sources, NO fixture identifiers, NO
    provisioners / exec / external / local-backend / remote source / secret literals / interpolation
    abuse. Passing does NOT itself authorize execution — the seal + capability + composition do.
    """
    if contract.scanner_version != CONTROLLED_LIVE_RENDER_SCANNER_VERSION:
        raise ControlledLiveRenderRefused("render_scanner_version_mismatch")
    if contract.provider_source != CONTROLLED_LIVE_PROVIDER_SOURCE:
        # The contract itself must name the one reviewed source; anything else is refused up front.
        raise ControlledLiveRenderRefused("provider_source_not_reviewed")
    if not _EXACT_VERSION_RE.fullmatch(f'version = "= {contract.provider_version}"'):
        raise ControlledLiveRenderRefused("provider_version_not_exactly_pinned")

    if not files:
        raise ControlledLiveRenderRefused("empty_workspace")

    provider_declared = False
    for _name, text in sorted(files.items()):
        low = text.lower()

        for marker in _FAKE_IDENTIFIERS:
            if marker in low:
                raise ControlledLiveRenderRefused("fake_provider_or_resource_identifier")
        for construct in _FORBIDDEN_CONSTRUCTS:
            if construct in low:
                raise ControlledLiveRenderRefused("forbidden_construct")
        if _REMOTE_SOURCE_RE.search(text):
            raise ControlledLiveRenderRefused("remote_source_fetch")
        if _SECRET_LITERAL_RE.search(text):
            raise ControlledLiveRenderRefused("secret_looking_literal")

        # Every provider ``source`` must be the exact reviewed source.
        for source in _SOURCE_RE.findall(text):
            if source == contract.provider_source:
                provider_declared = True
            elif "/" in source and not source.startswith("./") and not source.startswith("../"):
                # A registry-style provider/module source other than the reviewed one.
                raise ControlledLiveRenderRefused("unreviewed_source")

        # Every version constraint must be an EXACT pin.
        for constraint in _ANY_VERSION_RE.findall(text):
            token = constraint.strip()
            if token.startswith("="):
                # exact pin form "= X.Y.Z"
                if not _EXACT_VERSION_RE.search(f'version = "{constraint}"'):
                    raise ControlledLiveRenderRefused("provider_version_not_exactly_pinned")
            else:
                raise ControlledLiveRenderRefused("provider_version_not_exactly_pinned")

        # Only the supported resource types may be declared.
        for res_type in _RESOURCE_RE.findall(text):
            if res_type not in contract.supported_resource_types:
                raise ControlledLiveRenderRefused("unsupported_resource_type")

        # Only allowlisted data sources may be read.
        for data_type in _DATA_RE.findall(text):
            if data_type not in contract.allowed_data_sources:
                raise ControlledLiveRenderRefused("unallowed_data_source")

    if not provider_declared:
        raise ControlledLiveRenderRefused("provider_declaration_missing")
