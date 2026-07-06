"""Verified offline artifact pipeline (SECP-B4 §6).

Before the isolated network exists, the engine stages a CLOSED catalog of approved base artifacts
(base image, control-plane payload, OpenBao binary, nested-target installer) to SECP-owned storage.
Each artifact has a deterministic identity, an integrity digest, provenance, a bounded size,
and safe expiry. The generated cloud-init / config-drive installs ONLY from the staged local
artifacts and configures the guest fully offline (no package registry, DNS, proxy, or Internet), so
the isolated control plane and nested target can never fetch a dependency after isolation.

No real artifact bytes, hosts, URLs, checksums, or credentials are embedded in the repository. The
blob source is injected (sealed default refuses); staging fails closed if an artifact is unavailable
or fails integrity. Fully testable with fake blobs; nothing is downloaded during implementation.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from secp_api.deployment_contract import ARTIFACT_CATALOG_VERSION

# Bounded maximum artifact size (app-owned constant; a larger blob fails closed).
_MAX_ARTIFACT_BYTES = 8 * 1024 * 1024 * 1024


class ArtifactPipelineError(Exception):
    """Fail-closed artifact error. Closed reason only — never a URL/host/checksum/credential."""

    def __init__(self, reason_code: str) -> None:
        super().__init__(f"artifact pipeline refused: {reason_code}")
        self.reason_code = reason_code


@dataclass(frozen=True)
class ArtifactSpec:
    """A pinned, closed catalog artifact. ``artifact_id`` is an app-owned opaque label; there is no
    URL/host here — provenance is a closed label, and integrity is a content digest."""

    artifact_id: str
    kind: str  # base_image | control_plane_payload | openbao_binary | nested_target_installer
    provenance: str  # closed provenance label (e.g. "secp-approved-offline-mirror")
    size_bytes: int
    # The expected content digest (``sha256:...``) an artifact blob must match, byte-for-byte.
    integrity: str


# The closed catalog. Digests are DETERMINISTIC placeholders derived from the artifact identity (a
# real deployment pins real digests out of band); they are NOT real checksums and carry no host/URL/
# secret. The point proved here is: staging is integrity-gated and the guest bootstrap is offline.
def _placeholder_digest(artifact_id: str) -> str:
    payload = f"{ARTIFACT_CATALOG_VERSION}|{artifact_id}".encode()
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _catalog(manifest_id: str) -> tuple[ArtifactSpec, ...]:
    kinds = (
        ("base_image", 2 * 1024 * 1024 * 1024),
        ("control_plane_payload", 512 * 1024 * 1024),
        ("openbao_binary", 128 * 1024 * 1024),
        ("nested_target_installer", 1 * 1024 * 1024 * 1024),
    )
    return tuple(
        ArtifactSpec(
            artifact_id=f"{manifest_id}/{kind}",
            kind=kind,
            provenance="secp-approved-offline-mirror",
            size_bytes=size,
            integrity=_placeholder_digest(f"{manifest_id}/{kind}"),
        )
        for kind, size in kinds
    )


def artifacts_for(manifest_id: str) -> tuple[ArtifactSpec, ...]:
    """Return the closed approved-artifact set a manifest pins (deterministic; no external ref)."""
    if not (isinstance(manifest_id, str) and manifest_id.startswith(ARTIFACT_CATALOG_VERSION)):
        raise ArtifactPipelineError("unknown_artifact_manifest")
    return _catalog(manifest_id)


@runtime_checkable
class ArtifactBlobSource(Protocol):
    """Injected, pre-isolation source of approved artifact bytes (a real one reads a vetted offline
    mirror BEFORE the isolated plane exists). The shipped default refuses."""

    def fetch(self, artifact_id: str) -> bytes: ...


class SealedArtifactBlobSource:
    """The shipped default: NO blobs. Refuses — downloads nothing, contacts nothing."""

    def fetch(self, artifact_id: str) -> bytes:
        raise ArtifactPipelineError("artifact_source_sealed")


@dataclass(frozen=True)
class StagedArtifact:
    artifact_id: str
    kind: str
    verified: bool
    # The SECP-owned local storage reference the guest installs from (generated; never a real path).
    staged_ref: str


def verify_and_stage(
    *, manifest_id: str, ownership_tag: str, blob_source: ArtifactBlobSource
) -> tuple[StagedArtifact, ...]:
    """Fetch (pre-isolation) + integrity-verify + stage each approved artifact to owned storage.
    Fails closed on an unavailable blob, a size overflow, or an integrity mismatch."""
    staged = []
    for spec in artifacts_for(manifest_id):
        try:
            blob = blob_source.fetch(spec.artifact_id)
        except ArtifactPipelineError:
            raise
        except Exception as exc:  # never surface a raw source error
            raise ArtifactPipelineError("artifact_unavailable") from exc
        if not isinstance(blob, bytes | bytearray) or len(blob) > _MAX_ARTIFACT_BYTES:
            raise ArtifactPipelineError("artifact_size_invalid")
        digest = "sha256:" + hashlib.sha256(bytes(blob)).hexdigest()
        if digest != spec.integrity:
            raise ArtifactPipelineError("artifact_integrity_failed")
        staged.append(
            StagedArtifact(
                artifact_id=spec.artifact_id,
                kind=spec.kind,
                verified=True,
                staged_ref=f"secp-store:{ownership_tag}:{spec.kind}",
            )
        )
    return tuple(staged)


def build_offline_guest_bootstrap(staged: tuple[StagedArtifact, ...]) -> dict:
    """Build a reproducible, FULLY OFFLINE guest bootstrap (cloud-init-shaped) that installs ONLY
    from the staged local artifacts. It disables every network package path (no apt/dns/proxy), so a
    post-isolation guest cannot fetch an arbitrary dependency."""
    return {
        "schema": "secp-b4/offline-guest-bootstrap/v1",
        # Offline package posture: no external sources, no updates/upgrades, no network at boot.
        "apt": {"preserve_sources_list": False, "sources": {}, "disable_suites": ["all"]},
        "package_update": False,
        "package_upgrade": False,
        "manage_resolv_conf": False,
        "network": {"config": "disabled"},
        "environment": {
            # Neutralize any ambient proxy so no tool can reach out.
            "http_proxy": "",
            "https_proxy": "",
            "no_proxy": "*",
        },
        # Install strictly from the staged local artifact references.
        "install_from_local": [s.staged_ref for s in staged],
        "offline": True,
    }
