"""Provider-neutral workspace rendering (SECP-002B-1A, ADR-013) — worker-only.

Converts an immutable ``ProvisioningManifest`` + immutable ``ToolchainProfile`` into a
deterministic, secret-free rendered workspace with a content hash. It records the
manifest hash, scope-policy hash, toolchain-profile hash, renderer version, and
module-bundle hash so any drift can be detected. The rendered artifact contains **no
secrets, secret refs, endpoint-auth, or resolved credentials**; provider endpoint/token
are referenced only as input variables injected just-in-time at real apply (B1-B).

Local state is refused; provider plugins/modules are expected from an offline, pinned,
verified worker-side mirror (enforced by the toolchain profile + the runner's CLI flags).
Files are materialized only into an ephemeral, restrictive-permission workspace.
"""

from __future__ import annotations

import os
import re
import stat
import tempfile
from dataclasses import dataclass, field

from secp_scenario_schema import content_hash

from secp_worker.provisioning.adapters.base import AdapterError, get_adapter

# The renderer's own version. A toolchain profile must pin THIS exact version, so a
# profile rendered by a different renderer fails closed (renderer drift, proof #6).
RENDERER_VERSION = "secp-002b-1a/renderer/v1"

_LOCAL_STATE_TOKENS = {"local", "local-state", "localfs", "file", "disk", ""}
# A quoted literal assigned to a secret-like key would be a leaked secret. Variable
# references (``= var.x``) and ``sensitive = true`` declarations are allowed.
_SECRET_LITERAL_RE = re.compile(
    r'(pass|passwd|password|secret|token|api[_-]?key|apikey|credential)\s*=\s*"[^"]*"',
    re.IGNORECASE,
)
_SECRET_REF_RE = re.compile(r"\benv:SECP", re.IGNORECASE)


class RenderingError(Exception):
    """Rendering failure. Messages are redacted (never include secrets)."""


@dataclass(frozen=True)
class RenderedWorkspace:
    """A deterministic, secret-free rendered workspace and its provenance hashes."""

    files: dict[str, str]
    content_hash: str
    manifest_content_hash: str
    scope_policy_hash: str
    toolchain_profile_hash: str
    renderer_version: str
    module_bundle_hash: str
    adapter_kind: str
    provenance: dict = field(default_factory=dict)


def _assert_secret_free(files: dict[str, str]) -> None:
    for path, body in files.items():
        for line in body.splitlines():
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            if _SECRET_REF_RE.search(line):
                raise RenderingError(f"rendered file {path} contains a secret reference")
            m = _SECRET_LITERAL_RE.search(line)
            if m and "var." not in line and "sensitive" not in line:
                raise RenderingError(
                    f"rendered file {path} contains a secret-like literal assignment"
                )


def _render_backend(profile: dict) -> str:
    """Render a REMOTE backend block from the profile. Local state is refused."""
    backend = profile.get("state_backend") or {}
    kind = str(backend.get("kind", "")).strip().lower()
    reference = str(backend.get("reference", ""))
    if kind in _LOCAL_STATE_TOKENS:
        raise RenderingError(
            "local-only OpenTofu state is refused; a remote state backend is required"
        )
    if not reference:
        raise RenderingError("state backend reference is missing")
    return (
        "# GENERATED — remote state backend (no local state). Secret-free reference only.\n"
        "terraform {\n"
        f'  backend "{kind}" {{\n'
        f"    # workspace_key reference: {reference}\n"
        "  }\n"
        "}\n"
    )


class WorkspaceRenderer:
    """Renders a manifest + toolchain profile into a secret-free workspace."""

    renderer_version = RENDERER_VERSION

    def render(self, manifest: dict, profile: dict) -> RenderedWorkspace:
        # Defensive re-validation of the profile shape (control-plane validated it at
        # registration; the worker never trusts unvalidated input).
        from secp_api.toolchain_profile import toolchain_profile_hash, validate_toolchain_profile

        spec = validate_toolchain_profile(profile)

        # Renderer-version binding: a profile pinned to a different renderer fails closed.
        if spec.renderer_version != RENDERER_VERSION:
            raise RenderingError(
                "toolchain profile renderer_version does not match this renderer "
                f"({spec.renderer_version!r} != {RENDERER_VERSION!r}); "
                "regenerate the plan/manifest with a matching profile"
            )

        adapter = get_adapter(spec.adapter_kind)
        try:
            files = dict(adapter.render(manifest, profile))
        except AdapterError as exc:
            raise RenderingError(f"workspace rendering failed: {exc}") from exc

        # A remote backend is always rendered by the renderer (generic, not per-provider).
        files["backend.tf"] = _render_backend(profile)

        _assert_secret_free(files)

        canonical_files = {path: files[path] for path in sorted(files)}
        ws_hash = content_hash({"files": canonical_files, "renderer": RENDERER_VERSION})
        return RenderedWorkspace(
            files=canonical_files,
            content_hash=ws_hash,
            manifest_content_hash=content_hash(manifest),
            scope_policy_hash=str(manifest.get("target_scope_policy_hash") or ""),
            toolchain_profile_hash=toolchain_profile_hash(profile),
            renderer_version=RENDERER_VERSION,
            module_bundle_hash=str(spec.module_bundle_hash),
            adapter_kind=spec.adapter_kind,
            provenance={
                "opentofu_version": spec.opentofu_version,
                "provider_lockfile_hash": spec.provider_lockfile_hash,
                "provider_mirror": spec.provider_mirror.identity,
                "state_backend_kind": spec.state_backend.kind,
                "activation_class": spec.activation_class,
            },
        )

    def materialize(self, workspace: RenderedWorkspace, *, root: str | None = None) -> str:
        """Write files to an ephemeral, restrictive-permission workspace directory.

        Returns the created directory path. Files are written 0o600 inside a 0o700
        directory (best-effort on platforms without full POSIX permissions).
        """
        base = root or tempfile.gettempdir()
        os.makedirs(base, exist_ok=True)
        workdir = tempfile.mkdtemp(prefix="secp-tofu-ws-", dir=base)
        try:
            os.chmod(workdir, stat.S_IRWXU)  # 0o700
        except (OSError, NotImplementedError):  # pragma: no cover - platform dependent
            pass
        for rel_path, body in workspace.files.items():
            full = os.path.join(workdir, rel_path)
            os.makedirs(os.path.dirname(full) or workdir, exist_ok=True)
            with open(full, "w", encoding="utf-8") as fh:
                fh.write(body)
            try:
                os.chmod(full, stat.S_IRUSR | stat.S_IWUSR)  # 0o600
            except (OSError, NotImplementedError):  # pragma: no cover - platform dependent
                pass
        return workdir
