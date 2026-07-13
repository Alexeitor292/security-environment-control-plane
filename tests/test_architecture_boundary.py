"""Hardening §5 — control-plane boundary regression checks.

Static (AST) guardrails proving the API application code (``secp_api``) cannot
directly perform privileged execution: no shell/subprocess, no IaC/config-mgmt or
provider SDK imports, and no direct plugin side-effecting calls
(``apply``/``reset``/``destroy``). Privileged work must go through the worker
boundary (Charter Invariants 6, 7; ADR-005).

Mechanism and limits: this is a static import/call scan. It catches direct,
statically-resolvable usage. It does not catch dynamic dispatch via ``getattr`` or
fully obfuscated calls; those are mitigated by the runtime inline-execution guard
(``secp_api.safety``) and the worker-only execution path. The combination is the
defense.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

API_PKG = Path(__file__).resolve().parents[1] / "apps" / "api" / "secp_api"

# Modules that must never be imported by the control-plane API (shell, remote
# exec, IaC/config-mgmt, provider SDKs).
HARD_FORBIDDEN_MODULES = {
    "subprocess",
    "paramiko",
    "fabric",
    "pexpect",
    "telnetlib",
    "asyncssh",
    "ansible",
    "python_terraform",
    "proxmoxer",
    "libvirt",
    "pyVmomi",
    "boto3",
    "botocore",
    "azure",
    "googleapiclient",
    "kubernetes",
    "docker",
    # SECP-002A: the API must not import the Proxmox plugin/client or a provider
    # HTTP client (proof #2). Provider contact is worker-only. (``httpx`` is seam-restricted
    # to the OIDC verifier below — that is authentication trust infrastructure, not provider
    # contact.)
    "secp_plugin_proxmox",
    "requests",
    "aiohttp",
    # SECP-002B-0: the API must not import an IaC runner/tool. The provisioning
    # runner is worker-only; OpenTofu/Terraform are never imported anywhere.
    "opentofu",
    "terraform",
    "python_tofu",
    "libtmux",
}

# Modules allowed only in specific seam files.
RESTRICTED_MODULES = {
    # The concrete plugin is wired only by the registry.
    "secp_plugin_simulator": {"registry.py"},
    # Orchestration (which drives plugin side effects) is imported only by the
    # inline-dispatch seam (ADR-005).
    "secp_worker": {"dispatch.py"},
    # ADR-017: the OIDC verifier is the ONLY API file allowed an HTTP client, and only to fetch the
    # configured issuer's discovery/JWKS (read-only authentication trust infrastructure — never a
    # provider/infrastructure call, which remains worker-only). No redirects, bounded, no ambient
    # proxy (see secp_api/oidc.py).
    "httpx": {"oidc.py"},
}

# Full module paths that must never be imported by any API file, including dispatch.py.
# These are worker-internal collector implementations; the API must only dispatch.
FULL_MODULE_FORBIDDEN = frozenset(
    {
        "secp_worker.onboarding.target_evidence",
    }
)

# Specific names that must never be imported by any API file.
FORBIDDEN_IMPORT_NAMES = frozenset(
    {
        "SimulatedTargetEvidenceCollector",
        "TargetEvidenceCollector",
    }
)

# Plugin side-effecting capability methods the API must never call directly.
PLUGIN_SIDE_EFFECT_METHODS = {"apply", "reset", "destroy"}


def _py_files() -> list[Path]:
    return [p for p in API_PKG.rglob("*.py") if "__pycache__" not in p.parts]


def _root_module(name: str) -> str:
    return name.split(".")[0]


def _dotted_parts(func: ast.AST) -> list[str]:
    parts: list[str] = []
    cur = func
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
    parts.reverse()
    return parts


def _scan(path: Path):
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    forbidden_imports: list[str] = []
    restricted_imports: list[str] = []
    shell_calls: list[str] = []
    side_effect_calls: list[str] = []

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = _root_module(alias.name)
                if root in HARD_FORBIDDEN_MODULES:
                    forbidden_imports.append(alias.name)
                if alias.name in FULL_MODULE_FORBIDDEN:
                    forbidden_imports.append(
                        f"{alias.name} (worker collector import forbidden in all API files)"
                    )
                for name in node.names:
                    if name.name in FORBIDDEN_IMPORT_NAMES:
                        forbidden_imports.append(f"{name.name} (collector class forbidden)")
                if root in RESTRICTED_MODULES and path.name not in RESTRICTED_MODULES[root]:
                    restricted_imports.append(alias.name)
        elif isinstance(node, ast.ImportFrom):
            root = _root_module(node.module or "")
            if root in HARD_FORBIDDEN_MODULES:
                forbidden_imports.append(node.module or "")
            mod = node.module or ""
            if mod in FULL_MODULE_FORBIDDEN or any(
                mod == m or mod.startswith(m + ".") for m in FULL_MODULE_FORBIDDEN
            ):
                forbidden_imports.append(
                    f"{mod} (worker collector import forbidden in all API files)"
                )
            for alias in node.names:
                if alias.name in FORBIDDEN_IMPORT_NAMES:
                    forbidden_imports.append(
                        f"{mod}.{alias.name} (collector class import forbidden)"
                    )
            if root in RESTRICTED_MODULES and path.name not in RESTRICTED_MODULES[root]:
                restricted_imports.append(mod)
        elif isinstance(node, ast.Call):
            parts = _dotted_parts(node.func)
            if parts:
                if parts[0] == "subprocess":
                    shell_calls.append(".".join(parts))
                elif parts[0] == "os" and parts[-1] in {"system", "popen", "spawn"}:
                    shell_calls.append(".".join(parts))
                elif parts[-1] in PLUGIN_SIDE_EFFECT_METHODS:
                    side_effect_calls.append(".".join(parts))

    return forbidden_imports, restricted_imports, shell_calls, side_effect_calls


@pytest.mark.parametrize("path", _py_files(), ids=lambda p: p.name)
def test_api_module_has_no_forbidden_boundary_usage(path: Path):
    forbidden, restricted, shell, side_effects = _scan(path)
    assert not forbidden, f"{path.name}: forbidden imports {forbidden}"
    assert not restricted, f"{path.name}: restricted imports outside seam: {restricted}"
    assert not shell, f"{path.name}: shell/subprocess calls {shell}"
    assert not side_effects, (
        f"{path.name}: direct plugin side-effect calls {side_effects} "
        "(apply/reset/destroy must run via the worker)"
    )


def test_scan_actually_found_files():
    # Guard against the scan silently matching nothing.
    assert len(_py_files()) >= 10
