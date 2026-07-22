"""Provider-neutrality guard for the management plane (SECP-PR5G).

The management plane must stay strictly provider-neutral: the same identities, signed release trust,
bootstrap evidence, enrollment, and code-owned config that work for a Proxmox target must work
unchanged for Kubernetes / AWS / Azure / GCP / VMware later.  No infrastructure-provider concept may
leak into any management data surface.

This is a STRUCTURAL guard, not a text scan: it inspects the data-carrying surfaces of every
``secp_management`` module — dataclass/pydantic field names, class + function names, and serialized
dict KEYS — and refuses any infrastructure-provider token.  Explanatory docstrings/comments and
negative help/error strings (e.g. "there is deliberately no proxmox command") legitimately name
providers and are NOT scanned; only the actual serialized/typed vocabulary is.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import secp_management

# Infrastructure-provider / IaC-tool tokens that must never name a management data surface.  Matched
# case-insensitively on WORD boundaries so 'aws' never matches 'flaws' and 'gce' never matches a
# larger identifier.  Controller-stack COMPONENTS (postgres/minio/keycloak/temporal/web) are the
# environment's own services, not infrastructure providers, and are intentionally NOT listed.
_FORBIDDEN = (
    "proxmox",
    "vmware",
    "vsphere",
    "vcenter",
    "esxi",
    "aws",
    "ec2",
    "eks",
    "amazon",
    "azure",
    "aks",
    "gcp",
    "gce",
    "gke",
    "kubernetes",
    "k8s",
    "openstack",
    "cloudstack",
    "hetzner",
    "linode",
    "digitalocean",
    "nutanix",
    "libvirt",
    "terraform",
    "opentofu",
    "ansible",
    "openbao",
)
_TOKEN = re.compile(r"\b(" + "|".join(_FORBIDDEN) + r")\b", re.IGNORECASE)


def _module_files() -> list[Path]:
    root = Path(secp_management.__file__).parent
    return sorted(p for p in root.glob("*.py"))


def _data_surface_names(tree: ast.AST) -> list[tuple[str, str]]:
    """Every data-carrying name in the module: class names, function names, annotated field names
    (class-body ``name: type`` targets), and dict KEY string literals.  Docstrings, comments, and
    non-key string VALUES are deliberately excluded."""
    out: list[tuple[str, str]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            out.append(("class", node.name))
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            out.append(("function", node.name))
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            out.append(("field", node.target.id))
        elif isinstance(node, ast.Dict):
            for key in node.keys:
                if isinstance(key, ast.Constant) and isinstance(key.value, str):
                    out.append(("dict-key", key.value))
    return out


def test_no_provider_token_in_any_management_data_surface() -> None:
    offenders: list[str] = []
    for path in _module_files():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for kind, name in _data_surface_names(tree):
            if _TOKEN.search(name):
                offenders.append(f"{path.name}: {kind} {name!r}")
    assert not offenders, "provider-specific tokens in management data surfaces: " + "; ".join(
        offenders
    )


def test_management_identity_fields_are_provider_neutral() -> None:
    from secp_management.evidence import ManagementPlaneIdentity

    fields = set(
        getattr(ManagementPlaneIdentity, "model_fields", None)
        or ManagementPlaneIdentity.__annotations__
    )
    # the reviewed neutral identity vocabulary — installation/release/source/role/plane only
    assert {"plane", "role", "installation_id", "release_digest", "source_sha"} <= fields
    for f in fields:
        assert not _TOKEN.search(f), f"provider token in ManagementPlaneIdentity field {f!r}"


def test_evidence_attestation_message_keys_are_provider_neutral() -> None:
    # the attestation message is the exact signed evidence vocabulary; its keys must stay neutral
    src = (Path(secp_management.__file__).parent / "evidence.py").read_text(encoding="utf-8")
    tree = ast.parse(src)
    func = next(
        n
        for n in ast.walk(tree)
        if isinstance(n, ast.FunctionDef) and n.name == "evidence_attestation_message"
    )
    keys = {
        k.value
        for node in ast.walk(func)
        if isinstance(node, ast.Dict)
        for k in node.keys
        if isinstance(k, ast.Constant) and isinstance(k.value, str)
    }
    assert keys, "expected the attestation message to build a keyed document"
    for k in keys:
        assert not _TOKEN.search(k), f"provider token in attestation key {k!r}"


def test_enrollment_and_layout_surfaces_are_provider_neutral() -> None:
    from secp_management import enrollment, layout

    for mod in (enrollment, layout):
        tree = ast.parse(Path(mod.__file__).read_text(encoding="utf-8"))
        for kind, name in _data_surface_names(tree):
            assert not _TOKEN.search(name), f"{mod.__name__}: provider token in {kind} {name!r}"
