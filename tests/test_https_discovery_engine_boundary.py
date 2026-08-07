"""The HTTPS discovery engine is structurally incapable of mutation, and this is what scans it.

``tests/test_discovery_boundary.py`` proves that property for
``secp_worker/target_discovery`` — the LEGACY SSH probe package. The HTTPS engine that replaced it
lives at the top level of ``secp_worker`` and was scanned by nothing: five modules carrying the
whole production discovery path sat outside every structural guard, and the composition's claim to
have "no route to the legacy probe path, not a disabled route, no route" was verified by no test at
all. It was in fact false — the version parser imported the legacy probe module — which is exactly
what an unscanned claim becomes.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]
_WORKER = _ROOT / "apps" / "worker" / "secp_worker"

#: Every module of the production HTTPS discovery engine. Listed explicitly AND checked for
#: completeness below, so a new engine module cannot join the tree unscanned.
ENGINE_MODULES: tuple[str, ...] = (
    "proxmox_discovery_composition.py",
    "proxmox_discovery_operations.py",
    "proxmox_discovery_plan.py",
    "proxmox_discovery_projection.py",
    # The production entry point. It composes the engine and must be scanned exactly like the parts
    # it composes — an entry point that could reach a mutation-capable module would make every
    # guarantee below irrelevant, since it is the one module a runtime actually calls.
    "proxmox_discovery_runtime.py",
    "proxmox_discovery_transport.py",
    "proxmox_sdn_operations.py",
)

#: Import roots that would make mutation reachable. ``os`` is included for the same reason the
#: legacy guard includes it: discovery must not shell out or touch the process environment.
_FORBIDDEN_ROOTS = frozenset(
    {"subprocess", "os", "paramiko", "fabric", "asyncssh", "proxmoxer", "requests", "aiohttp"}
)

#: Fully-qualified modules that are mutation-capable, or that are the LEGACY probe contract the
#: engine claims to have no route to.
_FORBIDDEN_MODULES = frozenset(
    {
        "secp_worker.target_discovery",
        "secp_worker.discovery",
        "secp_worker.deployment.mutation_executor",
        "secp_worker.deployment.mutations",
        "secp_worker.deployment.engine",
        "secp_worker.deployment.ssh_bootstrap",
        "secp_worker.ssh_channel",
        "secp_worker.plan_gen",
        "secp_plugin_proxmox.mutation_transport",
    }
)


def _engine_paths() -> list[Path]:
    return [_WORKER / name for name in ENGINE_MODULES]


def _imports(tree: ast.AST) -> set[str]:
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            found.add(node.module)
    return found


def test_every_engine_module_exists_and_is_scanned():
    for path in _engine_paths():
        assert path.is_file(), path


def test_the_module_list_covers_every_proxmox_engine_module_in_the_tree():
    """Inverted: a new ``proxmox_*`` module joining the worker package must be added here, rather
    than silently escaping the scan the way these five did."""
    present = {p.name for p in _WORKER.glob("proxmox_*.py") if "__pycache__" not in p.parts}
    assert present == set(ENGINE_MODULES), sorted(present.symmetric_difference(ENGINE_MODULES))


@pytest.mark.parametrize("name", ENGINE_MODULES)
def test_no_engine_module_imports_a_mutation_capable_or_legacy_module(name):
    path = _WORKER / name
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for module in _imports(tree):
        root = module.split(".")[0]
        assert root not in _FORBIDDEN_ROOTS, f"{name} imports {module!r}"
        for forbidden in _FORBIDDEN_MODULES:
            assert not (module == forbidden or module.startswith(forbidden + ".")), (
                f"{name} imports {module!r}"
            )


@pytest.mark.parametrize("name", ENGINE_MODULES)
def test_no_engine_module_names_a_write_verb_or_a_shell(name):
    source = (_WORKER / name).read_text(encoding="utf-8")
    for forbidden in (
        "subprocess",
        "pvesh ",
        "pveum ",
        "os.system",
        "popen",
        "tofu ",
        "terraform ",
    ):
        assert forbidden not in source, f"{name} contains {forbidden!r}"


@pytest.mark.parametrize("name", ENGINE_MODULES)
def test_no_engine_module_can_express_a_non_get_request(name):
    """Not "refuses a mutation" — cannot represent one. There is no method parameter anywhere on
    the surface, so a POST is not expressible rather than expressible and checked."""
    source = (_WORKER / name).read_text(encoding="utf-8")
    for verb in ('"POST"', "'POST'", '"PUT"', "'PUT'", '"DELETE"', "'DELETE'", '"PATCH"'):
        assert verb not in source, f"{name} names {verb}"


def test_the_transport_is_the_only_module_that_opens_a_client():
    """One place reaches the network, and every other module talks to it through a narrow seam."""
    openers = []
    for path in _engine_paths():
        source = path.read_text(encoding="utf-8")
        if "open_hardened_client" in source:
            openers.append(path.name)
    assert openers == ["proxmox_discovery_transport.py"], openers


def test_the_composition_reaches_no_legacy_probe_even_transitively():
    """The claim in the composition's own docstring, verified rather than asserted.

    It was false when written: the version parser imported ``target_discovery.probes`` for
    ``parse_api_version``, so the production run did transitively import the legacy SSH probe
    contract — the module that owns ``render_probe_argv`` and the ``pvesh`` argv grammar.
    """
    seen: set[str] = set()
    queue = ["secp_worker.proxmox_discovery_composition"]
    while queue:
        module = queue.pop()
        if module in seen:
            continue
        seen.add(module)
        name = module.split(".")[-1] + ".py"
        path = _WORKER / name
        if not path.is_file():
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for imported in _imports(tree):
            assert not imported.startswith("secp_worker.target_discovery"), (
                f"{name} reaches the legacy probe contract via {imported!r}"
            )
            if imported.startswith("secp_worker."):
                queue.append(imported)
