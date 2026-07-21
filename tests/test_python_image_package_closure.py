"""Production Python image package-closure contract (SECP-PR5F.2).

The shared Python image (``infra/dev/Dockerfile.python``) installs the monorepo project editable, so
every local package root declared in ``pyproject.toml`` must be COPYied into the build context
before the install step.  A missing tree builds successfully but fails at runtime
(``ModuleNotFoundError``) — which is exactly how the reviewed PR5F controller/admission-proxy image
regressed.  These parse the TOML and the Dockerfile COPY contract (not brittle substrings) so a
future package declared in pyproject can never be silently absent from the image.  The real built
image is proven separately by the dedicated Docker smoke CI job.
"""

from __future__ import annotations

import importlib
import tomllib
from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]
_PYPROJECT = _REPO / "pyproject.toml"
_DOCKERFILE = _REPO / "infra" / "dev" / "Dockerfile.python"

# The reviewed set of local package roots (the directory that must be present in the image for each
# declared package).  Derived independently below and asserted equal, so a package added to or
# removed from pyproject forces a conscious review of this contract and the Dockerfile.
_EXPECTED_PACKAGE_ROOTS = {
    "apps/api",
    "apps/worker",
    "apps/commissioning",
    "apps/deployment",
    "apps/management",
    "contracts/scenario-schema",
    "contracts/plugin-api",
    "plugins/simulator",
    "plugins/proxmox",
}


def _pyproject() -> dict:
    return tomllib.loads(_PYPROJECT.read_text(encoding="utf-8"))


def _wheel_packages() -> list[str]:
    return _pyproject()["tool"]["hatch"]["build"]["targets"]["wheel"]["packages"]


def _package_roots() -> set[str]:
    # each entry is "<root>/<import_name>"; the root directory is what the image must contain
    return {package.rsplit("/", 1)[0] for package in _wheel_packages()}


def _dockerfile_copy_sources() -> set[str]:
    """The set of build-context source paths the Dockerfile COPYies in (excluding ``--from`` copies
    such as the uv binary, and excluding the destination token)."""

    text = _DOCKERFILE.read_text(encoding="utf-8")
    joined = text.replace("\\\n", " ")  # fold backslash line continuations
    sources: set[str] = set()
    for line in joined.splitlines():
        stripped = line.strip()
        if not stripped.upper().startswith("COPY "):
            continue
        tokens = stripped.split()[1:]  # drop the COPY keyword
        if any(token.startswith("--") for token in tokens):
            continue  # a flag-bearing copy (e.g. COPY --from=... /uv /bin/) is not a project source
        if len(tokens) < 2:
            continue
        for source in tokens[:-1]:  # the final token is the destination
            sources.add(source.removeprefix("./").rstrip("/") or ".")
    return sources


def _covered(root: str, sources: set[str]) -> bool:
    # a COPY of the root itself or any ancestor directory brings the root into the image
    return any(root == source or root.startswith(source + "/") for source in sources)


def test_wheel_package_roots_match_the_reviewed_set() -> None:
    assert _package_roots() == _EXPECTED_PACKAGE_ROOTS


def test_dockerfile_copies_every_declared_package_root() -> None:
    sources = _dockerfile_copy_sources()
    missing = sorted(root for root in _package_roots() if not _covered(root, sources))
    assert missing == [], (
        f"package roots declared in pyproject but not copied into the image: {missing}"
    )


def test_previously_missing_roots_are_now_present() -> None:
    sources = _dockerfile_copy_sources()
    for root in ("apps/commissioning", "apps/deployment", "apps/management"):
        assert _covered(root, sources), f"{root} must be copied into the image"


def test_project_is_installed_after_all_sources_are_copied() -> None:
    text = _DOCKERFILE.read_text(encoding="utf-8")
    install_index = text.find("uv pip install")
    assert install_index != -1, "the Dockerfile must install the project"
    for root in _package_roots():
        # every package root's COPY (or a covering ancestor's COPY) must precede the install
        covering = next(
            (
                text.find(f"COPY {source}")
                for source in _dockerfile_copy_sources()
                if root == source or root.startswith(source + "/")
            ),
            -1,
        )
        assert 0 <= covering < install_index, f"{root} must be copied before the install step"


def test_console_script_target_modules_live_in_a_copied_root() -> None:
    # scripts installed but whose target modules are absent from the image are exactly the failure
    # mode of secp-admission-proxy = secp_discovery_activation.proxy:main.
    scripts = _pyproject()["project"]["scripts"]
    sources = _dockerfile_copy_sources()
    import_to_root = {
        package.rsplit("/", 1)[1]: package.rsplit("/", 1)[0] for package in _wheel_packages()
    }
    for name, target in scripts.items():
        top_level = target.split(":", 1)[0].split(".", 1)[0]
        assert top_level in import_to_root, f"script {name} targets unknown package {top_level}"
        root = import_to_root[top_level]
        assert _covered(root, sources), (
            f"script {name} target {top_level} ({root}) not in the image"
        )


def test_importing_the_full_image_closure_preserves_the_runtime_seals() -> None:
    # importing the packages newly added to the image must not flip the runtime seals, change the
    # ordinary queue, start a Temporal worker, or activate the operator (imports stay inert).
    for name in (
        "secp_commissioning",
        "secp_operator_deployment",
        "secp_discovery_activation",
        "secp_management",
    ):
        importlib.import_module(name)
    from secp_discovery_activation.layout import ORDINARY_TASK_QUEUE
    from secp_worker.plan_gen import process_boundary
    from secp_worker.provisioning import activation, process_executor

    assert activation._B1A_SUBPROCESS_SEALED is True
    assert process_executor._B1A_SUBPROCESS_SEALED is True
    assert process_boundary._PLAN_ONLY_PROCESS_SEALED is False
    assert ORDINARY_TASK_QUEUE == "secp-orchestration"
