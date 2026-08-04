"""The harness reaches the outside world through exactly one seam, and it has no verb for a
provider.

The prohibitions this harness operates under — no Proxmox contact, no OpenTofu/Terraform, no apply
or destroy of real infrastructure, no production credential, no trust-root change — are recorded as
booleans in every evidence document. A boolean a program writes about itself is worth exactly as
much as the structure behind it, so these tests check the structure.

Each is a claim about the SHAPE of the harness package, checked over the parsed AST. That is
deliberately narrow: it proves the harness cannot casually acquire a second process seam or reach
for a provider SDK, and it does NOT prove that some future body could not shell out through the one
legitimate seam to a provider CLI. The evidence document's prohibition booleans and this file
together are the guard; neither alone is.
"""

from __future__ import annotations

import ast
import pathlib

import pytest

#: The one module permitted to create a subprocess. Everything else must go through it, so there is
#: a single place where argv construction, timeouts, output bounds and output redaction are decided.
_SEAM_MODULE = "shell.py"

#: Import roots that would mean the harness had grown a way to talk to a provider or an
#: infrastructure-as-code engine directly.
_FORBIDDEN_IMPORT_ROOTS = frozenset(
    {
        "proxmoxer",
        "pyproxmox",
        "openstack",
        "boto3",
        "botocore",
        "azure",
        "google",
        "libvirt",
        "pyVmomi",
        "paramiko",
        "fabric",
        "python_terraform",
        "libtmux",
    }
)

#: Process-spawning entry points. ``subprocess`` is permitted only in the seam; the rest are
#: permitted nowhere, because each is a way to run a command that bypasses the seam's bounds.
_PROCESS_MODULES = frozenset({"subprocess", "multiprocessing", "pty", "asyncio"})
_PROCESS_CALLS = frozenset(
    {"system", "popen", "spawn", "spawnl", "spawnv", "execv", "execve", "execvp", "fork"}
)


def _package_root() -> pathlib.Path:
    return pathlib.Path(__file__).resolve().parents[1] / "secp_acceptance"


def _modules() -> dict[str, ast.Module]:
    root = _package_root()
    found = {
        path.name: ast.parse(path.read_text(encoding="utf-8"))
        for path in sorted(root.rglob("*.py"))
        if "__pycache__" not in path.parts
    }
    assert found, "no harness modules were read; the package layout moved"
    return found


def _imported_roots(tree: ast.Module) -> set[str]:
    roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            roots.add(node.module.split(".")[0])
    return roots


def _called_names(tree: ast.Module) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute):
                names.add(node.func.attr)
            elif isinstance(node.func, ast.Name):
                names.add(node.func.id)
    return names


# --------------------------------------------------------------------------- premise guard


def _git_tracked_harness_modules() -> set[str]:
    """The harness ``.py`` files GIT knows about — an INDEPENDENT second reading.

    Not another filesystem walk: git's index is maintained by a different tool, so a bug in
    :func:`_modules` cannot shrink both readings together.
    """
    import subprocess

    result = subprocess.run(  # noqa: S603,S607 - fixed argv, no user input, bounded
        ["git", "ls-files", "--", "apps/acceptance/secp_acceptance"],
        cwd=_package_root().parents[2],  # apps/acceptance/secp_acceptance -> repo root
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert result.returncode == 0, "git ls-files failed; cannot take the independent reading"
    return {
        line.strip().rsplit("/", 1)[-1]
        for line in result.stdout.splitlines()
        if line.strip().endswith(".py") and "__pycache__" not in line
    }


def test_the_module_sweep_reads_every_harness_module():
    """The sweep must cover the whole package EXACTLY, not merely clear a floor.

    This replaced ``len(modules) >= 6`` against a package of 7. A floor set at "one less than
    reality" lets exactly one module vanish from the sweep unnoticed — and the module most worth
    covering here is ``tier.py``, which must never import pytest. Every assertion in this file is a
    statement about "no module does X", so any module missing from the sweep is silently exempt
    from all of them.
    """
    swept = set(_modules())
    tracked = _git_tracked_harness_modules()
    assert tracked, "the independent reading found nothing; it is not a usable control"
    assert swept == tracked, (
        f"the module sweep and the git-tracked inventory disagree.\n"
        f"  tracked but not swept: {sorted(tracked - swept)}\n"
        f"  swept but not tracked: {sorted(swept - tracked)}\n"
        f"(a newly added harness module must be `git add`ed before this can see it)"
    )
    assert _SEAM_MODULE in swept
    # and the parser must actually see imports, or every assertion below is trivially satisfied
    assert _imported_roots(_modules()[_SEAM_MODULE])


# --------------------------------------------------------------------------- one seam


def test_only_the_seam_module_may_import_subprocess():
    offenders = {
        name: sorted(_imported_roots(tree) & _PROCESS_MODULES)
        for name, tree in _modules().items()
        if name != _SEAM_MODULE and (_imported_roots(tree) & _PROCESS_MODULES)
    }
    assert offenders == {}, (
        f"these modules can spawn a process without the seam's argv/timeout/output bounds: "
        f"{offenders}"
    )


def test_the_seam_module_does_import_subprocess():
    """CONTROL. Without this, deleting the seam entirely would make the test above pass."""
    assert "subprocess" in _imported_roots(_modules()[_SEAM_MODULE])


def test_no_module_uses_a_shell_or_an_exec_family_call():
    """``os.system``, ``os.popen`` and the ``exec*``/``spawn*`` families all run a command outside
    the seam, and the first two interpret a SHELL STRING — which is the one thing the harness must
    never build, since it composes arguments from real host output."""
    offenders = {
        name: sorted(_called_names(tree) & _PROCESS_CALLS)
        for name, tree in _modules().items()
        if _called_names(tree) & _PROCESS_CALLS
    }
    assert offenders == {}


def test_the_seam_never_enables_the_shell():
    """``shell=True`` anywhere in the seam would defeat the argv discipline everything else relies
    on. Checked as a keyword on the actual call, not as a substring of the file."""
    tree = _modules()[_SEAM_MODULE]
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        for keyword in node.keywords:
            if keyword.arg == "shell":
                assert isinstance(keyword.value, ast.Constant) and keyword.value.value is False


# --------------------------------------------------------------------------- no provider reach


@pytest.mark.parametrize("root", sorted(_FORBIDDEN_IMPORT_ROOTS))
def test_the_harness_cannot_import_a_provider_or_iac_client(root: str):
    """One test per client, so a new dependency names itself instead of failing a set diff."""
    offenders = [name for name, tree in _modules().items() if root in _imported_roots(tree)]
    assert offenders == [], (
        f"{root} is importable from {offenders}; the harness must not reach a provider"
    )


#: Executables the harness must never invoke. Matched against ARGV-SHAPED string literals only —
#: short, no whitespace — because prose that NAMES the prohibition is exactly what the harness's own
#: docstrings are supposed to do. "This module runs no OpenTofu" and ``run(("tofu", "apply"))`` are
#: opposite claims, and a substring search over every string constant cannot tell them apart.
_FORBIDDEN_EXECUTABLES = frozenset(
    {"terraform", "tofu", "opentofu", "pvesh", "qm", "pct", "ansible", "ansible-playbook"}
)


def _argv_shaped_literals(tree: ast.Module) -> set[str]:
    """String constants that could plausibly be a command or an argument.

    Bounded to short, whitespace-free strings. A docstring is neither, which is the distinction
    this whole test rests on.
    """
    return {
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and 0 < len(node.value) <= 32
        and not any(character.isspace() for character in node.value)
    }


def test_no_harness_module_can_invoke_an_iac_or_provider_executable():
    """The harness is not authorised to run OpenTofu/Terraform or to contact Proxmox, so no module
    carries one of those names in a position where it could become argv[0].

    Note what this does NOT claim: the harness's docstrings name these tools constantly, and must,
    because that is where the prohibitions are written down. The measurement is over argv-shaped
    literals only.
    """
    offenders = {
        name: sorted(_argv_shaped_literals(tree) & _FORBIDDEN_EXECUTABLES)
        for name, tree in _modules().items()
        if _argv_shaped_literals(tree) & _FORBIDDEN_EXECUTABLES
    }
    assert offenders == {}


def test_that_executable_check_can_actually_fail():
    """CONTROL. ``_argv_shaped_literals`` must find a short bare word and reject a docstring, or
    the assertion above is satisfied by a matcher that never matches anything."""
    tree = ast.parse('x = "tofu"\ny = "this module runs no tofu at all, ever, anywhere"\n')
    literals = _argv_shaped_literals(tree)
    assert "tofu" in literals
    assert literals & _FORBIDDEN_EXECUTABLES == {"tofu"}
    # the prose form must NOT be picked up
    assert not any(len(value) > 32 for value in literals)


def test_the_harness_does_invoke_the_container_runtime_it_is_supposed_to():
    """The other control. The forbidden-executable check would also pass on a harness that invokes
    nothing at all, which would mean the fleet module had stopped working."""
    assert "docker" in _argv_shaped_literals(_modules()["hosts.py"])
