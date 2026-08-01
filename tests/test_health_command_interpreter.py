"""The ordinary worker's health interpreter must match the IMAGE that executes it.

WHAT WAS OPEN, AND HOW IT WAS MEASURED
--------------------------------------
``ORDINARY_HEALTH_COMMAND`` pinned ``/usr/bin/python3``. It is executed with
``docker exec <ordinary container> <argv>`` (``real_adapters.py``), so the interpreter has to exist
inside the worker image, which ``infra/dev/Dockerfile.python`` builds ``FROM python:3.11-slim``.

Two further sites carried the same string — the deployment profile fixture and a negative fixture —
and neither CHECKED it. They RESTATED it. Measured before this guard existed: changing the constant
from ``/usr/bin/python3`` to ``/usr/local/bin/python3`` and running
``apps/management/tests apps/deployment/tests tests`` produced **2905 passed, 0 failed**. The
interpreter could have been any string at all and the suite stayed green. Redundancy that is
incidental rather than structural is not coverage, and that measurement is what proves it here
rather than asserting it.

A THIRD agreeing site is why real-Docker CI was green: ``test_management_real_adapters_root.py``
drives the real observer against a real daemon, but from a ``busybox`` base with a fake interpreter
BIND-MOUNTED in. The only suite with the authority to catch this manufactured the very precondition
whose absence is the defect, and never loaded the real worker image. See
:func:`test_the_root_fixture_cannot_vouch_for_a_path_the_code_no_longer_names`.

WHY THIS IS SECURITY-RELEVANT, NOT COSMETIC
-------------------------------------------
The same argv drives ``real_adapters._polls_operator_queue``, which is FAIL-CLOSED: it returns
``True`` — "assume a breach" — on any exec error. An unresolvable interpreter therefore does not
merely block an install; it MANUFACTURES a false operator-queue containment breach, i.e. a false
report against the exact isolation property this program exists to guarantee. The blast radius is a
security signal, not a failed health check.

THE LIMIT OF THIS GUARD, STATED PLAINLY
---------------------------------------
The default gate binds the constant to the image's published BUILD RECIPE — the ``FROM`` line plus
a code-owned mapping from base image to interpreter prefix. It does **NOT** observe a running
image. Docker was unavailable when this was written, so the claim "``python:3.11-slim`` has no
``/usr/bin/python3``" rests on the official ``docker-library/python`` Dockerfile (Python's default
``configure`` prefix is ``/usr/local``, and the image symlinks only within ``/usr/local/bin``) and
NOT on an observation of the built image. :func:`test_the_running_image_provides_the_interpreter`
is the observation, and it is opt-in via ``SECP_VERIFY_WORKER_IMAGE=1`` rather than a silent skip,
because a skipped test reads as a passing one in a corpus count.

What the default gate *does* guarantee is the part that actually rots: the constant can no longer
drift from the base image silently. Change the ``FROM`` line to something whose interpreter lives
elsewhere and this fails loudly.

WHAT IS DELIBERATELY OUT OF SCOPE
--------------------------------
``BROKER_ENTRYPOINT`` runs on the management HOST under systemd, where ``/usr/bin/python3`` is
correct, and it is NOT changed. It held the same literal as the container's for unrelated reasons —
it shares the absolute-interpreter CONVENTION, not the defect. "Fixing" it for consistency would
have broken working, security-sensitive code, so the boundary is pinned as its own assertion in
:func:`test_the_broker_entrypoint_is_out_of_scope_and_stays_unchanged` and the finding cannot be
read wider than it was measured.
"""

from __future__ import annotations

import ast
import os
import pathlib
import re
import shutil
import subprocess

import pytest
from secp_management.topology import (
    BROKER_ENTRYPOINT,
    ORDINARY_HEALTH_COMMAND,
    WORKER_CONTAINER_INTERPRETER,
)

REPO = pathlib.Path(__file__).resolve().parents[1]
WORKER_DOCKERFILE = REPO / "infra" / "dev" / "Dockerfile.python"

#: Base image -> the absolute interpreter that image provides. Deliberately CLOSED: an unrecognised
#: base fails rather than defaults, because the whole failure being closed here is "nobody checked
#: which interpreter the image actually ships".
_INTERPRETER_BY_BASE = {
    # Official python images build CPython from source with the default ``configure`` prefix
    # (/usr/local) and symlink only inside /usr/local/bin. The slim Debian base ships no system
    # interpreter, so /usr/bin/python3 does not exist.
    "python": "/usr/local/bin/python3",
    # Distro bases carry a package-managed interpreter at the FHS location instead.
    "debian": "/usr/bin/python3",
    "ubuntu": "/usr/bin/python3",
}

_FROM = re.compile(r"^\s*FROM\s+(?P<ref>\S+)", re.MULTILINE | re.IGNORECASE)


def _worker_base_image() -> str:
    """The FIRST ``FROM`` in the worker Dockerfile — the base whose filesystem the argv runs on."""
    text = WORKER_DOCKERFILE.read_text(encoding="utf-8")
    matches = _FROM.findall(text)
    assert matches, f"{WORKER_DOCKERFILE} declares no FROM"
    return matches[0]


def _expected_interpreter(image_ref: str) -> str:
    repository = image_ref.split(":", 1)[0]
    assert repository in _INTERPRETER_BY_BASE, (
        f"{WORKER_DOCKERFILE} builds FROM {image_ref!r}, whose interpreter location is not "
        "registered. Add it to _INTERPRETER_BY_BASE after CHECKING which interpreter that image "
        "actually provides — do not guess, and do not assume it matches the previous base."
    )
    return _INTERPRETER_BY_BASE[repository]


# ------------------------------------------------------------------ the load-bearing binding


def test_the_health_interpreter_matches_the_image_that_executes_it() -> None:
    """The constant is derived from the Dockerfile's base, not asserted to be a fixed string.

    Written as a comparison against the base image so that changing ``FROM`` changes what this
    test demands. Asserting ``== "/usr/local/bin/python3"`` would be a second copy of the value and
    would keep passing after a base-image change that invalidated it.
    """
    base = _worker_base_image()
    assert WORKER_CONTAINER_INTERPRETER == _expected_interpreter(base), (
        f"the worker image is built FROM {base!r}, which provides "
        f"{_expected_interpreter(base)!r}, but the health command runs "
        f"{WORKER_CONTAINER_INTERPRETER!r}"
    )
    assert ORDINARY_HEALTH_COMMAND[0] == WORKER_CONTAINER_INTERPRETER


def test_the_health_command_really_is_executed_inside_that_container() -> None:
    """The binding above is only meaningful if the argv runs in the image, not on the host.

    Keyed on the CONTENT of the call — an ``exec`` tuple naming the ordinary container and
    splatting the health argv — rather than on a symbol name, which a comment would satisfy.
    """
    source = (REPO / "apps" / "management" / "secp_management" / "real_adapters.py").read_text(
        encoding="utf-8"
    )
    tree = ast.parse(source)

    def is_container_exec(node: ast.AST) -> bool:
        if not isinstance(node, ast.Tuple) or not node.elts:
            return False
        first = node.elts[0]
        if not (isinstance(first, ast.Constant) and first.value == "exec"):
            return False
        names = {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}
        return {"ORDINARY_CONTAINER_NAME", "ORDINARY_HEALTH_COMMAND"} <= names

    assert any(is_container_exec(n) for n in ast.walk(tree)), (
        "no `('exec', ORDINARY_CONTAINER_NAME, *ORDINARY_HEALTH_COMMAND...)` call remains; the "
        "health argv may no longer run inside the container, which would change which filesystem "
        "the interpreter must exist on"
    )


def test_the_deployment_profile_fixture_agrees_with_the_code_constant() -> None:
    """Close the "restate rather than check" gap that made the original defect invisible.

    ``_deploy_support.HEALTH_ARGV`` is what a VALID profile carries. It used to be an independent
    copy that agreed by coincidence; now a disagreement is a failure.
    """
    import sys

    deploy_tests = REPO / "apps" / "deployment" / "tests"
    sys.path.insert(0, str(deploy_tests))
    try:
        from _deploy_support import HEALTH_ARGV
    finally:
        sys.path.remove(str(deploy_tests))

    assert HEALTH_ARGV[0] == WORKER_CONTAINER_INTERPRETER
    assert tuple(HEALTH_ARGV) == tuple(ORDINARY_HEALTH_COMMAND)


# ------------------------------------------------------- the host interpreter is a DIFFERENT thing


def test_the_broker_entrypoint_is_out_of_scope_and_stays_unchanged() -> None:
    """``BROKER_ENTRYPOINT`` is CORRECT code and is deliberately NOT part of this fix.

    It is an ``ExecStart=`` in a host systemd unit, and a Debian/Ubuntu host does provide
    ``/usr/bin/python3``. It shares the container argv's absolute-interpreter CONVENTION, not its
    defect. Pinned here so the finding cannot later be read wider than it was measured — a change
    that "consistently" moved this one to the container's interpreter would break a working,
    security-sensitive host entrypoint, which is the failure direction nobody re-checks.

    NOTE: the acceptance stream also pins this boundary. One of the two should ship; see the PR
    body for which.
    """
    assert BROKER_ENTRYPOINT[0] == "/usr/bin/python3"
    assert BROKER_ENTRYPOINT[0] != WORKER_CONTAINER_INTERPRETER


def test_both_interpreters_are_absolute_so_neither_is_resolved_from_path() -> None:
    """A relative executable is resolved through the inherited PATH, which is hijackable.

    ``profile.py::_v_health`` enforces this for the profile; asserted here for the code constants
    so the property holds on both sides of that boundary.
    """
    for interpreter in (WORKER_CONTAINER_INTERPRETER, BROKER_ENTRYPOINT[0]):
        assert interpreter.startswith("/"), interpreter
        assert "//" not in interpreter and ".." not in interpreter


def test_the_root_fixture_cannot_vouch_for_a_path_the_code_no_longer_names() -> None:
    """The one suite with the authority to catch this MANUFACTURES the precondition.

    ``test_management_real_adapters_root.py`` runs the real observer against a real Docker daemon,
    but it builds the container from ``busybox`` and bind-mounts a fake interpreter INTO it — it
    never loads the real worker image. So it proves exec mechanics and can never be evidence that
    the shipped image provides the path.

    That fixture is root-gated (``skipif``) and therefore invisible to every local run, while its
    CI job fails closed on any skip. A mount left at a literal ``/usr/bin/python3`` would have gone
    red in root CI only. Keyed on the mount expression's CONTENT so a comment mentioning the
    constant cannot satisfy it.
    """
    source = (
        REPO / "apps" / "management" / "tests" / "test_management_real_adapters_root.py"
    ).read_text(encoding="utf-8")
    assert "{py3}:{WORKER_CONTAINER_INTERPRETER}:ro" in source, (
        "the root fixture no longer binds its bind-mount to WORKER_CONTAINER_INTERPRETER; it can "
        "again vouch for an interpreter path the code does not name"
    )
    assert ":/usr/bin/python3:ro" not in source, (
        "the root fixture mounts a hardcoded /usr/bin/python3 again"
    )


# --------------------------------------------------------------------------- discriminating power


def test_the_binding_would_catch_a_base_image_change() -> None:
    """Prove the guard's power instead of asserting it.

    A base whose interpreter lives elsewhere must demand a different constant; an unregistered base
    must REFUSE rather than fall through to a default. Without this, "the interpreter matches the
    image" would also be the reading produced by a mapping that returned one value for everything.
    """
    assert _expected_interpreter("python:3.11-slim") == "/usr/local/bin/python3"
    assert _expected_interpreter("debian:bookworm-slim") == "/usr/bin/python3"
    # The two really are different, so the mapping distinguishes rather than agrees with itself.
    assert _expected_interpreter("python:3.11-slim") != _expected_interpreter("debian:bookworm")

    with pytest.raises(AssertionError, match="not registered"):
        _expected_interpreter("some-unreviewed-base:latest")


def test_the_dockerfile_is_actually_read() -> None:
    """Non-vacuity: a missing or unparsed Dockerfile would make the binding silently trivial."""
    assert WORKER_DOCKERFILE.is_file(), WORKER_DOCKERFILE
    base = _worker_base_image()
    assert base.startswith("python:"), (
        f"the worker base image is now {base!r}; confirm which interpreter it provides and update "
        "_INTERPRETER_BY_BASE and WORKER_CONTAINER_INTERPRETER together"
    )


# ------------------------------------------------------------- the observation, opt-in and loud


@pytest.mark.skipif(
    os.environ.get("SECP_VERIFY_WORKER_IMAGE") != "1",
    reason=(
        "opt-in: set SECP_VERIFY_WORKER_IMAGE=1 with a working Docker daemon to OBSERVE the "
        "interpreter inside the real base image. The rest of this module binds to the build "
        "recipe only and does NOT observe a running image."
    ),
)
def test_the_running_image_provides_the_interpreter() -> None:
    """The measurement the default gate cannot make: does the path exist in the actual image?"""
    assert shutil.which("docker"), "SECP_VERIFY_WORKER_IMAGE=1 was set but docker is not on PATH"
    base = _worker_base_image()
    probe = subprocess.run(  # noqa: S603
        ["docker", "run", "--rm", base, "test", "-x", WORKER_CONTAINER_INTERPRETER],
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert probe.returncode == 0, (
        f"{base} does not provide an executable {WORKER_CONTAINER_INTERPRETER}: "
        f"{probe.stderr.strip()}"
    )
    # Non-vacuity: the same probe must FAIL for a path the image does not have, otherwise a
    # `docker run` that silently succeeded on everything would read as proof.
    absent = subprocess.run(  # noqa: S603
        ["docker", "run", "--rm", base, "test", "-x", "/usr/bin/definitely-not-here"],
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert absent.returncode != 0, "the probe reports success for a path that cannot exist"
