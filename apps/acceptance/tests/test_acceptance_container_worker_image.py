"""Container tier: OBSERVE that the pinned worker health interpreter exists in the real image.

``topology.WORKER_CONTAINER_INTERPRETER`` is the absolute ``argv[0]`` of the ordinary worker's
health command, and ``real_adapters`` runs that argv as ``<runtime> exec <ordinary container>
<argv>``. An absolute path gets no ``PATH`` lookup, so it must exist exactly as written INSIDE the
worker image.
Whether it does is a fact about an upstream image. No amount of reading this repository settles it.
This module looks.

WHY IT LIVES IN THE CONTAINER TIER
----------------------------------
``tests/test_health_command_interpreter.py`` binds the constant to the image's published BUILD
RECIPE — the ``FROM`` line plus a code-owned base-to-interpreter mapping — and says so plainly. Its
one actual observation of a running image is opt-in behind ``SECP_VERIFY_WORKER_IMAGE=1``, which is
the honest choice for a module that must run on a machine with no Docker.

The acceptance harness is the place where that excuse does not apply: the container tier exists
precisely because a real runtime is present. So the same observation runs here WITNESSED — if this
body does not execute, ``conftest.pytest_sessionfinish`` fails the session for a missing
``worker_image_probed`` witness, even when every collected test passed. That is the difference
between "we could observe this" and "we did".

WHY THE BASE IMAGE AND NOT THE FULL WORKER IMAGE
------------------------------------------------
The interpreter's location is established by the base and never changed afterwards: nothing in
``infra/dev/Dockerfile.python`` installs an apt ``python3`` or creates a ``/usr/bin`` symlink.
Probing the base settles the same question at a fraction of the cost — no repo upload, no dependency
resolution, no multi-minute build — and it still fails loudly if the upstream image ever changes.

The base is READ FROM the Dockerfile and the interpreter READ FROM the product constant. A pin
copied into this file would agree with itself after someone changed the real one, which is the
failure mode this whole harness keeps finding.

HISTORY, BECAUSE IT EXPLAINS THE SECOND ASSERTION
-------------------------------------------------
This module was written to discharge the antecedent of a FINDING: the health command then pinned
``/usr/bin/python3``, which ``python:*-slim`` does not provide, so the probe could not resolve, the
worker read as unhealthy, and the fail-closed queue probe manufactured a containment breach. That is
fixed — the constant now names ``/usr/local/bin/python3``. The absence of the OLD path is still
asserted below, because it is what makes the two interpreter constants genuinely different places
rather than two spellings of one, and a future "let us unify these" edit would reintroduce the exact
defect.
"""

from __future__ import annotations

import pathlib
import re

import pytest
from secp_acceptance import AcceptanceError
from secp_acceptance.shell import docker
from secp_acceptance.tier import require_container_runtime_or_refuse, witness

pytestmark = pytest.mark.container_tier

#: The HOST interpreter, pinned by ``BROKER_ENTRYPOINT`` for a systemd unit on the management host.
#: Correct there, absent here — the two must never be unified.
HOST_INTERPRETER = "/usr/bin/python3"


def _repo_root() -> pathlib.Path:
    here = pathlib.Path(__file__).resolve()
    for parent in here.parents:
        if (parent / "pyproject.toml").is_file() and (parent / "infra").is_dir():
            return parent
    raise AssertionError("repository root not found from the test file location")


def worker_base_image() -> str:
    """The base image the worker container is built FROM, read off the Dockerfile."""
    dockerfile = (_repo_root() / "infra" / "dev" / "Dockerfile.python").read_text(encoding="utf-8")
    match = re.search(r"^FROM\s+(\S+)", dockerfile, re.MULTILINE)
    assert match is not None, "no FROM line in infra/dev/Dockerfile.python"
    return match.group(1)


def pinned_interpreter() -> str:
    """The interpreter the PRODUCT pins for the worker container. Read, never restated."""
    from secp_management.topology import ORDINARY_HEALTH_COMMAND, WORKER_CONTAINER_INTERPRETER

    assert ORDINARY_HEALTH_COMMAND[0] == WORKER_CONTAINER_INTERPRETER, (
        "the health command no longer starts with the worker container interpreter constant; this "
        "probe would be measuring a path the product does not actually execute"
    )
    return WORKER_CONTAINER_INTERPRETER


@pytest.fixture(scope="module")
def base_image() -> str:
    """Prove the runtime, then make the base image locally available.

    REFUSES when Docker is absent — never skips. Without this the whole module would quietly prove
    nothing while rendering as a pass, which is the outcome the tier gate exists to prevent.
    """
    require_container_runtime_or_refuse()
    image = worker_base_image()
    if not docker("pull", image, timeout=900).ok:
        raise AcceptanceError("acceptance_host_image_build_failed")
    return image


def _path_is_executable_in(image: str, path: str) -> bool:
    """Is ``path`` an executable file inside a fresh container from ``image``?

    ``test -x`` in the image's own shell: exit 0 means present AND executable. Present-but-not-
    executable would fail the real ``docker exec`` just as surely as absent, so ``-x`` is the
    condition that matches what the product actually needs. No network, no mounts, nothing written;
    the container is removed on exit.
    """
    probe = docker("run", "--rm", "--network", "none", image, "test", "-x", path, timeout=300)
    return probe.ok


def test_the_probe_can_distinguish_present_from_absent(base_image: str):
    """CONTROL, and the reason every result below means anything.

    A probe that reported "absent" for everything — a broken argv, a shell that is not there, an
    image that will not start — would make the absence assertion unfalsifiable, and one that
    reported "present" for everything would make the presence assertion unfalsifiable. Establish
    both directions first, against paths whose status is certain.
    """
    assert _path_is_executable_in(base_image, "/bin/sh") is True
    assert _path_is_executable_in(base_image, "/definitely-not-a-real-path-9f3a") is False


def test_the_pinned_worker_interpreter_is_executable_in_the_worker_image(base_image: str):
    """THE observation. The path the product execs inside the worker container exists there.

    Witnesses ``worker_image_probed``: a declared container tier that never reached this line fails
    the session rather than reporting a green run that measured nothing.
    """
    interpreter = pinned_interpreter()
    present = _path_is_executable_in(base_image, interpreter)
    witness("worker_image_probed")
    assert present is True, (
        f"{interpreter} is not an executable file in {base_image}. The ordinary worker's health "
        f"command cannot resolve, so the worker reads as unhealthy and the fail-closed queue "
        f"containment probe manufactures a breach."
    )


def test_the_host_interpreter_is_absent_from_the_worker_image(base_image: str):
    """Why the two interpreter constants must stay different.

    ``BROKER_ENTRYPOINT`` pins ``/usr/bin/python3`` for a systemd unit on the management HOST, where
    it is correct. It is NOT correct here, and this is the measurement that says so: an edit that
    "unified" the two constants on the host's value would silently restore the original defect.
    """
    from secp_management.topology import BROKER_ENTRYPOINT

    assert BROKER_ENTRYPOINT[0] == HOST_INTERPRETER
    assert pinned_interpreter() != HOST_INTERPRETER
    assert _path_is_executable_in(base_image, HOST_INTERPRETER) is False, (
        f"{HOST_INTERPRETER} now exists in {base_image}. The two interpreter constants are no "
        f"longer distinguishable by observation, so the guard against unifying them is weaker "
        f"than it reads — re-derive it rather than deleting this assertion."
    )


def test_the_probed_image_is_the_one_the_dockerfile_declares(base_image: str):
    """Attribution. If this drifted from the Dockerfile, the measurements above would be about some
    other image and would say nothing about the worker."""
    assert base_image == worker_base_image()
    assert base_image.startswith("python:")
