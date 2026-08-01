"""Container tier: discharge Finding D's antecedent against a real image.

``test_acceptance_health_command_interpreter.py`` proves the CONDITIONAL hermetically — if the
worker image has no ``/usr/bin/python3``, the pinned health command cannot resolve, the worker reads
as unhealthy, and the fail-closed queue probe manufactures a containment breach. The premise it
rests on ("``python:3.11-slim`` puts the interpreter at ``/usr/local/bin/python3`` and provides no
``/usr/bin/python3``") is a fact about an upstream image. No amount of reading this repository
settles it. This module looks.

WHY THE BASE IMAGE AND NOT THE FULL WORKER IMAGE
------------------------------------------------
The interpreter's location is established by the base and never changed afterwards: nothing in
``infra/dev/Dockerfile.python`` installs an apt ``python3`` or creates a ``/usr/bin`` symlink, which
the hermetic file asserts separately. Probing the base therefore settles the same question at a
fraction of the cost — no repo upload, no dependency resolution, no multi-minute build — and it
still fails loudly if the upstream image ever changes.

The base is READ FROM the Dockerfile rather than restated here. A pin copied into this file would
agree with itself after someone changed the real one, which is the failure mode this whole harness
keeps finding.
"""

from __future__ import annotations

import pathlib
import re

import pytest
from secp_acceptance import AcceptanceError
from secp_acceptance.shell import docker
from secp_acceptance.tier import require_container_runtime_or_refuse, witness

pytestmark = pytest.mark.container_tier

#: Where the official ``python:*-slim`` images actually place the interpreter.
UPSTREAM_INTERPRETER = "/usr/local/bin/python3"
#: What ``topology.ORDINARY_HEALTH_COMMAND`` pins as ``argv[0]``.
PINNED_INTERPRETER = "/usr/bin/python3"


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


def _path_exists_in(image: str, path: str) -> bool:
    """Does ``path`` exist inside a fresh container from ``image``?

    ``test -e`` in the image's own shell: exit 0 means present. No network, no mounts, nothing
    written; the container is removed on exit.
    """
    probe = docker("run", "--rm", "--network", "none", image, "test", "-e", path, timeout=300)
    return probe.ok


def test_the_probe_can_distinguish_present_from_absent(base_image: str):
    """CONTROL, and the reason a later "absent" result means anything.

    A probe that reported "absent" for everything — a broken argv, a shell that is not there, an
    image that will not start — would make the finding below unfalsifiable. Establish first that it
    says PRESENT for a path that certainly exists, and ABSENT for one that certainly does not.
    """
    assert _path_exists_in(base_image, "/") is True
    assert _path_exists_in(base_image, "/definitely-not-a-real-path-9f3a") is False


def test_finding_d_antecedent_the_pinned_interpreter_is_absent_from_the_worker_image(
    base_image: str,
):
    """FINDING D's antecedent, measured.

    The hermetic file proves that IF this path is missing THEN the health command cannot resolve
    and the queue-containment probe fails closed. This is the IF.
    """
    present = _path_exists_in(base_image, PINNED_INTERPRETER)
    witness("worker_image_probed")
    assert present is False, (
        f"{PINNED_INTERPRETER} now exists in {base_image}. Finding D's antecedent no longer holds "
        f"and the finding should be re-derived rather than assumed — the upstream image changed."
    )


def test_the_interpreter_is_present_at_the_upstream_location(base_image: str):
    """The other half. The image does ship a python3 — just not where the pin looks.

    Without this the absence above would be consistent with "there is no interpreter at all", which
    would be a different and much larger problem, and would make the suggested fix wrong.
    """
    assert _path_exists_in(base_image, UPSTREAM_INTERPRETER) is True


def test_the_probed_image_is_the_one_the_dockerfile_declares(base_image: str):
    """Attribution. If this drifted from the Dockerfile, the measurement above would be about some
    other image and would say nothing about the worker."""
    assert base_image == worker_base_image()
    assert base_image.startswith("python:")
