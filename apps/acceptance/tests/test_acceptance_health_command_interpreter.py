"""ACCEPTANCE FINDING — the pinned worker health command names an interpreter the worker image
does not contain.

FINDING D — ``ORDINARY_HEALTH_COMMAND`` is unresolvable inside the real worker container
----------------------------------------------------------------------------------------
``topology.ORDINARY_HEALTH_COMMAND`` begins with the ABSOLUTE path ``/usr/bin/python3``. That argv
is not run on the host: ``LocalServiceStateAdapter._health`` runs it as
``<container-runtime> exec <ordinary container> <argv>``, and the product's own comment there says
"Run the EXACT pinned ordinary health contract INSIDE the container". So the path must resolve in
the WORKER IMAGE's filesystem.

The worker image is built from ``infra/dev/Dockerfile.python``, whose base is ``python:3.11-slim``.
The official ``python:*-slim`` images build CPython from source into ``/usr/local`` — so the
interpreter is ``/usr/local/bin/python3``, the Debian slim base carries no apt ``python3``, and
``/usr/bin/python3`` does not exist. ``docker exec`` with an absolute path does no ``PATH`` lookup,
so the probe fails with exit 126/127 rather than falling back.

WHY THAT IS NOT MERELY A FAILING HEALTH CHECK
---------------------------------------------
``_health``'s contract is "exit 0 is healthy; anything else is unhealthy", so a missing interpreter
is indistinguishable from a sick worker: ``ordinary_healthy`` is False, which makes the observation
not ``prepared``, which makes ``_worker_end_state_reason`` refuse. The same call also drives the
operator-queue containment probe (``_polls_operator_queue``), which is explicitly FAIL-CLOSED — it
returns True ("assume a breach") when the command errors. So this one wrong path both blocks the
install and manufactures a false queue-containment breach.

THE SHAPE OF THIS PROOF
-----------------------
The premise "``python:3.11-slim`` has no ``/usr/bin/python3``" is a fact about an upstream image,
not about this repo — exactly like Finding A's premise about systemd. So this file proves the
CONDITIONAL and the structural facts that make the conditional bite, and the ANTECEDENT is
discharged in the container tier by ``test_acceptance_container_worker_image.py``, which runs the
base image the Dockerfile declares and looks for the path.

Read that division precisely: **nothing in this file measures the antecedent**, and until the
container tier has actually run, Finding D is a proven conditional with an unmeasured premise. The
check id is ``worker_health_command_resolves_in_the_worker_image`` under ``worker_install``, and the
tier witnesses ``worker_image_probed``, so a declared tier that never probed the image fails rather
than passing quietly.

WHY CI IS GREEN
---------------
THREE fixtures agree with the wrong literal rather than testing it:

* ``apps/deployment/tests/_deploy_support.py`` pins ``HEALTH_ARGV`` to the same string;
* ``apps/deployment/tests/test_deployment_identities.py`` builds its mismatch case from the same
  string;
* decisively, ``apps/management/tests/test_management_real_adapters_root.py`` — the ONLY suite that
  drives the real observer against a real Docker daemon — runs the "ordinary worker" from
  ``busybox:latest`` and bind-mounts a fake shell script to ``/usr/bin/python3:ro``. It manufactures
  the exact path at the exact location the defect says is missing, and never uses the real worker
  image. A real-Docker test therefore cannot catch a real-image defect.
"""

from __future__ import annotations

import inspect
import pathlib
import re

import pytest

#: Where the official ``python:*-slim`` images actually put the interpreter.
_UPSTREAM_INTERPRETER = "/usr/local/bin/python3"


def _repo_root() -> pathlib.Path:
    here = pathlib.Path(__file__).resolve()
    for parent in here.parents:
        if (parent / "pyproject.toml").is_file() and (parent / "infra").is_dir():
            return parent
    raise AssertionError("repository root not found from the test file location")


def _read(relative: str) -> str:
    return (_repo_root() / relative).read_text(encoding="utf-8")


# --------------------------------------------------------------------------- the pinned argv


def test_the_health_command_names_an_absolute_interpreter():
    """The antecedent. An absolute argv[0] gets no ``PATH`` lookup, so the path must exist exactly
    as written; a bare ``python3`` would resolve wherever the image put it and there would be no
    finding here at all."""
    from secp_management.topology import ORDINARY_HEALTH_COMMAND

    assert ORDINARY_HEALTH_COMMAND[0] == "/usr/bin/python3"
    assert ORDINARY_HEALTH_COMMAND[0].startswith("/")
    assert ORDINARY_HEALTH_COMMAND[0] != _UPSTREAM_INTERPRETER


def test_finding_d_the_health_argv_is_resolved_inside_the_container_not_on_the_host():
    """The load-bearing structural fact. If this argv ran on the HOST it would be fine — a Debian/
    Ubuntu host does have ``/usr/bin/python3`` — and the finding would evaporate. It does not: the
    shipped adapter execs it inside the ordinary worker container."""
    from secp_operator_deployment.host_adapters import LocalServiceStateAdapter

    source = inspect.getsource(LocalServiceStateAdapter._health)
    assert '"exec", self.ordinary_container, *self.ordinary_health_command' in source
    assert "INSIDE the container" in source


def test_finding_d_the_queue_containment_probe_uses_the_same_interpreter_and_fails_closed():
    """The second blast radius. The operator-queue containment probe reuses the same argv[0] and
    conservatively reports a BREACH when the command errors — so an unresolvable interpreter does
    not merely look unhealthy, it manufactures a false ``worker_ordinary_polls_operator_queue``."""
    from secp_management.real_adapters import RealManagementHostObserver

    source = inspect.getsource(RealManagementHostObserver._polls_operator_queue)
    assert "*ORDINARY_HEALTH_COMMAND[:-1]" in source
    assert "fail closed" in source
    assert "return True" in source


# --------------------------------------------------------------------------- the worker image


def test_finding_d_the_worker_image_base_provides_a_different_interpreter_path():
    """The consequent's premise, read off the Dockerfile that builds the worker container."""
    dockerfile = _read("infra/dev/Dockerfile.python")
    base = re.search(r"^FROM\s+(\S+)", dockerfile, re.MULTILINE)
    assert base is not None
    assert base.group(1) == "python:3.11-slim", (
        "This finding is about where python:*-slim puts its interpreter. A different base makes "
        "the whole conditional a claim about something else and it must be re-derived."
    )
    # nothing in the image installs an apt python3 or creates the /usr/bin symlink the argv needs
    assert "/usr/bin/python3" not in dockerfile
    assert "apt-get install" not in dockerfile


def test_the_ordinary_worker_container_is_built_from_that_dockerfile():
    """Connect the pinned argv to that image. Without this, the paragraph above is about some
    unrelated image and proves nothing about the worker the installer actually runs."""
    compose = _read("infra/dev/docker-compose.yml")
    worker = compose.split("\n  worker:", 1)
    assert len(worker) == 2, "no `worker` service in the reviewed compose file"
    body = worker[1].split("\n  web:", 1)[0]
    assert "dockerfile: infra/dev/Dockerfile.python" in body


def test_the_images_own_commands_use_a_bare_interpreter_and_so_never_exercise_the_pin():
    """Why the image itself has never noticed. Every command the image and compose file run for
    themselves says bare ``python``, which resolves through ``PATH`` to ``/usr/local/bin/python``.
    Only the management observer's pinned probe hardcodes ``/usr/bin/python3``."""
    dockerfile = _read("infra/dev/Dockerfile.python")
    compose = _read("infra/dev/docker-compose.yml")
    assert 'CMD python -c "import urllib.request' in dockerfile
    assert '"CMD", "python", "-c", "import secp_worker;' in compose
    assert 'command: ["python", "-m", "secp_worker.main"]' in compose


# --------------------------------------------------------------------------- why nothing catches it


@pytest.mark.parametrize(
    ("relative", "needle"),
    [
        (
            "apps/deployment/tests/_deploy_support.py",
            'HEALTH_ARGV = ("/usr/bin/python3", "-m", "secp_worker.health", "check")',
        ),
        (
            "apps/deployment/tests/test_deployment_identities.py",
            'ordinary_health_command=["/usr/bin/python3", "-m", "x"]',
        ),
    ],
)
def test_the_existing_fixtures_restate_the_literal_rather_than_resolving_it(
    relative: str, needle: str
):
    """Two fixtures pin the same string the product pins. Agreement between a constant and a copy
    of that constant is not a test of the constant."""
    assert needle in _read(relative)


def test_the_only_real_docker_suite_manufactures_the_missing_path():
    """The decisive one.

    ``test_management_real_adapters_root.py`` is the one suite that puts the real observer in front
    of a real Docker daemon and a real systemd — the place this defect should surface. It runs the
    ordinary worker from ``busybox:latest`` and bind-mounts a fake ``python3`` shell script INTO the
    container at exactly ``/usr/bin/python3``. It therefore creates the very file whose absence is
    the defect, and it never loads the real worker image at all.
    """
    source = _read("apps/management/tests/test_management_real_adapters_root.py")
    assert 'f"{py3}:/usr/bin/python3:ro"' in source
    assert '_BASE_IMAGE = "busybox:latest"' in source
    assert "Dockerfile.python" not in source


def test_no_suite_anywhere_asserts_the_interpreter_exists_in_the_worker_image():
    """The negative space, measured rather than assumed.

    Every occurrence of the literal in the repo is either the product's own pin, a fixture that
    restates it, the bind-mount that manufactures it, or this acceptance package. None of them
    resolves it against the built worker image. Counted exactly: a new occurrence must be
    classified here rather than silently joining the pile.
    """
    root = _repo_root()
    occurrences: dict[str, int] = {}
    for path in sorted(root.glob("**/*.py")):
        rel = path.relative_to(root).as_posix()
        if "__pycache__" in rel or rel.startswith(".venv/"):
            continue
        count = path.read_text(encoding="utf-8").count("/usr/bin/python3")
        if count:
            occurrences[rel] = count

    product_pins = {
        "apps/management/secp_management/topology.py": 2,  # health command + broker entrypoint
    }
    fixtures_restating_it = {
        "apps/commissioning/tests/test_commissioning_locations.py": 1,
        "apps/deployment/tests/_deploy_support.py": 1,
        "apps/deployment/tests/test_deployment_identities.py": 1,
        "apps/management/tests/test_enrollment_signer_broker.py": 1,
        "apps/management/tests/test_management_real_adapters_root.py": 2,  # comment + bind-mount
        "tests/test_pr5h_signer_boundary_guards.py": 1,
    }
    accounted = {**product_pins, **fixtures_restating_it}

    # The positive control runs FIRST, deliberately. The assertion below succeeds on ABSENCE, so a
    # sweep that silently read nothing would satisfy it vacuously. Requiring these seven files to be
    # present with these exact counts means a broken or shrunken sweep fails HERE, naming the real
    # cause, instead of passing the negative check and failing later with a confusing message.
    for rel, expected in accounted.items():
        assert occurrences.get(rel) == expected, (
            f"{rel} now has {occurrences.get(rel)} references, expected {expected}. If this is "
            f"None, the sweep did not read the file at all and the absence check below would have "
            f"been vacuous."
        )

    unaccounted = {
        rel: n
        for rel, n in occurrences.items()
        if rel not in accounted and not rel.startswith("apps/acceptance/")
    }
    assert unaccounted == {}, (
        "A new reference to the pinned interpreter path appeared. Classify it: does it RESOLVE "
        "the path against the real worker image (which would close Finding D), or does it restate "
        f"the literal (which does not)?  {unaccounted}"
    )


def test_the_broker_entrypoint_shares_the_literal_but_not_the_finding():
    """The boundary of this finding, stated so it is not read wider than it was measured.

    ``BROKER_ENTRYPOINT`` begins with the same ``/usr/bin/python3``, but it is an ``ExecStart=`` in
    a systemd unit that runs on the controller HOST, not in a container. A Debian/Ubuntu host does
    provide ``/usr/bin/python3``, so the same literal is defensible there. Finding D is about the
    CONTAINER-executed health command only. (Whether the host interpreter can import
    ``secp_management`` is a separate question the controller stage measures.)
    """
    from secp_management.controller_compose_contract import render_broker_reviewed_unit
    from secp_management.topology import BROKER_ENTRYPOINT

    assert BROKER_ENTRYPOINT[0] == "/usr/bin/python3"
    # Read it off the RENDERED unit rather than the renderer's source: the question is where the
    # interpreter is resolved, and the unit text is what systemd on the host actually executes.
    unit = render_broker_reviewed_unit().content.decode("utf-8")
    assert "ExecStart=" + " ".join(BROKER_ENTRYPOINT) in unit
    assert "[Service]" in unit  # a host systemd unit...
    assert "docker" not in unit and "podman" not in unit  # ...with no container runtime in sight
