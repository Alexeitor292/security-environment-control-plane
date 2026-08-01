"""ACCEPTANCE FINDINGS — the production worker end-state gate cannot be satisfied.

Two independent defects, both found while building the two-host acceptance harness and both
provable without a container, so they live here as executable proofs rather than as paragraphs in
a PR body. Either one alone makes the supported production worker installation path unable to
succeed; they are recorded separately because fixing one does not fix the other.

The gate in question is ``engine._worker_end_state_reason``. It is the reobservation gate for
``secpctl bootstrap worker --write --confirm``, the precondition for ``adopt``, and the predicate
behind ``secpctl status worker``. Its expectations come from ``_expected_worker(manifest)``; its
observation comes from ``deps.observer.observe_worker()``, which ``production.py`` wires to
``RealManagementHostObserver``.

FINDING A — ``worker_generation_marker_invalid``
------------------------------------------------
``_worker_generation_complete`` requires a non-empty operator ``InvocationID``::

    if obs.operator_present and not obs.operator_invocation_id:
        return False

systemd assigns an ``InvocationID`` when a unit is STARTED. The reviewed operator unit is installed
present, disabled and stopped and is *never started* — that is the security property the whole
worker installation is built around, and the product says so in three places (the runbook's "ships
the operator unit present, disabled and stopped", ``install_operator_unit_disabled``'s "NEVER
systemctl enable/start", and the observer's own regex comment ``# 128-bit systemd invocation id
(empty when never run)``). So on a correctly prepared host the field is empty, the generation tuple
is judged incomplete, and the gate refuses before it looks at anything else.

The premise "a never-started unit reports an empty InvocationID" is a fact about systemd, not about
this repo, so the test below proves the CONDITIONAL and the harness measures the antecedent on a
real host (``worker_operator_unit_present_disabled_stopped`` records the observed value).

FINDING B — ``worker_operator_image_mismatch``
----------------------------------------------
``_expected_worker`` derives ``operator_image`` from the signed manifest, so it is always a
non-empty ``sha256:...``. ``RealManagementHostObserver.observe_worker`` passes the literal empty
string for ``operator_image_digest``, commented "the prepared operator is stopped; no running
image" — which is true, and is exactly why the equality can never hold. Even with Finding A
repaired, the gate still refuses here.

WHY CI IS GREEN ON BOTH
-----------------------
The engine suites drive ``FakeObserver``, which reports ``w.operator_invocation_id`` (a fixture
constant, ``"a" * 32``) and ``w.operator_image_digest`` (which ``FakeWorkerAdapter`` sets to the
signed operator image). The fake disagrees with the production leaf on exactly these two fields.
The one suite that drives the REAL observer against real Docker and real systemd
(``test_management_real_adapters_root.py``) asserts observer FIELDS and never calls
``_worker_end_state_reason``, so no existing test puts the real observation in front of the real
gate. This file is that test.
"""

from __future__ import annotations

import dataclasses

import pytest
from secp_commissioning.canonical import sha256_bytes

_ORDINARY_IMAGE = sha256_bytes(b"acceptance/worker-ordinary")
_OPERATOR_IMAGE = sha256_bytes(b"acceptance/worker-operator")
_CONTAINER_ID = "b3" + "0" * 62
_STARTED_AT = "2026-01-02T03:04:05.000000000Z"
_PID = "4242"
_RESTART = "0"
#: A systemd invocation id for a unit that HAS been started. Used only to step past Finding A so
#: Finding B can be shown to be independent of it.
_STARTED_INVOCATION = "9f" * 16

_COMPOSE_BODY = b"# acceptance worker compose\n"
_UNIT_BODY = b"[Unit]\nDescription=acceptance operator unit\n"
_PACKAGE_BODY = b"acceptance deployment package\n"


class _Result:
    def __init__(self, exit_code: int, stdout: str) -> None:
        self.exit_code = exit_code
        self.stdout = stdout
        self.stderr = ""


class _PreparedHostRunner:
    """Answers every command the real observer issues the way a correctly prepared host would.

    ``operator_invocation_id`` is a parameter so the same runner can model both the real posture
    (never started -> empty) and the counterfactual (started once -> 32 hex), which is what makes
    the two findings separable.
    """

    def __init__(self, *, invocation_id: str) -> None:
        self._invocation = invocation_id

    def run(self, pin, argv, *, timeout_seconds, max_output_bytes):  # noqa: ANN001, ANN003
        if argv[0] == "show":
            return _Result(
                0,
                "LoadState=loaded\n"
                "ActiveState=inactive\n"
                "UnitFileState=static\n"
                f"InvocationID={self._invocation}\n"
                "StateChangeTimestampMonotonic=123456\n",
            )
        if argv[0] == "inspect" and "{{.Image}}" in argv:
            return _Result(0, _ORDINARY_IMAGE + "\n")
        if argv[0] == "inspect":
            return _Result(
                0,
                f"{_CONTAINER_ID} true {_RESTART} {_STARTED_AT} 0001-01-01T00:00:00Z {_PID}\n",
            )
        if argv[0] == "exec" and argv[-1] == "queues":
            return _Result(0, "secp-orchestration\n")
        if argv[0] == "exec":
            return _Result(0, "")  # the pinned health contract passes
        if argv[0] == "version":
            return _Result(0, "29.0.0\n")
        return _Result(1, "")


class _PreparedFilesystem:
    """Returns the exact installed-document bytes a prepared worker host carries."""

    def __init__(self, paths: dict[str, bytes]) -> None:
        self._paths = paths

    def safe_read(self, path: str, *, max_bytes: int, expected_uid: int) -> bytes:
        if path not in self._paths:
            raise FileNotFoundError(path)
        return self._paths[path]


def _pin(path: str):  # noqa: ANN202
    from secp_operator_deployment.pinned_exec import ExecutablePin

    return ExecutablePin(path, "sha256:" + "a" * 64)


def _observe(*, invocation_id: str):  # noqa: ANN202
    """Drive the REAL production observer over a prepared host and return its observation."""
    from secp_management.layout import ManagementLocations
    from secp_management.real_adapters import (
        PinnedExecutables,
        RealAdapterContext,
        RealManagementHostObserver,
    )

    locations = ManagementLocations()
    ctx = RealAdapterContext(
        locations=locations,
        fs=_PreparedFilesystem(  # type: ignore[arg-type]
            {
                locations.worker_compose_path(): _COMPOSE_BODY,
                locations.operator_unit_path(): _UNIT_BODY,
                locations.worker_deployment_package_path(): _PACKAGE_BODY,
            }
        ),
        runner=_PreparedHostRunner(invocation_id=invocation_id),  # type: ignore[arg-type]
        executables=PinnedExecutables(
            container_runtime=_pin("/usr/bin/docker"),
            compose_runtime=_pin("/usr/local/bin/docker-compose"),
            service_manager=_pin("/usr/bin/systemctl"),
        ),
    )
    return RealManagementHostObserver(ctx).observe_worker()


def _expected_for(observation):  # noqa: ANN001, ANN202
    from secp_management.engine import _ExpectedWorker
    from secp_management.evidence import health_command_identity
    from secp_management.topology import ORDINARY_HEALTH_COMMAND

    return _ExpectedWorker(
        ordinary_image=_ORDINARY_IMAGE,
        operator_image=_OPERATOR_IMAGE,
        ordinary_config_identity=observation.ordinary_config_identity,
        operator_unit_identity=observation.operator_unit_identity,
        health_command_identity=health_command_identity(ORDINARY_HEALTH_COMMAND),
        deployment_aggregate=observation.deployment_package_aggregate,
    )


def _with_invocation(observation, invocation_id: str):  # noqa: ANN001, ANN202
    """Replace the operator invocation id AND re-derive the generation marker.

    The marker is a digest over the whole generation tuple, so changing a component without
    re-deriving it would fail the marker-equality check for a second, unrelated reason and make the
    next assertion unattributable.
    """
    from secp_management.adapters import worker_generation_marker

    return dataclasses.replace(
        observation,
        operator_invocation_id=invocation_id,
        generation_marker=worker_generation_marker(
            container_id=observation.ordinary_container_id,
            running_pid=observation.ordinary_pid,
            restart_count=observation.ordinary_restart_count,
            started_at=observation.ordinary_started_at,
            operator_invocation_id=invocation_id,
        ),
    )


@pytest.fixture()
def never_started():  # noqa: ANN201
    """The real posture: the operator unit is present, disabled, stopped, and NEVER started."""
    return _observe(invocation_id="")


# --------------------------------------------------------------------------- premise guard


def test_the_prepared_host_fixture_is_not_degenerate(never_started):
    """If this fixture did not model a correctly prepared host, both findings below would be about
    a broken fixture rather than about the product."""
    assert never_started.coherent is True
    assert never_started.ordinary_present is True
    assert never_started.ordinary_running is True
    assert never_started.ordinary_healthy is True
    assert never_started.ordinary_image_digest == _ORDINARY_IMAGE
    assert never_started.operator_present is True
    assert never_started.operator_enabled is False
    assert never_started.operator_running is False
    assert never_started.ordinary_polls_operator_queue is False
    assert never_started.package_trusted is True
    # the observer's OWN composed verdict: this host IS prepared and sealed-prepared
    assert never_started.commissioning_status == "prepared"
    assert never_started.deployment_status == "sealed_prepared"


# --------------------------------------------------------------------------- finding A


def test_a_never_started_operator_unit_reports_no_invocation_id(never_started):
    """The antecedent, as the observer reports it."""
    assert never_started.operator_invocation_id == ""


def test_finding_a_the_gate_refuses_a_never_started_operator(never_started):
    """FINDING A. A correctly prepared host — operator present, disabled, never started — is
    refused ``worker_generation_marker_invalid``."""
    from secp_management.engine import _worker_end_state_reason

    assert (
        _worker_end_state_reason(never_started, _expected_for(never_started))
        == "worker_generation_marker_invalid"
    )


def test_finding_a_control_only_the_invocation_id_causes_that_refusal(never_started):
    """CONTROL for Finding A. With every other field byte-identical, supplying an invocation id
    moves the refusal PAST the generation check — so the generation refusal is attributable to that
    field alone and not to some other incompleteness in the fixture."""
    from secp_management.engine import _worker_end_state_reason

    started = _with_invocation(never_started, _STARTED_INVOCATION)
    reason = _worker_end_state_reason(started, _expected_for(started))
    assert reason != "worker_generation_marker_invalid"


# --------------------------------------------------------------------------- finding B


def test_the_production_observer_never_reports_an_operator_image(never_started):
    """The loaded-object fact behind Finding B: for a correctly prepared host, the SHIPPED observer
    reports the empty string for the operator image."""
    assert never_started.operator_image_digest == ""


def test_finding_b_survives_finding_a(never_started):
    """FINDING B, shown to be INDEPENDENT of Finding A.

    Step past the generation check by supplying an invocation id, and the very next thing the gate
    refuses is the operator image — so repairing Finding A alone would not make the production
    install path succeed.
    """
    from secp_management.engine import _worker_end_state_reason

    started = _with_invocation(never_started, _STARTED_INVOCATION)
    assert (
        _worker_end_state_reason(started, _expected_for(started))
        == "worker_operator_image_mismatch"
    )


def test_finding_b_control_only_the_operator_image_field_causes_that_refusal(never_started):
    """CONTROL for Finding B, and the proof that these are the ONLY two blockers in this fixture.

    With the invocation id supplied AND the operator image supplied, the same gate over the same
    observation returns ``None`` — the complete canonical prepared end state. Every other field the
    gate checks was already satisfied by the real observer's own output.
    """
    from secp_management.engine import _worker_end_state_reason

    started = _with_invocation(never_started, _STARTED_INVOCATION)
    repaired = dataclasses.replace(started, operator_image_digest=_OPERATOR_IMAGE)
    assert _worker_end_state_reason(repaired, _expected_for(repaired)) is None


def test_the_signed_operator_image_is_never_the_empty_string():
    """The other half of Finding B: no valid worker bundle can make the comparison succeed by
    supplying ``""`` — the release schema requires an image archive to carry a real digest."""
    from secp_management.release_bundle import (
        WORKER_OPERATOR_PURPOSE,
        ReleaseManifest,
        signed_worker_image,
    )

    manifest = ReleaseManifest.model_validate(
        {
            "bootstrap_contract_version": "secp.bootstrap/v1alpha1",
            "plane": "management",
            "role": "worker",
            "release_version": "0.0.1",
            "source_sha": "a" * 40,
            "source_tree_sha": "b" * 40,
            "parent_sha": None,
            "migration_identity": "c4e2f9a1b7d3",
            "implementation_aggregate": "sha256:" + "1" * 64,
            "bootstrap_package_identity": "secp-pr5e/management-bootstrap/v1",
            "signing_anchor_id": "secp-acceptance-anchor/v1",
            "artifacts": [
                {
                    "name": "images/operator.tar",
                    "kind": "image_archive",
                    "role": "shared",
                    "sha256": sha256_bytes(b"operator archive"),
                    "size": 16,
                    "image_digest": _OPERATOR_IMAGE,
                    "purpose": WORKER_OPERATOR_PURPOSE,
                }
            ],
        }
    )
    assert signed_worker_image(manifest, WORKER_OPERATOR_PURPOSE) == _OPERATOR_IMAGE
    assert signed_worker_image(manifest, WORKER_OPERATOR_PURPOSE) != ""


# --------------------------------------------------------------------------- blast radius


def test_both_findings_block_bootstrap_adoption_and_status_alike():
    """``_worker_end_state_reason`` is the shared predicate behind FOUR engine paths, so neither
    finding is confined to a first install.

    The four callers, identified by their enclosing function on the loaded module: the bootstrap
    write transaction's reobservation gate (``_prepare_gate``), the adoption admission check
    (``adopt``), the adoption transaction's final observation (``_adopt_transaction``), and
    ``secpctl status worker`` (``_worker_status``).

    Counted exactly, not as a floor: a refactor that adds or removes a caller must revisit this
    claim rather than silently widen or narrow it.
    """
    import inspect

    from secp_management import engine

    lines = inspect.getsource(engine).splitlines()
    definitions = [ln for ln in lines if ln.startswith("def _worker_end_state_reason(")]
    call_sites = [
        ln for ln in lines if "_worker_end_state_reason(" in ln and not ln.startswith("def ")
    ]
    assert len(definitions) == 1
    assert len(call_sites) == 4, f"expected exactly 4 call sites, found {len(call_sites)}"

    # and each caller is one of the four named paths (attribute the blast radius, do not assume it)
    enclosing: list[str] = []
    current = ""
    for line in lines:
        stripped = line.lstrip()
        if stripped.startswith("def "):
            current = stripped[4:].split("(", 1)[0]
        if "_worker_end_state_reason(" in line and not line.startswith("def "):
            enclosing.append(current)
    assert sorted(enclosing) == [
        "_adopt_transaction",
        "_prepare_gate",
        "_worker_status",
        "adopt",
    ]
