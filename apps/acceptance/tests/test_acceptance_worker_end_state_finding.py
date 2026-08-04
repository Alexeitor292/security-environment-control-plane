"""ACCEPTANCE REGRESSION — the production worker end-state gate CAN be satisfied, and still bites.

This file began as two acceptance FINDINGS: the supported production worker installation path
could not succeed, because ``engine._worker_end_state_reason`` refused a correctly prepared host
twice over (Finding A, ``worker_generation_marker_invalid``; Finding B,
``worker_operator_image_mismatch``). Both are CLOSED on ``main``:

* **Finding A** — ``_worker_generation_complete`` no longer demands a non-empty operator
  ``InvocationID``. systemd assigns one when a unit is STARTED, and the reviewed operator unit is
  installed present, disabled and stopped and is *never started*, so the field is legitimately empty
  on a correct host. The generation tuple now carries ``operator_state_change_monotonic``, which a
  never-started unit DOES expose, so the ABA property the check exists for survives.
* **Finding B** — ``RealManagementHostObserver.observe_worker`` no longer hardcodes ``""`` for the
  operator image. ``_installed_operator_image`` reads the host's own installed-release record, asks
  the runtime whether that content-addressed image is loaded, and returns the digest only when the
  runtime answers with the same id. The gate gained ``worker_operator_image_unobserved`` so an
  unproven image can never reach — let alone satisfy — the equality against the signed manifest.

WHY THIS FILE STILL EXISTS
--------------------------
The reason the two findings were invisible has not changed: the engine suites drive
``FakeObserver``, and the one suite that drives the REAL observer against real Docker and real
systemd (``test_management_real_adapters_root.py``) asserts observer FIELDS and never calls
``_worker_end_state_reason``. **No other suite puts the real observation in front of the real
gate.** This file is that test. It now pins the CLOSURE rather than the defect, which is the same
measurement pointed the other way.

Every positive claim below is paired with a CONTROL that removes exactly one fact and shows the
gate refuses. Without those, "the prepared host is accepted" would be equally consistent with a
gate that had simply been deleted — which is the failure mode a closed finding invites.
"""

from __future__ import annotations

import dataclasses
import json

import pytest
from secp_commissioning.canonical import sha256_bytes

_ORDINARY_IMAGE = sha256_bytes(b"acceptance/worker-ordinary")
_OPERATOR_IMAGE = sha256_bytes(b"acceptance/worker-operator")
_CONTAINER_ID = "b3" + "0" * 62
_STARTED_AT = "2026-01-02T03:04:05.000000000Z"
_PID = "4242"
_RESTART = "0"
#: What systemd reports for the operator unit's last state change. A never-started unit HAS this
#: fact — it is why it can replace the InvocationID in the generation tuple without weakening it.
_STATE_CHANGE_MONOTONIC = "123456"

_COMPOSE_BODY = b"# acceptance worker compose\n"
_UNIT_BODY = b"[Unit]\nDescription=acceptance operator unit\n"
_PACKAGE_BODY = b"acceptance deployment package\n"


def _release_manifest_obj() -> dict:
    """A minimal VALID signed-release manifest naming the operator image.

    The contract version is READ FROM the product constant, never restated. A copied literal would
    agree with itself after someone bumped the real one, and the only symptom would be an observer
    that silently cannot read its own record — which reads exactly like Finding B coming back.
    ``test_the_release_record_fixture_is_actually_readable_by_the_product`` proves the parse.
    """
    from secp_management import BOOTSTRAP_CONTRACT_VERSION
    from secp_management.release_bundle import (
        WORKER_DEPLOYMENT_PACKAGE_PURPOSE,
        WORKER_OPERATOR_PURPOSE,
        WORKER_ORDINARY_PURPOSE,
    )

    return {
        "bootstrap_contract_version": BOOTSTRAP_CONTRACT_VERSION,
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
        # `image_archive` and `python_wheel` are both SHARED-role kinds in `_KIND_ROLE`;
        # naming them "worker" is refused `release_artifact_role_kind_mismatch`.
        # All THREE required worker purposes. A worker manifest missing any of them is refused
        # `release_purpose_set_incomplete`, so a record naming only the operator image is not a
        # record the product would ever have written.
        "artifacts": [
            {
                "name": "images/ordinary.tar",
                "kind": "image_archive",
                "role": "shared",
                "sha256": sha256_bytes(b"ordinary archive"),
                "size": 16,
                "image_digest": _ORDINARY_IMAGE,
                "purpose": WORKER_ORDINARY_PURPOSE,
            },
            {
                "name": "images/operator.tar",
                "kind": "image_archive",
                "role": "shared",
                "sha256": sha256_bytes(b"operator archive"),
                "size": 16,
                "image_digest": _OPERATOR_IMAGE,
                "purpose": WORKER_OPERATOR_PURPOSE,
            },
            {
                "name": "wheels/secp_worker-0.0.1-py3-none-any.whl",
                "kind": "python_wheel",
                "role": "shared",
                "sha256": sha256_bytes(b"worker deployment package"),
                "size": 16,
                "image_digest": None,
                "purpose": WORKER_DEPLOYMENT_PACKAGE_PURPOSE,
            },
        ],
    }


def _release_record_bytes() -> bytes:
    return json.dumps(_release_manifest_obj()).encode("utf-8")


class _Result:
    def __init__(self, exit_code: int, stdout: str) -> None:
        self.exit_code = exit_code
        self.stdout = stdout
        self.stderr = ""


class _PreparedHostRunner:
    """Answers every command the real observer issues the way a correctly prepared host would.

    Two knobs, each isolating one control below: whether the operator image is LOADED (the runtime
    answers the ``image inspect`` with the same content-addressed id), and whether the ordinary
    worker's queue self-report probe completes at all.
    """

    def __init__(self, *, image_loaded: bool = True, queue_probe_ok: bool = True) -> None:
        self._image_loaded = image_loaded
        self._queue_probe_ok = queue_probe_ok

    def run(self, pin, argv, *, timeout_seconds, max_output_bytes):  # noqa: ANN001, ANN003
        if argv[0] == "show":
            return _Result(
                0,
                "LoadState=loaded\n"
                "ActiveState=inactive\n"
                "UnitFileState=static\n"
                # EMPTY, and correct: the reviewed operator unit is never started.
                "InvocationID=\n"
                f"StateChangeTimestampMonotonic={_STATE_CHANGE_MONOTONIC}\n",
            )
        if argv[0] == "image":  # ("image", "inspect", "--format", "{{.Id}}", <digest>)
            if not self._image_loaded:
                return _Result(1, "")
            return _Result(0, argv[-1] + "\n")
        if argv[0] == "inspect" and "{{.Image}}" in argv:
            return _Result(0, _ORDINARY_IMAGE + "\n")
        if argv[0] == "inspect":
            return _Result(
                0,
                f"{_CONTAINER_ID} true {_RESTART} {_STARTED_AT} 0001-01-01T00:00:00Z {_PID}\n",
            )
        if argv[0] == "exec" and argv[-1] == "queues":
            if not self._queue_probe_ok:
                return _Result(1, "")
            return _Result(0, "secp-orchestration\n")
        if argv[0] == "exec":
            return _Result(0, "")  # the pinned health contract passes
        if argv[0] == "version":
            return _Result(0, "29.0.0\n")
        return _Result(1, "")


class _PreparedFilesystem:
    """Returns the exact installed-document bytes a prepared worker host carries.

    An absent path raises the product's own ``FilesystemError``, not the builtin
    ``FileNotFoundError``: the observer catches ``(FilesystemError, ManagementError)`` and treats
    them as "not proof". A stub that raised something outside that pair would escape the observer
    entirely and the control below would be measuring an exception leak rather than the fail-closed
    path it claims to measure.
    """

    def __init__(self, paths: dict[str, bytes]) -> None:
        self._paths = paths

    def safe_read(self, path: str, *, max_bytes: int, expected_uid: int) -> bytes:
        from secp_commissioning.runtime import FilesystemError

        if path not in self._paths:
            raise FilesystemError("file_absent")
        return self._paths[path]


def _pin(path: str):  # noqa: ANN202
    from secp_operator_deployment.pinned_exec import ExecutablePin

    return ExecutablePin(path, "sha256:" + "a" * 64)


def _observe(  # noqa: ANN201
    *, release_record: bool = True, image_loaded: bool = True, queue_probe_ok: bool = True
):
    """Drive the REAL production observer over a prepared host and return its observation."""
    from secp_management.layout import ManagementLocations
    from secp_management.planes import Role
    from secp_management.real_adapters import (
        PinnedExecutables,
        RealAdapterContext,
        RealManagementHostObserver,
    )

    locations = ManagementLocations()
    paths = {
        locations.worker_compose_path(): _COMPOSE_BODY,
        locations.operator_unit_path(): _UNIT_BODY,
        locations.worker_deployment_package_path(): _PACKAGE_BODY,
    }
    if release_record:
        paths[locations.release_record_path(Role.WORKER.value)] = _release_record_bytes()
    ctx = RealAdapterContext(
        locations=locations,
        fs=_PreparedFilesystem(paths),  # type: ignore[arg-type]
        runner=_PreparedHostRunner(  # type: ignore[arg-type]
            image_loaded=image_loaded, queue_probe_ok=queue_probe_ok
        ),
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


def _reason(observation) -> str | None:  # noqa: ANN001
    from secp_management.engine import _worker_end_state_reason

    return _worker_end_state_reason(observation, _expected_for(observation))


def _without_state_change(observation):  # noqa: ANN001, ANN202
    """Drop the operator's state-change fact AND re-derive the generation marker.

    The marker is a digest over the whole generation tuple, so removing a component without
    re-deriving it would fail the marker-equality check for a second, unrelated reason and make the
    refusal unattributable.
    """
    from secp_management.adapters import worker_generation_marker

    return dataclasses.replace(
        observation,
        operator_state_change_monotonic="",
        generation_marker=worker_generation_marker(
            container_id=observation.ordinary_container_id,
            running_pid=observation.ordinary_pid,
            restart_count=observation.ordinary_restart_count,
            started_at=observation.ordinary_started_at,
            operator_invocation_id=observation.operator_invocation_id,
            operator_state_change_monotonic="",
        ),
    )


@pytest.fixture()
def never_started():  # noqa: ANN201
    """The real posture: the operator unit is present, disabled, stopped, and NEVER started."""
    return _observe()


# --------------------------------------------------------------------------- premise guard


def test_the_prepared_host_fixture_is_not_degenerate(never_started):
    """If this fixture did not model a correctly prepared host, every claim below would be about a
    broken fixture rather than about the product."""
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


# --------------------------------------------------------------------------- the headline


def test_the_prepared_end_state_is_reachable_from_the_real_observer_with_no_field_surgery(
    never_started,
):
    """THE claim this file exists to make, and the one no other suite makes.

    The REAL production observer's own output, unmodified, put in front of the REAL end-state gate,
    returns ``None`` — the complete canonical prepared end state. Earlier this returned
    ``worker_generation_marker_invalid``, and then ``worker_operator_image_mismatch`` once that was
    stepped past, which is what made the supported installation path unable to succeed.
    """
    assert _reason(never_started) is None


# --------------------------------------------------------------------------- finding A, closed


def test_a_never_started_operator_unit_still_reports_no_invocation_id(never_started):
    """Unchanged fact about systemd, and the reason Finding A was real. The fix did not make the
    field appear; it stopped the gate from requiring it."""
    assert never_started.operator_invocation_id == ""


def test_finding_a_closed_an_empty_invocation_id_no_longer_refuses(never_started):
    """FINDING A, closed. The empty InvocationID above does not reach the generation refusal."""
    assert _reason(never_started) != "worker_generation_marker_invalid"


def test_finding_a_control_the_generation_check_still_refuses_an_incomplete_tuple(never_started):
    """CONTROL for Finding A, and the guard against a fix that simply deleted the check.

    ``operator_state_change_monotonic`` is what replaced the InvocationID in the generation tuple.
    Remove exactly that one fact — marker re-derived so the refusal is attributable to it alone —
    and the gate refuses ``worker_generation_marker_invalid`` again. So the ABA property the check
    exists for is intact; only the fact it reads has changed.
    """
    assert _reason(_without_state_change(never_started)) == "worker_generation_marker_invalid"


# --------------------------------------------------------------------------- finding B, closed


def test_the_release_record_fixture_is_actually_readable_by_the_product():
    """NON-VACUITY, and it runs before the two controls it protects.

    ``_installed_operator_image`` swallows every parse failure and returns ``""`` — correctly, since
    an unreadable record is not proof. But that means a fixture whose record the product cannot
    parse produces ``worker_operator_image_unobserved`` for the WRONG reason, and both controls
    below would pass while measuring a broken fixture instead of the product. (That is not
    hypothetical: this fixture first named a contract version the product refuses.) So parse it
    here, through the product's own loader, and read the digest back out.
    """
    from secp_management.release_bundle import (
        WORKER_OPERATOR_PURPOSE,
        parse_manifest_bytes,
        signed_worker_image,
    )

    manifest = parse_manifest_bytes(_release_record_bytes())
    assert signed_worker_image(manifest, WORKER_OPERATOR_PURPOSE) == _OPERATOR_IMAGE


def test_finding_b_closed_the_observer_now_reports_the_installed_operator_image(never_started):
    """FINDING B, closed. The SHIPPED observer reports the signed operator image for a prepared
    host, read from the host's installed-release record and confirmed loaded by the runtime."""
    assert never_started.operator_image_digest == _OPERATOR_IMAGE


def test_finding_b_control_an_unreadable_release_record_is_unobserved_not_assumed():
    """CONTROL for Finding B, half one: no record to read.

    The refusal is ``worker_operator_image_unobserved``, NOT ``..._mismatch`` and emphatically not
    ``None``. The distinction is the whole point of the fix: "I could not prove which image is
    loaded" is a different fact from "the wrong image is loaded", and neither is evidence of a
    match.
    """
    assert _reason(_observe(release_record=False)) == "worker_operator_image_unobserved"


def test_finding_b_control_a_runtime_that_cannot_confirm_the_image_is_unobserved():
    """CONTROL for Finding B, half two: the record names the image, but the runtime does not confirm
    it is loaded. Reading a digest out of a file is not proof the image is there, and the observer
    must not treat it as such."""
    assert _reason(_observe(image_loaded=False)) == "worker_operator_image_unobserved"


def test_the_signed_operator_image_is_never_the_empty_string():
    """The other half of Finding B: no valid worker bundle can make the comparison succeed by
    supplying ``""`` — the release schema requires an image archive to carry a real digest."""
    from secp_management.release_bundle import (
        WORKER_OPERATOR_PURPOSE,
        ReleaseManifest,
        signed_worker_image,
    )

    manifest = ReleaseManifest.model_validate(_release_manifest_obj())
    assert signed_worker_image(manifest, WORKER_OPERATOR_PURPOSE) == _OPERATOR_IMAGE
    assert signed_worker_image(manifest, WORKER_OPERATOR_PURPOSE) != ""


# --------------------------------------------------------- queue containment, now three-valued


def test_a_probe_that_did_not_complete_is_unprovable_and_not_a_fabricated_breach():
    """The isolation property this program exists for, reported honestly.

    An ordinary-worker queue self-report probe that exits non-zero used to be folded into
    ``ordinary_polls_operator_queue=True`` — fail-closed and therefore safe, but it announced an
    observed BREACH of operator-queue containment when nothing had been observed at all. A false
    breach gets acted on, so the false-alarm direction is the damaging one.

    Now the verdict is ``unprovable``, it carries a bounded cause, and the gate refuses with its own
    reason. Fail-closed is unchanged — this still refuses to certify.
    """
    from secp_management.adapters import CONTAINMENT_UNPROVABLE, resolve_queue_containment

    observation = _observe(queue_probe_ok=False)
    assert resolve_queue_containment(observation) == CONTAINMENT_UNPROVABLE
    assert observation.ordinary_queue_containment_reason == "queue_probe_command_failed"
    # still fail-closed on the two-valued field every existing caller reads
    assert observation.ordinary_polls_operator_queue is True
    assert _reason(observation) == "worker_ordinary_queue_containment_unprovable"


def test_a_completed_probe_on_a_contained_worker_is_a_positive_observation(never_started):
    """The control for the above: a probe that DID complete and saw no operator queue is
    ``contained``, with no cause to report. Without this, "unprovable" would be consistent with a
    probe that can never succeed."""
    from secp_management.adapters import CONTAINMENT_CONTAINED, resolve_queue_containment

    assert resolve_queue_containment(never_started) == CONTAINMENT_CONTAINED
    assert never_started.ordinary_queue_containment_reason is None


# --------------------------------------------------------------------------- blast radius


def test_the_gate_is_the_shared_predicate_behind_bootstrap_adoption_and_status():
    """``_worker_end_state_reason`` governs FOUR engine paths, so neither the findings nor their
    closure were confined to a first install.

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
