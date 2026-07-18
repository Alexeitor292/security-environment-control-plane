"""Read-only real-host adapters: coherent generation-checked observation, Docker topology, health
(SECP-PR5D). Covers the ABA-safe observation (systemd InvocationID/StateChangeTimestampMonotonic +
Docker RestartCount/StartedAt/FinishedAt/Pid), the strict closed grammars, and the deployment-owned
HostObservationEvidence."""

from __future__ import annotations

import pathlib

import pytest
from _deploy_support import (
    CONTAINER_EXE,
    CONTAINER_EXE_DIGEST,
    DIGEST_CP,
    DIGEST_OW,
    HEALTH_ARGV,
    INSPECTOR_EXE,
    INSPECTOR_EXE_DIGEST,
    OPERATOR_SERVICE,
    ORDINARY_CONTAINER,
    FakeCommandRunner,
    valid_expected,
    valid_profile,
)
from secp_operator_deployment import DeploymentPackageError
from secp_operator_deployment.host_adapters import (
    _CONTAINER_FORMAT,
    _OPERATOR_PROPERTIES,
    HostObservationEvidence,
    LocalContainerRuntimeAdapter,
    LocalServiceStateAdapter,
    build_real_host_adapters,
)
from secp_operator_deployment.host_process import CommandResult
from secp_operator_deployment.pinned_exec import ExecutablePin

_CONTAINER_PIN = ExecutablePin(CONTAINER_EXE, CONTAINER_EXE_DIGEST)
_INSPECTOR_PIN = ExecutablePin(INSPECTOR_EXE, INSPECTOR_EXE_DIGEST)

_SHOW_TAIL = ("show", "--property", ",".join(_OPERATOR_PROPERTIES), OPERATOR_SERVICE)
_INSPECT_TAIL = ("inspect", "--format", _CONTAINER_FORMAT, ORDINARY_CONTAINER)
_HEALTH_TAIL = ("exec", ORDINARY_CONTAINER, *HEALTH_ARGV)

# Well-formed generation values.
_CID = "3f2a" + "0" * 60
_STARTED = "2026-01-02T03:04:05.123456789Z"
_FINISHED_ZERO = "0001-01-01T00:00:00Z"
_INVOCATION = "a" * 32
_MONOTONIC = "123456789"


def _show_output(*, load, active, unit_file, invocation=_INVOCATION, monotonic=_MONOTONIC):
    return (
        "\n".join(
            [
                f"LoadState={load}",
                f"ActiveState={active}",
                f"UnitFileState={unit_file}",
                f"InvocationID={invocation}",
                f"StateChangeTimestampMonotonic={monotonic}",
            ]
        )
        + "\n"
    )


def _container_output(
    *, cid=_CID, running=True, restart="0", started=_STARTED, finished=_FINISHED_ZERO, pid="4242"
):
    return f"{cid} {'true' if running else 'false'} {restart} {started} {finished} {pid}\n"


def _img_key(digest):
    return (CONTAINER_EXE, ("image", "inspect", "--format", "{{.Id}}", digest))


# --------------------------------------------------------------------------- container runtime


def test_container_adapter_reports_present_on_exact_digest():
    runner = FakeCommandRunner({_img_key(DIGEST_CP): (0, DIGEST_CP + "\n")})
    adapter = LocalContainerRuntimeAdapter(container_runtime=_CONTAINER_PIN, runner=runner)
    assert adapter.image_present(DIGEST_CP) is True


def test_container_adapter_reports_absent_without_pulling():
    runner = FakeCommandRunner({_img_key(DIGEST_OW): (1, "")})
    adapter = LocalContainerRuntimeAdapter(container_runtime=_CONTAINER_PIN, runner=runner)
    assert adapter.image_present(DIGEST_OW) is False


@pytest.mark.parametrize("ref", ["latest", "docker.io/x:latest", "sha256:short", "  "])
def test_container_adapter_refuses_non_exact_digest(ref):
    adapter = LocalContainerRuntimeAdapter(
        container_runtime=_CONTAINER_PIN, runner=FakeCommandRunner({})
    )
    with pytest.raises(DeploymentPackageError) as exc:
        adapter.image_present(ref)
    assert exc.value.reason_code == "image_reference_not_exact_digest"


def test_container_adapter_refuses_malformed_output():
    runner = FakeCommandRunner({_img_key(DIGEST_CP): (0, "not-the-digest\n")})
    adapter = LocalContainerRuntimeAdapter(container_runtime=_CONTAINER_PIN, runner=runner)
    with pytest.raises(DeploymentPackageError) as exc:
        adapter.image_present(DIGEST_CP)
    assert exc.value.reason_code == "image_runtime_output_malformed"


# --------------------------------------------------------------------------- coherent observation


def _responses(
    *, op_load, op_active, op_unit, container_present, container_running, healthy, **over
):
    r = {
        (INSPECTOR_EXE, _SHOW_TAIL): (
            0,
            _show_output(load=op_load, active=op_active, unit_file=op_unit),
        )
    }
    if container_present:
        r[(CONTAINER_EXE, _INSPECT_TAIL)] = (
            0,
            _container_output(running=container_running, **over),
        )
    else:
        r[(CONTAINER_EXE, _INSPECT_TAIL)] = (1, "")
    r[(CONTAINER_EXE, _HEALTH_TAIL)] = (0 if healthy else 1, "")
    return r


def _adapter(runner):
    return LocalServiceStateAdapter(
        operator_service=OPERATOR_SERVICE,
        ordinary_container=ORDINARY_CONTAINER,
        ordinary_health_command=HEALTH_ARGV,
        container_runtime=_CONTAINER_PIN,
        service_inspector=_INSPECTOR_PIN,
        runner=runner,
    )


def _prepared(**over):
    return _adapter(
        FakeCommandRunner(
            _responses(
                op_load="loaded",
                op_active="inactive",
                op_unit="disabled",
                container_present=True,
                container_running=True,
                healthy=True,
                **over,
            )
        )
    )


def test_coherent_observation_prepared_and_ready():
    ev = _prepared().observe()
    assert isinstance(ev, HostObservationEvidence)
    assert ev.inspected is True and ev.coherent is True
    assert ev.operator_present and not ev.operator_enabled and not ev.operator_running
    assert ev.ordinary_running is True
    # snapshot() derives the 5-bool ServiceStateSnapshot for inspect_host
    snap = _prepared().snapshot()
    assert snap.inspected is True and snap.ordinary_running is True


def test_ordinary_running_but_health_failing_is_not_ready():
    ev = _adapter(
        FakeCommandRunner(
            _responses(
                op_load="loaded",
                op_active="inactive",
                op_unit="disabled",
                container_present=True,
                container_running=True,
                healthy=False,
            )
        )
    ).observe()
    assert ev.ordinary_running is False


def test_ordinary_container_absent_is_not_ready():
    ev = _adapter(
        FakeCommandRunner(
            _responses(
                op_load="loaded",
                op_active="inactive",
                op_unit="disabled",
                container_present=False,
                container_running=False,
                healthy=False,
            )
        )
    ).observe()
    assert ev.ordinary_running is False


def test_operator_active_is_reflected():
    ev = _adapter(
        FakeCommandRunner(
            _responses(
                op_load="loaded",
                op_active="active",
                op_unit="enabled",
                container_present=True,
                container_running=True,
                healthy=True,
            )
        )
    ).observe()
    assert ev.operator_running is True and ev.operator_enabled is True


def test_ambiguous_reading_fails_closed():
    ev = _adapter(
        FakeCommandRunner(
            _responses(
                op_load="loaded",
                op_active="weird-unknown",
                op_unit="disabled",
                container_present=True,
                container_running=True,
                healthy=True,
            )
        )
    ).observe()
    assert ev.inspected is False and ev.coherent is False


def test_command_error_fails_closed():
    class _Raiser:
        def run(self, pin, argv_tail, *, timeout_seconds, max_output_bytes):
            raise DeploymentPackageError("command_timeout")

    ev = _adapter(_Raiser()).observe()
    assert ev.inspected is False and ev.ordinary_running is False


# --------------------------------------------------------------------------- strict systemd
# grammar


def test_malformed_systemctl_missing_property_fails_closed():
    bad = (
        "LoadState=loaded\nActiveState=inactive\nUnitFileState=disabled\nInvocationID="
        + _INVOCATION
        + "\n"
    )
    r = _responses(
        op_load="loaded",
        op_active="inactive",
        op_unit="disabled",
        container_present=True,
        container_running=True,
        healthy=True,
    )
    r[(INSPECTOR_EXE, _SHOW_TAIL)] = (0, bad)  # missing StateChangeTimestampMonotonic
    assert _adapter(FakeCommandRunner(r)).observe().inspected is False


def test_malformed_systemctl_unexpected_property_fails_closed():
    r = _responses(
        op_load="loaded",
        op_active="inactive",
        op_unit="disabled",
        container_present=True,
        container_running=True,
        healthy=True,
    )
    r[(INSPECTOR_EXE, _SHOW_TAIL)] = (
        0,
        _show_output(load="loaded", active="inactive", unit_file="disabled") + "Extra=1\n",
    )
    assert _adapter(FakeCommandRunner(r)).observe().inspected is False


@pytest.mark.parametrize("invocation", ["not-hex-invocation", "AAAA" + "a" * 28, "a" * 31])
def test_malformed_invocation_id_fails_closed(invocation):
    r = _responses(
        op_load="loaded",
        op_active="inactive",
        op_unit="disabled",
        container_present=True,
        container_running=True,
        healthy=True,
    )
    r[(INSPECTOR_EXE, _SHOW_TAIL)] = (
        0,
        _show_output(load="loaded", active="inactive", unit_file="disabled", invocation=invocation),
    )
    assert _adapter(FakeCommandRunner(r)).observe().inspected is False


def test_empty_invocation_id_is_allowed():
    # A never-started unit legitimately has an empty InvocationID.
    r = _responses(
        op_load="loaded",
        op_active="inactive",
        op_unit="disabled",
        container_present=True,
        container_running=True,
        healthy=True,
    )
    r[(INSPECTOR_EXE, _SHOW_TAIL)] = (
        0,
        _show_output(load="loaded", active="inactive", unit_file="disabled", invocation=""),
    )
    assert _adapter(FakeCommandRunner(r)).observe().inspected is True


def test_malformed_monotonic_fails_closed():
    r = _responses(
        op_load="loaded",
        op_active="inactive",
        op_unit="disabled",
        container_present=True,
        container_running=True,
        healthy=True,
    )
    r[(INSPECTOR_EXE, _SHOW_TAIL)] = (
        0,
        _show_output(load="loaded", active="inactive", unit_file="disabled", monotonic="12x34"),
    )
    assert _adapter(FakeCommandRunner(r)).observe().inspected is False


# --------------------------------------------------------------------------- strict Docker grammar


def _container_only_adapter(inspect_output):
    return _adapter(FakeCommandRunner({(CONTAINER_EXE, _INSPECT_TAIL): (0, inspect_output)}))


def test_container_grammar_accepts_exact_line():
    obs = _container_only_adapter(_container_output())._container_observation()
    assert obs.present and obs.container_id == _CID and obs.running is True
    assert obs.restart_count == "0" and obs.started_at == _STARTED and obs.pid == "4242"


def test_container_grammar_accepts_stopped():
    out = _container_output(running=False, pid="0")
    obs = _container_only_adapter(out)._container_observation()
    assert obs.present and obs.running is False and obs.pid == "0"


@pytest.mark.parametrize(
    "raw",
    [
        "abc123 true 0 " + _STARTED + " " + _FINISHED_ZERO + " 1\n",  # short id
        _CID.upper() + " true 0 " + _STARTED + " " + _FINISHED_ZERO + " 1\n",  # uppercase
        _CID[:-1] + "g true 0 " + _STARTED + " " + _FINISHED_ZERO + " 1\n",  # non-hex
        _CID + " true 0 " + _STARTED + " " + _FINISHED_ZERO + "\n",  # missing pid field
        _CID + " true 0 " + _STARTED + " " + _FINISHED_ZERO + " 1 extra\n",  # extra field
        _CID + " yes 0 " + _STARTED + " " + _FINISHED_ZERO + " 1\n",  # bad boolean
        _CID + " true x " + _STARTED + " " + _FINISHED_ZERO + " 1\n",  # bad restart count
        _CID + " true 0 not-a-timestamp " + _FINISHED_ZERO + " 1\n",  # bad StartedAt
        _CID + " true 0 " + _STARTED + " " + _FINISHED_ZERO + " x\n",  # bad pid
        _container_output() + _container_output(),  # extra line
        "",  # empty
        "\n",  # only newline
    ],
)
def test_container_grammar_rejects_malformed(raw):
    with pytest.raises(DeploymentPackageError) as exc:
        _container_only_adapter(raw)._container_observation()
    assert exc.value.reason_code == "container_runtime_output_malformed"


def test_container_absent_when_inspect_nonzero():
    obs = _adapter(
        FakeCommandRunner({(CONTAINER_EXE, _INSPECT_TAIL): (1, "")})
    )._container_observation()
    assert obs.present is False


# --------------------------------------------------------------------------- ABA / generation gap


class _SequencedRunner:
    """Returns a scripted SEQUENCE of results for a key (before/after), else a fixed response."""

    def __init__(self, responses, sequences):
        self.responses = responses
        self.sequences = sequences
        self._n: dict = {}

    def run(self, pin, argv_tail, *, timeout_seconds, max_output_bytes):
        key = (pin.path, tuple(argv_tail))
        if key in self.sequences:
            seq = self.sequences[key]
            i = self._n.get(key, 0)
            self._n[key] = i + 1
            code, out = seq[min(i, len(seq) - 1)]
            return CommandResult(code, out)
        if key in self.responses:
            code, out = self.responses[key]
            return CommandResult(code, out)
        raise AssertionError(f"unscripted command: {key}")


def _aba_adapter(*, container_seq=None, operator_seq=None):
    base = _responses(
        op_load="loaded",
        op_active="inactive",
        op_unit="disabled",
        container_present=True,
        container_running=True,
        healthy=True,
    )
    sequences = {}
    if container_seq is not None:
        sequences[(CONTAINER_EXE, _INSPECT_TAIL)] = [(0, o) for o in container_seq]
    if operator_seq is not None:
        sequences[(INSPECTOR_EXE, _SHOW_TAIL)] = [(0, o) for o in operator_seq]
    return _adapter(_SequencedRunner(base, sequences))


def test_container_restart_count_aba_refuses():
    # Same id + running=true before/after, but RestartCount changed → ABA restart → fail closed.
    ev = _aba_adapter(
        container_seq=[_container_output(restart="0"), _container_output(restart="1")]
    ).observe()
    assert ev.coherent is False and ev.inspected is False


def test_container_started_at_aba_refuses():
    ev = _aba_adapter(
        container_seq=[
            _container_output(started=_STARTED),
            _container_output(started="2026-01-02T09:09:09.000000000Z"),
        ]
    ).observe()
    assert ev.inspected is False


def test_container_pid_aba_refuses():
    ev = _aba_adapter(
        container_seq=[_container_output(pid="4242"), _container_output(pid="5353")]
    ).observe()
    assert ev.inspected is False


def test_operator_invocation_id_aba_refuses():
    # Same load/active/unit-file, but a new systemd InvocationID → operator restarted → fail
    # closed.
    ev = _aba_adapter(
        operator_seq=[
            _show_output(
                load="loaded", active="inactive", unit_file="disabled", invocation="a" * 32
            ),
            _show_output(
                load="loaded", active="inactive", unit_file="disabled", invocation="b" * 32
            ),
        ]
    ).observe()
    assert ev.inspected is False


def test_operator_state_change_timestamp_aba_refuses():
    ev = _aba_adapter(
        operator_seq=[
            _show_output(load="loaded", active="inactive", unit_file="disabled", monotonic="111"),
            _show_output(load="loaded", active="inactive", unit_file="disabled", monotonic="222"),
        ]
    ).observe()
    assert ev.inspected is False


def test_health_result_cannot_apply_across_container_generations():
    # Health passes against the BEFORE generation, but the container's generation changes
    # (StartedAt) before the after-observation → the whole observation is not coherent and fails
    # closed, so a health result from one generation is never applied to another.
    ev = _aba_adapter(
        container_seq=[
            _container_output(started=_STARTED, pid="4242"),
            _container_output(started="2026-02-02T02:02:02.000000000Z", pid="9999"),
        ]
    ).observe()
    assert ev.ordinary_running is False and ev.inspected is False


# --------------------------------------------------------------------------- no mutation / exact
# argv


def test_adapter_invokes_no_mutation_subcommand():
    text = pathlib.Path(
        __import__("secp_operator_deployment.host_adapters", fromlist=["x"]).__file__
    ).read_text(encoding="utf-8")
    for verb in ("start", "stop", "restart", "enable", "disable", "reload", "mask"):
        assert f'"{verb}",' not in text, verb
    assert '"show"' in text and '"inspect"' in text


def test_operator_uses_one_systemctl_show_call():
    # Exactly one `systemctl show` per observation (not three independently timed calls);
    # `is-enabled` is no longer used — UnitFileState comes from the single show.
    text = pathlib.Path(
        __import__("secp_operator_deployment.host_adapters", fromlist=["x"]).__file__
    ).read_text(encoding="utf-8")
    assert '"is-enabled"' not in text
    assert "_OPERATOR_PROPERTIES" in text


def test_exact_health_argv_is_enforced():
    text = pathlib.Path(
        __import__("secp_operator_deployment.host_adapters", fromlist=["x"]).__file__
    ).read_text(encoding="utf-8")
    assert '("exec", self.ordinary_container, *self.ordinary_health_command)' in text


def test_host_observation_evidence_is_exact_typed_and_derives_snapshot():
    from secp_commissioning.status import ServiceStateSnapshot

    ev = _prepared().observe()
    assert type(ev) is HostObservationEvidence
    snap = ev.to_service_state_snapshot()
    assert type(snap) is ServiceStateSnapshot
    assert snap.ordinary_running == ev.ordinary_running


# --------------------------------------------------------------------------- construction


def test_build_real_host_adapters_requires_profile_agreement():
    bad = valid_profile(container_runtime_executable_digest="sha256:" + "0" * 64)
    with pytest.raises(DeploymentPackageError):
        build_real_host_adapters(bad, valid_expected())


def test_build_real_host_adapters_wires_pins():
    container, service = build_real_host_adapters(valid_profile(), valid_expected())
    assert container.container_runtime.path == CONTAINER_EXE
    assert service.ordinary_container == ORDINARY_CONTAINER
    assert service.service_inspector.path == INSPECTOR_EXE
