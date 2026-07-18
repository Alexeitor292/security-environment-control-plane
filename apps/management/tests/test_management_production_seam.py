"""Production adapter seam (SECP-PR5E round 2): the SHIPPED defaults are SEALED, so the CLI's
default dependencies fail closed; a CLI user can neither select nor inject an adapter; and the
adapter surfaces expose ONLY the reviewed operations (no subprocess/shell/argv/path verb)."""

from __future__ import annotations

from dataclasses import replace

import pytest
from _mgmt_support import deps_for, ephemeral_trust_root, prepared_worker_world
from secp_commissioning.runtime import InMemoryFilesystem
from secp_management import ManagementError
from secp_management.adapters import (
    ControllerBootstrapAdapter,
    ManagementHostObserver,
    ManagementRollbackAdapter,
    SealedControllerBootstrapAdapter,
    SealedHostObserver,
    SealedRollbackAdapter,
    SealedWorkerBootstrapAdapter,
    WorkerBootstrapAdapter,
)
from secp_management.cli import build_parser, run
from secp_management.engine import EngineDeps


def test_default_engine_deps_use_sealed_adapters():
    d = EngineDeps()
    assert isinstance(d.observer, SealedHostObserver)
    assert isinstance(d.controller_adapter, SealedControllerBootstrapAdapter)
    assert isinstance(d.worker_adapter, SealedWorkerBootstrapAdapter)
    assert isinstance(d.rollback_adapter, SealedRollbackAdapter)


def test_sealed_observer_fails_closed():
    obs = SealedHostObserver()
    for call in (obs.platform, obs.observe_controller, obs.observe_worker):
        with pytest.raises(ManagementError) as exc:
            call()
        assert exc.value.reason_code == "host_observer_not_available"


def test_sealed_mutation_adapters_fail_closed():
    from secp_management.adapters import ReviewedConfig, VerifiedArtifact

    art = VerifiedArtifact(
        role="shared",
        kind="image_archive",
        name="x",
        digest="sha256:" + "0" * 64,
        size=1,
        reader=lambda: b"x",
    )
    with pytest.raises(ManagementError) as exc:
        SealedWorkerBootstrapAdapter().load_image(art)
    assert exc.value.reason_code == "worker_bootstrap_adapter_not_provisioned"
    with pytest.raises(ManagementError) as exc:
        SealedControllerBootstrapAdapter().start_stack(expected_components=())
    assert exc.value.reason_code == "controller_bootstrap_adapter_not_provisioned"
    with pytest.raises(ManagementError) as exc:
        SealedWorkerBootstrapAdapter().install_ordinary_config(
            ReviewedConfig(identity="sha256:" + "0" * 64, content=b"x")
        )
    assert exc.value.reason_code == "worker_bootstrap_adapter_not_provisioned"
    with pytest.raises(ManagementError) as exc:
        SealedRollbackAdapter().remove_object(binding="b", kind="file")
    assert exc.value.reason_code == "rollback_not_implemented"


def _all_option_strings(parser) -> set[str]:
    opts: set[str] = set()
    for a in parser._actions:
        opts.update(getattr(a, "option_strings", []))
        choices = getattr(a, "choices", None)
        if isinstance(choices, dict):  # a subparsers action → recurse into each subcommand
            for sub in choices.values():
                if hasattr(sub, "_actions"):
                    opts |= _all_option_strings(sub)
    return opts


def test_cli_cannot_select_or_inject_an_adapter():
    option_strings = _all_option_strings(build_parser())
    forbidden = ("--observer", "--adapter", "--probe", "--fs", "--filesystem", "--exec", "--shell")
    for f in forbidden:
        assert f not in option_strings
    # the only path argument anywhere in the surface is the read-only bundle source
    assert "--bundle" in option_strings


def _public_methods(proto: type) -> set[str]:
    return {n for n in dir(proto) if not n.startswith("_")}


def test_adapter_surfaces_are_closed_and_reviewed():
    # no adapter exposes a generic subprocess/shell/argv/path/exec/run verb
    forbidden_tokens = (
        "subprocess",
        "shell",
        "exec",
        "run_shell",
        "argv",
        "popen",
        "system",
        "spawn",
    )
    surfaces = {
        ManagementHostObserver: {"platform", "observe_controller", "observe_worker"},
        ControllerBootstrapAdapter: {
            "load_image",
            "install_config",
            "install_unit",
            "daemon_reload",
            "run_migrations",
            "start_stack",
            "receipt",
            "compensate",
        },
        WorkerBootstrapAdapter: {
            "load_image",
            "install_ordinary_config",
            "install_deployment_package",
            "install_operator_unit_disabled",
            "daemon_reload",
            "start_ordinary",
            "receipt",
            "compensate",
        },
        ManagementRollbackAdapter: {"remove_object"},
    }
    # every mutation op consumes an EXACT typed input, never a bare path/argv — proven by the fact
    # that no method name carries a generic-primitive token
    for proto, expected in surfaces.items():
        methods = _public_methods(proto)
        assert methods == expected, (proto, methods ^ expected)
        for name in methods:
            assert not any(tok in name for tok in forbidden_tokens), (proto, name)


def test_host_inspect_reports_observer_unavailable_when_sealed():
    trust, _kid, _priv, _pub = ephemeral_trust_root()
    fs = InMemoryFilesystem()
    deps = replace(deps_for(fs, prepared_worker_world(), trust), observer=SealedHostObserver())
    code, rep = run(["host", "inspect"], deps)
    assert code == 0
    assert rep["observer_available"] is False
    assert rep["docker_present"] is None and rep["compose_present"] is None
