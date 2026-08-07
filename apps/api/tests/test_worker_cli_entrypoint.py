"""``secp-worker`` — the executable the installed unit runs, which until now did not exist.

The installer rendered ``ExecStart=/opt/secp/worker/bin/secp-worker --role <r> --task-queue <q>``
and refused to install unless that file was present; nothing in the repository produced it, and
``secp_worker.main.main`` parsed no argv, so even a hand-built wrapper would have ignored the role
and the queue. These tests pin both halves: the executable is declared, and it refuses a unit whose
argv disagrees with the process configuration.

The queue check is a privilege check, not a nuisance check — the operator queue is the privileged
one, so a worker quietly polling the wrong queue is a privilege confusion.
"""

from __future__ import annotations

import pytest
from secp_worker.cli import (
    EXIT_MISCONFIGURED,
    SUPPORTED_ROLES,
    WorkerCliError,
    build_parser,
    main,
    resolve_role_and_queue,
)


class _Settings:
    def __init__(self, ordinary: str = "secp-orchestration", operator: str = "") -> None:
        self.temporal_task_queue = ordinary
        self.temporal_operator_task_queue = operator


# === the argv the installer actually renders =====================================================


def test_the_installed_argv_shape_is_accepted():
    role, queue = resolve_role_and_queue(
        ["--role", "ordinary", "--task-queue", "secp-orchestration"], settings=_Settings()
    )
    assert (role, queue) == ("ordinary", "secp-orchestration")


def test_the_role_set_is_closed():
    assert SUPPORTED_ROLES == ("ordinary", "operator")
    with pytest.raises(SystemExit):
        build_parser().parse_args(["--role", "superuser", "--task-queue", "q"])


def test_an_abbreviated_flag_is_refused():
    """``allow_abbrev=False``. ``--role`` must not be satisfiable by a prefix — an installer typo
    that happened to abbreviate would otherwise be accepted and mean something."""
    with pytest.raises(SystemExit):
        build_parser().parse_args(["--ro", "ordinary", "--task-queue", "q"])


@pytest.mark.parametrize("missing", [["--role", "ordinary"], ["--task-queue", "q"], []])
def test_both_arguments_are_required(missing):
    with pytest.raises(SystemExit):
        build_parser().parse_args(missing)


# === the unit and the configuration must agree ===================================================


def test_a_queue_that_does_not_match_the_configured_ordinary_queue_refuses():
    with pytest.raises(WorkerCliError, match="does_not_match_configured_ordinary_queue"):
        resolve_role_and_queue(
            ["--role", "ordinary", "--task-queue", "some-other-queue"], settings=_Settings()
        )


def test_an_ordinary_unit_pointed_at_the_operator_queue_refuses():
    """The symptom this prevents is a worker silently serving the privileged queue."""
    settings = _Settings(operator="secp-controlled-live-v1")
    with pytest.raises(WorkerCliError, match="does_not_match_configured_ordinary_queue"):
        resolve_role_and_queue(
            ["--role", "ordinary", "--task-queue", "secp-controlled-live-v1"], settings=settings
        )


def test_an_ordinary_role_refuses_even_when_both_queues_are_configured_the_same():
    """Belt and braces: if a deployment configured both settings to one string, an ordinary unit
    must still not end up on the privileged queue."""
    same = _Settings(ordinary="secp-orchestration", operator="secp-orchestration")
    with pytest.raises(WorkerCliError, match="ordinary_role_on_operator_queue"):
        resolve_role_and_queue(
            ["--role", "ordinary", "--task-queue", "secp-orchestration"], settings=same
        )


def test_an_operator_role_refuses_when_no_operator_queue_is_configured():
    with pytest.raises(WorkerCliError, match="operator_queue_not_configured"):
        resolve_role_and_queue(
            ["--role", "operator", "--task-queue", "secp-controlled-live-v1"],
            settings=_Settings(),
        )


def test_an_operator_role_with_the_wrong_queue_refuses():
    settings = _Settings(operator="secp-controlled-live-v1")
    with pytest.raises(WorkerCliError, match="does_not_match_configured_operator_queue"):
        resolve_role_and_queue(
            ["--role", "operator", "--task-queue", "secp-orchestration"], settings=settings
        )


def test_an_empty_queue_refuses():
    with pytest.raises(WorkerCliError, match="task_queue_empty"):
        resolve_role_and_queue(["--role", "ordinary", "--task-queue", "   "], settings=_Settings())


# === argv cannot enable anything =================================================================


def test_argv_carries_no_capability_switch():
    """Execution authority comes from durable rows (ADR-030). A command line is not a durable row,
    and this pins that the entry point offers no way to pretend otherwise."""
    parser = build_parser()
    options = {action.dest for action in parser._actions}
    assert options == {"help", "role", "task_queue"}
    for banned in ("enable", "real", "armed", "unseal", "unsealed", "force", "allow"):
        assert banned not in options, banned
    with pytest.raises(SystemExit):
        parser.parse_args(
            ["--role", "ordinary", "--task-queue", "secp-orchestration", "--enable-real"]
        )


def test_an_operator_unit_refuses_rather_than_serving_the_ordinary_set(monkeypatch, capsys):
    """A process that said "operator" and then served the ordinary composition would be exactly the
    privilege confusion the queue separation exists to prevent."""
    import secp_api.config as config

    monkeypatch.setattr(
        config, "get_settings", lambda: _Settings(operator="secp-controlled-live-v1")
    )
    code = main(["--role", "operator", "--task-queue", "secp-controlled-live-v1"])
    assert code == EXIT_MISCONFIGURED
    assert "worker_operator_composition_not_installed" in capsys.readouterr().err


def test_a_misconfigured_unit_exits_distinctly_from_a_failed_run(monkeypatch, capsys):
    """A misconfigured unit needs an operator edit; restarting it forever would hide that."""
    import secp_api.config as config

    monkeypatch.setattr(config, "get_settings", lambda: _Settings())
    code = main(["--role", "ordinary", "--task-queue", "wrong"])
    assert code == EXIT_MISCONFIGURED
    assert "does_not_match_configured_ordinary_queue" in capsys.readouterr().err


def test_the_agreed_configuration_reaches_the_worker(monkeypatch):
    """The happy path actually starts the worker rather than returning success without doing so."""
    import secp_api.config as config
    import secp_worker.main as worker_main

    started: list[str] = []
    monkeypatch.setattr(config, "get_settings", lambda: _Settings())
    monkeypatch.setattr(worker_main, "main", lambda: started.append("ran"))
    assert main(["--role", "ordinary", "--task-queue", "secp-orchestration"]) == 0
    assert started == ["ran"]


# === it is declared as a console script ==========================================================


def test_the_console_script_is_declared_and_points_at_this_module():
    """The installer refuses `installer_worker_runtime_absent` without it, and the declaration is
    the only thing that produces the file."""
    import pathlib
    import tomllib

    root = pathlib.Path(__file__).resolve().parents[3]
    data = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    scripts = data["project"]["scripts"]
    assert scripts["secp-worker"] == "secp_worker.cli:main"


def test_the_declared_entry_point_matches_what_the_unit_runs():
    """The unit's ExecStart basename and the console-script name must be the same string, or the
    installer installs a unit pointing at a file the package never creates."""
    import pathlib
    import re

    root = pathlib.Path(__file__).resolve().parents[3]
    adapters = (
        root / "apps" / "management" / "secp_management" / "worker_service_adapters.py"
    ).read_text(encoding="utf-8")
    match = re.search(r'return f"\{[^}]+\}/bin/(?P<name>[A-Za-z0-9_-]+)"', adapters)
    assert match is not None, "the worker executable path is no longer a recognizable f-string"
    assert match.group("name") == "secp-worker"
