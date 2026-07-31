"""The operator CLI SURFACE: the production entrypoint, its grammar, and its output (WS-E).

The report builders in ``verify.py`` are pure and well covered. What was NOT covered is the thin
layer an operator actually touches. ``run`` was exercised by several modules; :func:`main` — the
``python -m secp_operator_deployment`` entrypoint that ``__main__`` calls — was exercised by none,
so the stdout rendering, the ``--json`` branch and the exit-code return were unpinned.

The load-bearing test here is :func:`test_no_command_accepts_a_path_or_queue_argument`. A path
argument is what would let a report describe, entirely truthfully, a tree that is NOT the one that
would run — and such a report is indistinguishable from one about the tree that would. The existing
suite pinned the absence of ``verify --profile`` but never the absence of a path on ``provenance``,
so that property was documented in two docstrings and enforced nowhere. The ``queue`` command
(WS-E) extends the same property to a queue NAME, which is its path-equivalent.

Nothing in this module builds a composition aggregate, constructs a ``Worker``, calls
``run_plan_generation``, resolves a credential, or contacts any infrastructure. The provenance
tests below DO run the real production path, which reads the installed package directory read-only;
they assert it stays bounded rather than asserting a platform-specific outcome.
"""

from __future__ import annotations

import json

import pytest
from _deploy_support import host_evidence, valid_expected, valid_profile
from secp_operator_deployment.cli import build_parser, main
from secp_operator_deployment.verify import (
    PROVENANCE_EXIT_CODES,
    STATUS_EXIT_CODES,
    classify_reason_code,
)

# The queue NAMES are profile values and must never reach an operator's terminal in either form.
_QUEUE_NAMES = ("secp-orchestration", "secp-controlled-live-v1")


@pytest.fixture
def prepared_context(monkeypatch):
    """Point the PRODUCTION context loader at a prepared, fully-agreeing deployment.

    ``main`` takes no dependency-injection seam — it always calls the loader — so this is the only
    way to drive its rendering deterministically.
    """
    from secp_operator_deployment import production_context

    ctx = production_context.VerifyContext(
        profile=valid_profile(),
        profile_load_reason=None,
        expected=valid_expected(),
        installed_trust_ok=True,
        installed_trust_reason=None,
        attestation=None,
        host_observation=host_evidence(),
    )
    monkeypatch.setattr(production_context, "load_verify_context", lambda: ctx)
    return ctx


# --------------------------------------------------------------------------- the grammar


@pytest.mark.parametrize(
    "argv",
    [
        # provenance: the property the brief pins and nothing enforced.
        ["provenance", "--package-dir", "/tmp/x"],
        ["provenance", "--path", "/tmp/x"],
        ["provenance", "--dir", "/tmp/x"],
        ["provenance", "--package", "/tmp/x"],
        ["provenance", "/tmp/x"],
        # verify: --profile was already pinned elsewhere; the rest were not.
        ["verify", "--profile", "/tmp/x.json"],
        ["verify", "--package-dir", "/tmp/x"],
        ["verify", "--expected", "/tmp/x.json"],
        ["verify", "/tmp/x"],
        # queue (WS-E): a queue NAME is the path-equivalent here — naming one would let the report
        # describe a queue that is not the one the deployment would actually use.
        ["queue", "--queue", "some-queue"],
        ["queue", "--task-queue", "some-queue"],
        ["queue", "--profile", "/tmp/x.json"],
        ["queue", "/tmp/x"],
    ],
    ids=lambda a: " ".join(a),
)
def test_no_command_accepts_a_path_or_queue_argument(argv, capsys):
    """A truthful report about the WRONG tree carries the same authority as one about the right
    tree. The only defence is that no path can be named."""
    with pytest.raises(SystemExit):
        build_parser().parse_args(argv)
    capsys.readouterr()  # argparse writes usage to stderr; keep the run quiet


@pytest.mark.parametrize("command", ["verify", "provenance", "queue"])
def test_each_command_exposes_exactly_one_optional_flag(command):
    """``--json`` and nothing else — no path, no host, no override, no gate."""
    parsed = vars(build_parser().parse_args([command]))
    assert set(parsed) == {"command", "json"}
    assert parsed["command"] == command
    assert parsed["json"] is False
    assert vars(build_parser().parse_args([command, "--json"]))["json"] is True


def test_no_third_command_is_reachable():
    for argv in (["activate"], ["install"], ["start"], ["apply"], ["destroy"], ["enroll"]):
        with pytest.raises(SystemExit):
            build_parser().parse_args(argv)


# --------------------------------------------------------------------------- main() rendering


def test_main_json_is_one_deterministic_line_and_returns_the_report_exit_code(
    prepared_context, capsys
):
    code = main(["verify", "--json"])
    out = capsys.readouterr().out

    assert out.endswith("\n")
    assert out.count("\n") == 1, "the JSON report must be exactly one line"
    payload = json.loads(out)
    assert payload["phase"] == "verify"
    assert payload["status"] == "sealed_prepared"
    # The exact serialisation the entrypoint promises: sorted keys, no incidental whitespace.
    assert out == json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n"
    # The returned code is the report's own, not a separately derived one.
    assert code == payload["exit_code"] == STATUS_EXIT_CODES[payload["status"]] == 0


def test_main_default_output_is_one_bounded_summary_line(prepared_context, capsys):
    code = main(["verify"])
    out = capsys.readouterr().out
    assert out == "[verify] exit=0 status=sealed_prepared\n"
    assert code == 0


@pytest.mark.parametrize("argv", [["verify", "--json"], ["verify"]])
def test_main_never_emits_a_queue_name_in_either_output_form(prepared_context, argv, capsys):
    main(argv)
    out = capsys.readouterr().out
    for name in _QUEUE_NAMES:
        assert name not in out, f"{name} leaked into operator output via {argv}"


def test_main_reports_a_blocking_prerequisite_without_raising(monkeypatch, capsys):
    """The unhappy path renders too — a refusal must be a report, never a traceback."""
    from secp_operator_deployment import production_context

    ctx = production_context.VerifyContext(
        profile=None,
        profile_load_reason=None,
        expected=None,
        installed_trust_ok=False,
        installed_trust_reason=None,
        attestation=None,
        host_observation=None,
    )
    monkeypatch.setattr(production_context, "load_verify_context", lambda: ctx)

    code = main(["verify", "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert code == payload["exit_code"] != 0
    assert payload["prerequisites"]["next_blocking"] == "profile_installed"
    assert classify_reason_code(payload["prerequisites"]["next_blocking_reason_code"]) is not None


# --------------------------------------------------------------------------- the real production
# path (no injection): it must stay bounded on ANY platform rather than produce a specific verdict


def test_main_provenance_against_the_real_installed_tree_stays_bounded(capsys):
    """Runs the genuine production provenance path — the only test that does.

    The verdict is platform-dependent (the trusted directory-fd walk refuses off POSIX-root), so
    this pins the SHAPE: a catalogued status, a matching exit code, a classified reason code, and
    the declared absence of effects.
    """
    code = main(["provenance", "--json"])
    payload = json.loads(capsys.readouterr().out)

    assert payload["phase"] == "provenance"
    assert payload["status"] in PROVENANCE_EXIT_CODES
    assert code == payload["exit_code"] == PROVENANCE_EXIT_CODES[payload["status"]]

    for section in ("source_aggregate", "installed_aggregate"):
        reason = payload[section].get("reason_code")
        if reason is not None:
            assert classify_reason_code(reason) is not None, f"{section} -> {reason}"

    assert payload["effects_of_this_provenance_check"] == {
        "worker_constructed": False,
        "workflow_submitted": False,
        "run_plan_generation_called": False,
        "secret_resolver_constructed": False,
        "external_contact_performed": False,
        "host_mutated": False,
    }


def test_main_provenance_is_byte_identical_across_runs(capsys):
    """Observed, not merely declared: a read-only check that changed something would drift."""
    main(["provenance", "--json"])
    first = capsys.readouterr().out
    main(["provenance", "--json"])
    second = capsys.readouterr().out
    assert first == second


def test_the_real_provenance_path_reports_the_covered_module_count(capsys):
    """The count is what makes the aggregate comparable to a signed release."""
    from secp_operator_deployment.manifest import COVERED_MODULES

    main(["provenance", "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert payload["package_artifact"]["covered_module_count"] == len(COVERED_MODULES)


# --------------------------------------------------------------------------- the no-effect claim,
# OBSERVED rather than declared


def test_running_both_commands_leaves_the_installed_package_byte_identical(
    prepared_context, capsys
):
    """``host_mutated: False`` is a hardcoded dict value — the builder asserts its own innocence.

    This is the half that cannot be faked: snapshot the installed package before running BOTH
    production commands and after, and require the aggregate digest and every covered module's
    size and mtime to be unchanged. A command that wrote anything into the tree it reports on
    would fail here regardless of what its effects section claims.
    """
    import pathlib

    from secp_operator_deployment import package_implementation_digest
    from secp_operator_deployment.manifest import COVERED_MODULES
    from secp_operator_deployment.production_context import _installed_package_dir

    pkg = pathlib.Path(_installed_package_dir())

    def snapshot() -> tuple:
        rows = []
        for name in sorted(COVERED_MODULES):
            st = (pkg / name).stat()
            rows.append((name, st.st_size, st.st_mtime_ns))
        return (package_implementation_digest(), tuple(rows))

    before = snapshot()
    main(["verify", "--json"])
    main(["provenance", "--json"])
    capsys.readouterr()
    after = snapshot()

    assert after == before, "a read-only command modified the package it reports on"
