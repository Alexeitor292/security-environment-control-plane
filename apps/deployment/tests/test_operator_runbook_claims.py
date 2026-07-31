"""The operator runbook's checkable claims (WS-E).

Most of a runbook is prose and cannot be tested. A few of its claims are not prose: when it tells
an operator *which command to run*, that is a factual assertion about another package's CLI, and it
is exactly the kind of claim that rots silently — the command gets renamed, the runbook keeps
naming the old one, and the operator meets an argparse error in the middle of a supervised
installation sequence.

So the command names are pinned three ways, and a drift in any direction fails:

* the set the runbook NAMES,
* the set ``secp_commissioning`` actually EXPOSES,
* the set ``secp_operator_deployment`` actually exposes.

Two of the runbook's *descriptive* claims are pinned as well, because they are **safety defaults**
of another package and a runbook that misstated them would be an operator-facing defect rather than
a docs nit: that `install-prepared` is dry-run by default, and that nothing in `secp_commissioning`
can enable or start the operator unit. Neither pin duplicates `secp_commissioning`'s own suite —
that suite tests its *behaviour*; these assert the *declared surface* my runbook describes, by
introspection and by absence, so the two cannot drift apart silently.

Still narrow, and the remaining gaps stated rather than implied. It does not check the rest of the
runbook's descriptions, its step ordering, its JSON examples, or the dry-run *semantics* (that the
gate actually precedes the writes) — that last one is `secp_commissioning`'s to test, and
reasserting it here would be the duplication this file exists to avoid. Those remain unpoliced
prose, and saying so is cheaper than implying a coverage that does not exist.

One further limit on the zero-match pin, stated because it is the sort of thing that decays into a
false alarm: `secp_commissioning` delegates service observation to an INJECTED
`ServiceStateAdapter`, so "no enable path here" is necessary but not sufficient on its own. The
real adapter lives in this package, and its inability to mutate is pinned by
``test_operator_adapter_mutation_surface.py`` — structurally, via the AST of every ``runner.run``
call site and the adapters' exact public surface. Together they cover the claim; either alone does
not.

That linkage previously named the two SUBSTRING guards
(``test_adapters_expose_no_mutation_verb`` and ``test_adapter_invokes_no_mutation_subcommand``),
which was an over-claim: both match only a double-quoted verb followed by a comma, so a constructed
verb (``"en" + "able"``) passed them both. They remain as cheap textual smoke checks; the
structural module is what actually carries the half of this linkage that is not about
``secp_commissioning``.

Nothing here runs a command; parsers are built, signatures introspected, sources read.
"""

from __future__ import annotations

import argparse
import pathlib
import re

_RUNBOOK = (
    pathlib.Path(__file__).resolve().parents[3] / "docs" / "runbooks" / "operator-productization.md"
)

# The install ACTUATION surface the runbook points an operator at (§1.1). Install actuation lives
# in secp_commissioning, never in this package — see the section for why the split exists.
_COMMISSIONING_COMMANDS = frozenset(
    {
        "inspect",
        "plan",
        "render",
        "verify",
        "install-prepared",
        "status",
        "rollback-prepared",
        "evidence",
    }
)

# The three read-only commands this package exposes.
_DEPLOYMENT_COMMANDS = frozenset({"verify", "provenance", "queue"})


def _subcommands(parser: argparse.ArgumentParser) -> set[str]:
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            return set(action.choices)
    raise AssertionError("parser exposes no subcommands")


def _runbook() -> str:
    return _RUNBOOK.read_text(encoding="utf-8")


def _section_11_command_cells() -> set[str]:
    """The commands named in the FIRST COLUMN of the §1.1 actuation table.

    Scoped to that table on purpose. An earlier version of this guard asked whether the backticked
    command appeared anywhere in the document, which is blind: ``verify`` occurs eleven times in
    §2/§3/§4 about THIS package, and ``plan`` collides with "a non-destroy `plan`" in §5 about
    OpenTofu grammar. Both rows could be deleted from the operator-facing table and the guard
    stayed green — the exact rot it exists to catch.
    """
    text = _runbook()
    start = text.index("### 1.1")
    end = text.index("\n## ", start)  # the next top-level section
    cells: set[str] = set()
    for line in text[start:end].splitlines():
        match = re.match(r"^\|\s*`([a-z-]+)`\s*\|", line)
        if match:
            cells.add(match.group(1))
    return cells


def test_the_runbook_exists_where_this_guard_expects_it():
    assert _RUNBOOK.is_file(), _RUNBOOK


def test_every_commissioning_command_the_runbook_names_actually_exists():
    """The runbook sends an operator to these mid-installation. A renamed command would surface as
    an argparse error during a supervised sequence, which is the worst possible moment."""
    from secp_commissioning.cli import build_parser

    actual = _subcommands(build_parser())
    missing = sorted(_COMMISSIONING_COMMANDS - actual)
    assert not missing, f"the runbook names commissioning commands that do not exist: {missing}"


def test_the_runbook_names_the_whole_commissioning_surface_not_a_convenient_subset():
    """A partial table would read as complete. If a command is added there, it belongs here."""
    from secp_commissioning.cli import build_parser

    actual = _subcommands(build_parser())
    assert actual == set(_COMMISSIONING_COMMANDS), (
        "the commissioning command surface moved — update the runbook §1.1 table and this set"
    )


def test_the_section_11_table_names_every_actuation_command_and_no_others():
    """Equality against the §1.1 TABLE, not a substring search of the document.

    This is what makes deleting a row fail. The operator-facing actuation table is the thing an
    operator reads; a command missing from it is missing, however many times the word appears
    elsewhere in the runbook about something else entirely.
    """
    assert _section_11_command_cells() == set(_COMMISSIONING_COMMANDS)


def test_the_table_scoping_is_not_vacuous():
    """Guard the guard: if the section slice or the row regex stopped matching, the equality above
    would compare two empty-ish sets and pass. Pin that it really parses the table."""
    cells = _section_11_command_cells()
    assert len(cells) == 8, cells
    # And that the scoping genuinely excludes the rest of the document: `provenance` is discussed
    # at length in §4 but is NOT an actuation command, so it must not appear in the table cells.
    assert "provenance" not in cells
    assert "queue" not in cells


def test_the_runbook_points_at_the_actuation_package_by_name():
    """`There is no install command` must read as a design split, not a missing feature — which it
    only does if the runbook says where installation DOES happen."""
    text = _runbook()
    assert "python -m secp_commissioning" in text
    assert "pr5d-operator-deployment.md" in text


def test_the_runbook_names_exactly_this_packages_commands():
    from secp_operator_deployment.cli import build_parser

    assert _subcommands(build_parser()) == set(_DEPLOYMENT_COMMANDS)
    text = _runbook()
    for command in sorted(_DEPLOYMENT_COMMANDS):
        assert f"python -m secp_operator_deployment {command}" in text, command


# --------------------------------------------------------------------------- the safety defaults
#
# These two are the runbook's claims about ANOTHER package's safety posture. An operator believes
# "dry-run by default" without checking it, so it must not be able to rot silently.


def test_install_prepared_is_dry_run_by_default_as_the_runbook_claims():
    """Introspect the REAL signature — not a restatement of it.

    Scoped to the declared defaults. Whether the gate actually precedes the writes is
    ``secp_commissioning``'s behaviour to test, and reasserting it here would duplicate its suite.
    """
    import inspect

    from secp_commissioning.install import install_prepared

    params = inspect.signature(install_prepared).parameters
    for name in ("write", "confirm"):
        assert name in params, f"runbook §1.1 names --{name}, which no longer exists"
        assert params[name].default is False, (
            f"install_prepared({name}=...) no longer defaults to False — "
            "the runbook's dry-run-by-default claim is now wrong"
        )
        # Keyword-only: a positional caller cannot switch on writes by argument order.
        assert params[name].kind is inspect.Parameter.KEYWORD_ONLY, name


def _package_sources(pkg: pathlib.Path) -> list[pathlib.Path]:
    """Every ``.py`` under ``pkg`` at ANY depth. Recursive by construction — see
    :func:`test_the_enable_scan_reaches_into_subpackages` for the proof that it is."""
    return sorted(p for p in pkg.rglob("*.py") if "__pycache__" not in p.parts)


_ENABLE_MECHANISMS = (
    r"systemctl",  # the only binary that could enable a unit
    r"\.enable\(",
    r"\.start\(",  # NB: excludes `.startswith(` by the paren — there are real uses of that
    r"enable_unit",
    r"start_unit",
)


def test_secp_commissioning_contains_no_mechanism_to_enable_or_start_the_operator():
    """The runbook says the unit is installed **disabled**. That reads as a default something could
    later flip unless the stronger fact is pinned: there is no enable path to flip.

    RECURSIVE. It scanned ``glob("*.py")`` — top level only — and the package is flat today, so it
    reported green while covering everything. It would have stopped covering the moment anyone added
    a subdirectory: a ``secp_commissioning/adapters/systemd.py`` running
    ``systemctl enable`` sat entirely outside the scan and the suite stayed green. The guard's whole
    value is the completeness of "there is no enable path in this package", so a scan that silently
    narrows is worse than none.

    Known false-positive risk, recorded rather than hidden: ``\\.start\\(`` would also match a regex
    match object's ``.start()``. There are none today. If one appears, the fix is to narrow the
    pattern — never to delete the check.
    """
    import pathlib
    import re

    pkg = (
        pathlib.Path(__file__).resolve().parents[3]
        / "apps"
        / "commissioning"
        / "secp_commissioning"
    )
    sources = _package_sources(pkg)
    assert sources, f"no sources found under {pkg} — the check would vacuously pass"

    offenders: list[str] = []
    for source in sources:
        text = source.read_text(encoding="utf-8")
        for pattern in _ENABLE_MECHANISMS:
            if re.search(pattern, text):
                offenders.append(f"{source.name}: {pattern}")

    assert not offenders, (
        "secp_commissioning gained something that could enable or start the operator unit: "
        f"{offenders} — the runbook's 'installed disabled' claim is no longer structural"
    )


def test_the_enable_scan_reaches_into_subpackages(tmp_path):
    """Prove the scan's COVERAGE, not just its patterns.

    The previous version used non-recursive ``glob``. The package is flat, so it was green while
    covering everything — and would have gone on being green the moment a subdirectory appeared,
    which is the failure mode that matters. This builds the exact tree that defeated it and
    requires the scan to reach the nested file.
    """
    import re

    pkg = tmp_path / "secp_commissioning"
    (pkg / "adapters").mkdir(parents=True)
    (pkg / "__init__.py").write_text("", encoding="utf-8")
    (pkg / "adapters" / "systemd.py").write_text(
        'subprocess.run(["/usr/bin/systemctl", "enable", name])\ndef enable_unit(n): ...\n',
        encoding="utf-8",
    )

    sources = _package_sources(pkg)
    assert pkg / "adapters" / "systemd.py" in sources, "the scan does not reach subpackages"

    offenders = [
        f"{s.name}: {p}"
        for s in sources
        for p in _ENABLE_MECHANISMS
        if re.search(p, s.read_text(encoding="utf-8"))
    ]
    assert offenders, "a nested enable path went undetected"


def test_the_enable_detector_actually_detects():
    """Guard the guard. A zero-match assertion passes just as happily when the patterns are broken
    as when the property holds, so the detector is shown to fire on each mechanism it claims to
    catch — and to stay silent on the ``.startswith(`` uses that really exist."""
    import re

    for pattern, offending in (
        (r"systemctl", 'runner.run("/usr/bin/systemctl", ["enable", unit])'),
        (r"\.enable\(", "service.enable(unit)"),
        (r"\.start\(", "service.start(unit)"),
        (r"enable_unit", "enable_unit(name)"),
        (r"start_unit", "start_unit(name)"),
    ):
        assert pattern in _ENABLE_MECHANISMS, pattern
        assert re.search(pattern, offending), f"{pattern} failed to catch {offending!r}"

    # The real code is full of these; none may trip the check.
    benign = 'if not value.startswith("sha256:") and path.startswith("/"):'
    for pattern in _ENABLE_MECHANISMS:
        assert not re.search(pattern, benign), f"{pattern} false-positives on .startswith("


def test_the_runbook_never_advertises_a_command_that_would_activate():
    """The package's whole value is that it cannot activate. A runbook that names an `activate`,
    `apply`, `destroy` or `start` command — even to describe one — is where an operator would go
    looking for it."""
    text = _runbook()
    for forbidden in (
        "python -m secp_operator_deployment activate",
        "python -m secp_operator_deployment start",
        "python -m secp_operator_deployment apply",
        "python -m secp_operator_deployment destroy",
        "python -m secp_operator_deployment install",
    ):
        assert forbidden not in text, forbidden
