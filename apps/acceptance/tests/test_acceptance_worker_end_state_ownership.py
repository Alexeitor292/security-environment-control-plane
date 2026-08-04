"""The worker end-state gate's BLAST RADIUS — the one property of it `main` does not already own.

This file used to carry two acceptance findings (the supported production worker installation path
could not reach its own success state) and then, briefly, the regression pins for their closure.
Both are gone, and the reason is worth stating so nobody re-adds them.

WHY THERE IS ALMOST NOTHING LEFT HERE
-------------------------------------
`main` closed both findings in #68's review cycle AND landed its own proofs of the closure — proofs
that are strictly better than the ones this harness would carry, because they build the expectation
with the product's own ``_expected_worker(manifest)`` from a real signed manifest instead of a
hand-assembled ``_ExpectedWorker``. A second copy in the acceptance package would buy no coverage
and would create a second place to update. The program rule is: do not keep duplicate harnesses.

So each property is named here with its owner, and asserted nowhere in this package:

``apps/management/tests/test_real_observer_production.py``
    ``test_a_correctly_prepared_worker_host_PASSES_the_real_end_state_gate`` — drives the real
    ``RealManagementHostObserver`` over a prepared host and puts that observation in front of the
    real ``_worker_end_state_reason``, asserting the never-started posture is real
    (``operator_invocation_id == ""``), that the operator image was OBSERVED rather than defaulted,
    and that the gate returns ``None``. That single test owns the closure of BOTH findings.
    ``test_the_operator_image_is_refused_when_it_is_not_actually_loaded`` (runtime will not confirm
    the image), ``test_a_missing_release_record_refuses_rather_than_assuming_the_image`` (no record
    to read), ``test_an_empty_operator_image_can_never_satisfy_the_gate``,
    ``test_a_substituted_operator_image_is_refused``,
    ``test_a_record_naming_another_release_operator_image_is_a_MISMATCH_not_a_pass`` and
    ``test_worker_shipped_static_operator_unit_is_observed_prepared`` own the rest.

``apps/management/tests/test_management_generation.py``
    ``test_a_present_operator_without_a_monotonic_state_stamp_refuses`` and
    ``test_a_present_operator_with_a_nonnumeric_monotonic_stamp_refuses`` own the control that the
    generation check still bites — that accepting an empty ``InvocationID`` RELOCATED the operator's
    generation coverage onto ``operator_state_change_monotonic`` rather than removing it.
    ``test_a_running_operator_without_an_invocation_id_refuses`` owns the remaining case.

``apps/management/tests/test_queue_containment_verdict.py``
    Owns the whole three-valued containment verdict, including that ``unprovable`` is distinct from
    ``breached`` and that ``EXIT_CONTAINMENT_UNPROVABLE`` is never mistakable for success.

``tests/test_health_command_interpreter.py``
    Owns the worker health interpreter, which was the third finding.

WHAT IS LEFT, AND WHY IT IS NOT A DUPLICATE
-------------------------------------------
Nothing in `main` establishes HOW MANY code paths that gate governs. Every property above is a
statement about what the gate decides; the one below is a statement about who asks it. It is the
reason the findings mattered at all — a refusal here was never confined to a first install, it also
stopped ``adopt`` and made ``secpctl status worker`` report a drifted host. A fifth caller would
silently inherit every one of those properties, and would need reviewing against all of them.
"""

from __future__ import annotations

import inspect
import pathlib


def test_the_gate_governs_exactly_four_paths_and_they_are_the_ones_named():
    """``_worker_end_state_reason`` is the shared predicate behind FOUR engine paths.

    The four callers, identified by their enclosing function on the loaded module: the bootstrap
    write transaction's reobservation gate (``_prepare_gate``), the adoption admission check
    (``adopt``), the adoption transaction's final observation (``_adopt_transaction``), and
    ``secpctl status worker`` (``_worker_status``).

    Counted EXACTLY, not as a floor. A refactor that adds a caller must come here and state which
    path it added and that it reviewed the gate's refusals against it, rather than silently widening
    the blast radius; one that removes a caller must say where that path went.
    """
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


def test_the_owners_named_above_actually_exist():
    """NON-VACUITY for the docstring. That comment block is this file's real content — it is what
    justifies asserting nothing else here — so a named owner that has been renamed or deleted must
    fail loudly rather than leaving a paragraph pointing at nothing.

    Checked as literal text in the owning files, because the claim is "that test exists and covers
    this property", and importing the module would prove only that it loads.
    """
    here = pathlib.Path(__file__).resolve()
    root = next(
        p for p in here.parents if (p / "pyproject.toml").is_file() and (p / "infra").is_dir()
    )

    owners: dict[str, tuple[str, ...]] = {
        "apps/management/tests/test_real_observer_production.py": (
            "def test_a_correctly_prepared_worker_host_PASSES_the_real_end_state_gate(",
            "def test_the_operator_image_is_refused_when_it_is_not_actually_loaded(",
            "def test_a_missing_release_record_refuses_rather_than_assuming_the_image(",
            "def test_an_empty_operator_image_can_never_satisfy_the_gate(",
            "def test_worker_shipped_static_operator_unit_is_observed_prepared(",
        ),
        "apps/management/tests/test_management_generation.py": (
            "def test_a_present_operator_without_a_monotonic_state_stamp_refuses(",
            "def test_a_present_operator_with_a_nonnumeric_monotonic_stamp_refuses(",
        ),
        "apps/management/tests/test_queue_containment_verdict.py": (),
        "tests/test_health_command_interpreter.py": (),
    }
    for relative, functions in owners.items():
        path = root / relative
        assert path.is_file(), f"{relative} is named as an owner above but does not exist"
        source = path.read_text(encoding="utf-8")
        for function in functions:
            name = function.removeprefix("def ").removesuffix("(")
            assert function in source, (
                f"{relative} no longer defines {name}. The property it owns is then asserted "
                f"NOWHERE — either restore it there, or bring the assertion back into this package."
            )
