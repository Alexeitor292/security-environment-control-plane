"""Write-once guard for the durable controller-identity activation receipt (SECP-PR5H-B2 C3).

The ``controller_identity_activation_receipt`` table is APPEND-ONLY / WRITE-ONCE: the activation
one-shot is the sole trusted WRITER, and it only ever INSERTs (``session.add``) and SELECTs a
receipt. Exactly TWO other modules may reference the model at all, both fixed READ-ONLY observation
surfaces from clean-room review 4803080223 (SECP-PR5H-B2 2b-3c-c):

* ``observe_controller_finalization_once`` (R1/R3) — SELECTs the durable activation generation and
  re-verifies receipt/identity coherence;
* ``signer_readiness`` (R4) — SELECTs the durable activation generation for the runtime readiness
  surface the root installer's management observer consumes.

Both are separately proven here to construct, insert, update and delete nothing. Nothing else in the
API production surface may reference the model, and even the trusted writer must never UPDATE or
DELETE it. These are guards, not behaviour: a future refactor cannot silently turn the byte-frozen
replay receipt into mutable state (which would let a replay disagree with what committed).

Methodology: AST over the production source (never a blind substring scan) so docstrings/prose that
merely DISCUSS the receipt never trip the guard.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
API_PKG = REPO / "apps" / "api" / "secp_api"

MODEL = "ControllerIdentityActivationReceipt"
DEFINITION = API_PKG / "controller_identity_models.py"
ONE_SHOT = API_PKG / "activate_controller_identity_once.py"
#: the ONLY other permitted referrers, both fixed READ-ONLY observation surfaces: the finalization
#: DB-state one-shot (R1/R3) and the enrollment-signer runtime readiness surface (R4).
READ_ONLY_OBSERVER = API_PKG / "observe_controller_finalization_once.py"
READ_ONLY_READINESS = API_PKG / "signer_readiness.py"
READ_ONLY_REFERRERS = (READ_ONLY_OBSERVER, READ_ONLY_READINESS)


def _referenced_identifiers(path: Path) -> set[str]:
    """Identifiers a module DEFINES or USES as code: class/function definitions, imported names, and
    bare name references. Deliberately excludes string literals so ``__all__`` entries and
    docstrings that merely mention a symbol do not count as a reference."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            names.add(node.id)
        elif isinstance(node, ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef):
            names.add(node.name)
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                names.add(alias.asname or alias.name)
    return names


def test_only_the_definition_the_writer_and_the_read_only_observers_reference_the_model() -> None:
    referencing = {path for path in API_PKG.rglob("*.py") if MODEL in _referenced_identifiers(path)}
    assert referencing == {DEFINITION, ONE_SHOT, *READ_ONLY_REFERRERS}, sorted(
        str(p.relative_to(REPO)) for p in referencing
    )


@pytest.mark.parametrize("module", READ_ONLY_REFERRERS, ids=lambda p: p.stem)
def test_the_read_only_referrers_never_construct_or_mutate_a_receipt(module: Path) -> None:
    """Every permitted non-writer referrer is a pure READER: it never constructs a receipt row,
    never stages one on a session, and issues no update/delete/commit/driver-level statement
    anywhere. Its only relationship to the write-once table is SELECT."""
    tree = ast.parse(module.read_text(encoding="utf-8"))
    called: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                assert node.func.id != MODEL, "a reader must never construct a receipt row"
                called.add(node.func.id)
            elif isinstance(node.func, ast.Attribute):
                called.add(node.func.attr)
    assert not (
        called
        & {
            "add",
            "add_all",
            "merge",
            "delete",
            "update",
            "commit",
            "flush",
            "begin",
            "exec_driver_sql",
        }
    ), sorted(called)


def test_the_one_shot_never_updates_or_deletes_a_receipt() -> None:
    """The sole trusted writer makes no bulk-DML mutation and no ``.delete``/``.update`` call — it
    only reads and inserts. (A SQLAlchemy row DELETE/UPDATE would surface as such a call.)"""
    tree = ast.parse(ONE_SHOT.read_text(encoding="utf-8"))
    called = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Name):
                called.add(func.id)
            elif isinstance(func, ast.Attribute):
                called.add(func.attr)
    assert "delete" not in called, "the write-once receipt one-shot must never delete"
    assert "update" not in called, "the write-once receipt one-shot must never bulk-update"


def test_every_receipt_construction_is_an_insert_via_session_add() -> None:
    """Every ``ControllerIdentityActivationReceipt(...)`` construction in the one-shot is passed
    directly to ``session.add(...)`` — it is only ever INSERTed, never staged for mutation."""
    tree = ast.parse(ONE_SHOT.read_text(encoding="utf-8"))
    constructions = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == MODEL
    ]
    add_args: list[ast.AST] = []
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "add"
        ):
            add_args.extend(node.args)
    assert constructions, "expected at least one receipt INSERT in the one-shot"
    for construction in constructions:
        assert construction in add_args, "a receipt was constructed but not INSERTed via .add"
