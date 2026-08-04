"""Two guards over the contract itself: where its vocabulary comes from, and when it may ship.

BOTH ARE TRIGGERS THAT MUST FIRE ON THEIR OWN
---------------------------------------------
Neither property is one a person will remember to check. The first is invisible until a vocabulary
drifts; the second is a decision deferred to "before we publish", which is precisely the kind of
trigger that never fires because it lands in someone's third priority in a commit about something
else. So both are enforced mechanically here.
"""

from __future__ import annotations

import ast
import pathlib

import pytest
from secp_acceptance.evidence import ACCEPTANCE_EVIDENCE_SCHEMA
from secp_acceptance.run import EVIDENCE_FILENAME

#: The outcome names :mod:`secp_acceptance.provenance` re-exports under ``PROVENANCE_*`` aliases.
#: They must ARRIVE FROM the contract, not be restated beside it.
_ALIASED_OUTCOMES = ("OUTCOME_OBSERVED", "OUTCOME_REFUSED", "OUTCOME_UNPROVEN")


def _repo_root() -> pathlib.Path:
    for parent in pathlib.Path(__file__).resolve().parents:
        if (parent / "pyproject.toml").is_file() and (parent / "infra").is_dir():
            return parent
    raise AssertionError("repository root not found from the test file location")


def _package_root() -> pathlib.Path:
    return pathlib.Path(__file__).resolve().parents[1] / "secp_acceptance"


# ------------------------------------------------------- the vocabulary arrives from the contract


def _imported_from_reasons(tree: ast.Module) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == "secp_acceptance.reasons":
            names.update(alias.name for alias in node.names)
    return names


def _module_level_assignments(tree: ast.Module) -> set[str]:
    return {
        target.id
        for node in tree.body
        if isinstance(node, ast.Assign)
        for target in node.targets
        if isinstance(target, ast.Name)
    }


def test_the_provenance_aliases_are_imported_not_restated():
    """``PROVENANCE_*`` aliases the contract's outcome vocabulary. It must IMPORT it.

    WHY AN AST CHECK AND NOT AN EQUALITY OR AN IDENTITY ASSERTION
    ------------------------------------------------------------
    ``assert PROVENANCE_OBSERVED == OUTCOME_OBSERVED`` is a tautology once both are the same
    literal, and ``is`` is no better: CPython interns short strings, so
    ``PROVENANCE_OBSERVED is OUTCOME_OBSERVED`` succeeds even when one side is a locally restated
    ``"observed"`` shadowing the import. acc-B-enrollment hit exactly that — a mutant replacing an
    entire import block with local literals SURVIVED an identity assertion written to catch it.

    Where the property is actually decidable is the import graph, so that is what is checked. If the
    contract ever renames an outcome, an importing module fails loudly at import; a module carrying
    its own literals would silently keep the old value and agree with itself forever.
    """
    tree = ast.parse((_package_root() / "provenance.py").read_text(encoding="utf-8"))
    imported = _imported_from_reasons(tree)

    for name in _ALIASED_OUTCOMES:
        assert name in imported, (
            f"provenance.py no longer imports {name} from secp_acceptance.reasons. If it now "
            f"restates the literal, the two vocabularies can drift apart while every equality and "
            f"identity assertion between them still passes."
        )
    assigned = _module_level_assignments(tree)
    for name in _ALIASED_OUTCOMES:
        assert name not in assigned, (
            f"provenance.py assigns {name} at module level, shadowing the imported contract value"
        )


def test_the_import_reader_can_actually_fail():
    """CONTROL. A reader that found nothing would make the assertions above vacuous."""
    restated = ast.parse('OUTCOME_OBSERVED = "observed"\n')
    assert _imported_from_reasons(restated) == set()
    assert "OUTCOME_OBSERVED" in _module_level_assignments(restated)

    real = ast.parse("from secp_acceptance.reasons import OUTCOME_OBSERVED\n")
    assert "OUTCOME_OBSERVED" in _imported_from_reasons(real)
    assert _module_level_assignments(real) == set()


# ------------------------------------------------------- the schema bump has a mechanical trigger


def _workflow_files() -> dict[str, str]:
    workflows = _repo_root() / ".github" / "workflows"
    return {path.name: path.read_text(encoding="utf-8") for path in sorted(workflows.glob("*.yml"))}


def test_the_evidence_document_is_not_published_while_the_schema_is_still_v1():
    """The schema bump must not be a trigger somebody remembers — it must be one that fires.

    THE DEFERRED DECISION THIS ENFORCES
    -----------------------------------
    ``observed_cause`` and ``provenance`` were both added to the document without bumping
    ``ACCEPTANCE_EVIDENCE_SCHEMA``. That was the right call at the time and is recorded as such: the
    fields are optional so older documents still load, nothing has ever persisted a document, and
    there are no readers outside this repo — while four streams referencing the version string were
    mid-flight, so a bump was four-way churn for no protective value.

    But the version is bound into :meth:`AcceptanceEvidence.digest`, and the docstring promises that
    two runs observing the same things produce the same digest. Across those commits they do not,
    and nothing in the document explains why. That incoherence is harmless only while the document
    stays inside the run that produced it.

    So: the moment anything moves it OUT — an artifact upload, a PR attachment, a release asset —
    the version must have been bumped. Naming the file in a workflow is the earliest mechanical
    signal of that intent, and this is where whoever writes that step is told.
    """
    still_v1 = ACCEPTANCE_EVIDENCE_SCHEMA.endswith("/v1")
    publishing = {
        name: text for name, text in _workflow_files().items() if EVIDENCE_FILENAME in text
    }
    if not still_v1:
        pytest.skip("the schema has been bumped; this trigger has served its purpose")
    assert publishing == {}, (
        f"{sorted(publishing)} reference {EVIDENCE_FILENAME}, which means the evidence document is "
        f"leaving the run that produced it — but ACCEPTANCE_EVIDENCE_SCHEMA is still "
        f"{ACCEPTANCE_EVIDENCE_SCHEMA!r}.\n\n"
        f"Two optional fields (observed_cause, provenance) were added under /v1 deliberately, "
        f"while no document was ever published and four streams referenced the version string. "
        f"That trade expires here: the version is bound into digest(), so two runs that observed "
        f"the same things produce different digests across those commits with nothing in the "
        f"document saying why. Bump the schema in the same commit that publishes it."
    )


def test_the_publication_scan_reads_real_workflows():
    """CONTROL, and a premise guard. A scan that read no files would pass the test above forever."""
    workflows = _workflow_files()
    assert workflows, "no workflow files were read; the publication scan is not usable"
    assert "acceptance.yml" in workflows
    # ...and it must be capable of matching, or the assertion above is satisfied by a broken needle
    assert EVIDENCE_FILENAME
    assert any("upload-artifact" in text for text in workflows.values()), (
        "no workflow uploads any artifact, so this scan has never been exercised against the "
        "shape it is looking for"
    )
