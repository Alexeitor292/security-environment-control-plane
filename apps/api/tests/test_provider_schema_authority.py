"""Containment for the schema-attestation minting token.

A private token is only private if nothing shipped reaches it. The plan-only capability relies on
exactly this property, so this guard is written the same way rather than as a second mechanism.

The scan is phrased as an ALLOW-LIST of modules permitted to name the token, and the allow-list is
asserted to be what it is. When the attested schema-inspection producer is written it will be added
here in the same change that gives it the capability — which is the moment somebody has to look at
it.
"""

from __future__ import annotations

import pathlib

APPS = pathlib.Path(__file__).resolve().parents[3] / "apps"

TOKEN_NAME = "_SCHEMA_ATTESTATION_TOKEN"

#: Modules permitted to name the minting token. The defining module, and — when it exists — the
#: producer. Nothing else, and notably not the plan-document builder: the document READS a minted
#: attestation and must never be able to make one.
PERMITTED = frozenset({"apps/worker/secp_worker/provisioning/provider_schema_evidence.py"})


def _shipped_python_files() -> list[pathlib.Path]:
    """Every shipped module — tests excluded, since a test naming the token is the point."""
    return sorted(
        p
        for p in APPS.rglob("*.py")
        if "__pycache__" not in p.parts and "tests" not in p.parts and p.name != "conftest.py"
    )


def _rel(path: pathlib.Path) -> str:
    return path.relative_to(APPS.parents[0]).as_posix()


def test_no_shipped_module_outside_the_allow_list_names_the_minting_token():
    """Collects ALL offenders before asserting.

    Asserting inside the loop would report only the first file, and this repository has already been
    bitten by that: a guard that names one violating file reads as a complete list and is not one.
    """
    offenders = [
        _rel(path)
        for path in _shipped_python_files()
        if TOKEN_NAME in path.read_text(encoding="utf-8") and _rel(path) not in PERMITTED
    ]
    assert offenders == [], (
        f"these shipped modules reach the schema-attestation minting token: {offenders}. "
        "Only the attested schema-inspection producer may mint an attestation; add it to "
        "PERMITTED in the same change that gives it the capability."
    )


def test_the_allow_list_is_exactly_the_defining_module_today():
    """Pins the allow-list itself, so growing it is a reviewed edit rather than a quiet one."""
    assert PERMITTED == frozenset(
        {"apps/worker/secp_worker/provisioning/provider_schema_evidence.py"}
    )


def test_the_permitted_module_exists():
    """Keys on the file rather than the name: an allow-list entry pointing at a moved or renamed
    module silently permits nothing and hides that the guard stopped covering anything."""
    for entry in PERMITTED:
        assert (APPS.parents[0] / entry).is_file(), entry


def test_the_plan_document_builder_cannot_mint():
    """Stated as its own case because it is the module most likely to acquire the shortcut.

    ``build_plan_document`` reads an attestation and must never be able to make one — if it could,
    the gate would be back to a caller asserting the conclusion, just one call deeper.
    """
    plan_document = APPS / "worker" / "secp_worker" / "provisioning" / "plan_document.py"
    assert TOKEN_NAME not in plan_document.read_text(encoding="utf-8")
    assert "issue_provider_schema_attestation" not in plan_document.read_text(encoding="utf-8")
