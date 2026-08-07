"""ADR-030 retired the execution seal CONSTANTS. It must not have touched the signed evidence.

`b1a_subprocess_sealed_activation` and `b1a_subprocess_sealed_executor` are required members of
:class:`BootstrapEvidence`, whose ``canonical()`` is a full ``model_dump()`` — so both sit inside
``digest()``, which carries an independently verified Ed25519 attestation. Removing them, renaming
them, or making them optional would change the canonical field set and invalidate the digest of
every evidence document already issued, with no migration path for documents already signed and
distributed.

So the ruling is: **retire the constants, preserve the schema.** The field names stay; what changes
is where their values come from and what they mean:

``old True``  the capability is globally sealed, therefore unauthorized execution is impossible
``new True``  the production capability may exist, but the unauthorized path was BEHAVIOURALLY
              exercised and stayed closed

That transition is monotonic — every historical ``True`` is still truthful under the new reading,
because a capability that could not exist could not be reached without authority either. This module
is what stops that ruling being a claim in prose.

``fixtures/pre_adr030_bootstrap_evidence.json`` was generated from the tree BEFORE the retirement
and is frozen. Regenerating it would defeat the entire point: it exists to be the independent second
source of truth that the current code is compared against, and a fixture regenerated from the code
it is meant to check proves only that the code agrees with itself.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import ValidationError
from secp_management.evidence import BootstrapEvidence, canonical_bytes

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "pre_adr030_bootstrap_evidence.json"

#: The four field names the signed document requires. Named here rather than derived from the model,
#: deliberately: deriving them would make this list agree with whatever the model currently says,
#: which is the thing under test.
COMPATIBILITY_FIELDS = (
    "operator_activation_sealed",
    "plan_only_process_sealed",
    "b1a_subprocess_sealed_activation",
    "b1a_subprocess_sealed_executor",
)


@pytest.fixture(scope="module")
def frozen() -> dict:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def reparsed(frozen: dict) -> BootstrapEvidence:
    return BootstrapEvidence(**frozen["canonical"])


# === 1-4: the document issued before the transition is still exactly itself ======================


def test_the_pre_transition_evidence_still_parses(frozen: dict) -> None:
    """A strict, frozen, ``extra='forbid'`` model: an added, removed or renamed field would raise
    here before any digest comparison could even run."""
    evidence = BootstrapEvidence(**frozen["canonical"])
    for field in COMPATIBILITY_FIELDS:
        assert hasattr(evidence, field), field


def test_the_canonical_bytes_are_byte_identical(frozen: dict, reparsed: BootstrapEvidence) -> None:
    """Byte identity, not equality of parsed dicts. The attestation is over BYTES, so a change in
    key order or number formatting breaks verification while leaving every value equal."""
    raw = canonical_bytes(reparsed)
    assert len(raw) == frozen["canonical_bytes_len"]
    assert hashlib.sha256(raw).hexdigest() == frozen["canonical_bytes_sha256_hex"]


def test_the_digest_is_unchanged(frozen: dict, reparsed: BootstrapEvidence) -> None:
    assert reparsed.digest() == frozen["digest"]
    assert reparsed.bootstrap_binding_digest() == frozen["bootstrap_binding_digest"]


def test_the_detached_attestation_still_verifies(frozen: dict, reparsed: BootstrapEvidence) -> None:
    """The signature was produced before the transition, over the bytes as they were then. It
    verifying now is the single strongest statement that nothing in the canonical form moved."""
    attestation = frozen["attestation"]
    public_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(attestation["public_key_hex"]))
    public_key.verify(bytes.fromhex(attestation["signature_hex"]), canonical_bytes(reparsed))


# === 5: today's behavioural re-observation agrees with what the old document recorded ============


def test_todays_observation_reproduces_the_recorded_seal_values(frozen: dict) -> None:
    """Re-observing now must AGREE with the pre-transition document, or old evidence would be
    rejected by a controller running current code.

    The values are the same; only their derivation changed, from reading a constant to exercising
    the unauthorized routes to the real executor. That agreement is the whole compatibility claim,
    and it holds only while those routes actually stay closed — which is the point. If someone
    opened the executor, this test fails rather than silently reinterpreting the old ``True``.
    """
    from secp_management.topology import read_seals

    recorded = frozen["canonical"]
    observed = read_seals()
    for field in COMPATIBILITY_FIELDS:
        assert getattr(observed, field) is recorded[field], field
    assert observed.safe is True


def test_the_two_retired_fields_are_no_longer_backed_by_a_constant() -> None:
    """The values agree; their SOURCE must not. If a constant were reintroduced to make the
    compatibility test pass, this is what would catch it."""
    from secp_worker.provisioning import activation as act
    from secp_worker.provisioning import process_executor as pe

    for module in (pe, act):
        assert not hasattr(module, "_B1A_SUBPROCESS_SEALED"), module.__name__


# === 6: breaking the compatibility surface is caught =============================================


@pytest.mark.parametrize("field", COMPATIBILITY_FIELDS)
def test_removing_a_compatibility_field_is_refused(frozen: dict, field: str) -> None:
    payload = dict(frozen["canonical"])
    payload.pop(field)
    with pytest.raises(ValidationError):
        BootstrapEvidence(**payload)


@pytest.mark.parametrize("field", COMPATIBILITY_FIELDS)
def test_renaming_a_compatibility_field_is_refused(frozen: dict, field: str) -> None:
    """``extra='forbid'`` makes a rename two failures at once: the old name is missing and the new
    one is unknown. Either alone would be enough; both is what makes a silent rename impossible."""
    payload = dict(frozen["canonical"])
    payload[f"{field}_v2"] = payload.pop(field)
    with pytest.raises(ValidationError):
        BootstrapEvidence(**payload)


@pytest.mark.parametrize("field", COMPATIBILITY_FIELDS)
def test_changing_a_compatibility_value_changes_the_digest(frozen: dict, field: str) -> None:
    """Each of the four is genuinely INSIDE the digest. Asserted per field rather than once: a
    field accidentally excluded from ``canonical()`` would leave the digest stable while its value
    moved, which is exactly the silent reinterpretation this ruling forbids."""
    payload = dict(frozen["canonical"])
    payload[field] = not payload[field]
    mutated = BootstrapEvidence(**payload)
    assert mutated.digest() != frozen["digest"], field
    assert canonical_bytes(mutated) != canonical_bytes(BootstrapEvidence(**frozen["canonical"]))


def test_a_mutated_document_fails_the_original_attestation(frozen: dict) -> None:
    """The end-to-end statement: tampering with a compatibility field invalidates the signature an
    operator would verify, rather than merely differing from a digest nobody re-checks."""
    payload = dict(frozen["canonical"])
    payload["b1a_subprocess_sealed_executor"] = not payload["b1a_subprocess_sealed_executor"]
    attestation = frozen["attestation"]
    public_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(attestation["public_key_hex"]))
    with pytest.raises(InvalidSignature):
        public_key.verify(
            bytes.fromhex(attestation["signature_hex"]),
            canonical_bytes(BootstrapEvidence(**payload)),
        )


def test_the_fixture_is_frozen_not_regenerated() -> None:
    """A fixture rebuilt from the code it checks proves only that the code agrees with itself.

    There is no generator wired into the test run, and the file carries its own warning. This pins
    that the fixture is READ here and nowhere written.
    """
    import ast

    # AST, not a substring scan: a list of forbidden writer names contains those names, so scanning
    # this file's own text for them trips on the guard itself. Asking whether any CALL in this
    # module is a write is the actual property.
    tree = ast.parse(Path(__file__).read_text(encoding="utf-8"))
    called = {ast.unparse(node.func) for node in ast.walk(tree) if isinstance(node, ast.Call)}
    for writer in called:
        assert not writer.endswith((".write_text", ".write_bytes", ".unlink", ".mkdir")), writer
        assert writer not in ("open", "json.dump"), writer
    assert "regenerat" in json.loads(FIXTURE.read_text(encoding="utf-8"))["_comment"].lower()
