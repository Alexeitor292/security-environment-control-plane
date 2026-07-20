"""Race-safe fixed-path evidence-key preparation semantics."""

from __future__ import annotations

import pytest
from secp_commissioning.runtime import InMemoryFilesystem
from secp_discovery_activation.evidence_key import (
    EvidenceKeyError,
    LocalEvidenceAuthenticator,
    local_evidence_trust_root,
    prepare_local_evidence_key,
)
from secp_discovery_activation.layout import PRODUCTION_LAYOUT

_ROOT = "/var/lib/secp/discovery-activation"
_KEY = PRODUCTION_LAYOUT.evidence_signing_key_path
_ANCHOR = PRODUCTION_LAYOUT.evidence_trust_anchor_path


def test_prepare_creates_exclusive_pair_then_adopts_same_identity() -> None:
    fs = InMemoryFilesystem()

    created = prepare_local_evidence_key(fs, write=True, confirm=True)
    adopted = prepare_local_evidence_key(fs, write=True, confirm=True)

    assert created.classification == "created"
    assert adopted.classification == "adopted"
    assert adopted.key_id == created.key_id
    assert fs.lstat(_KEY).mode == 0o600  # type: ignore[union-attr]
    assert fs.lstat(_ANCHOR).mode == 0o644  # type: ignore[union-attr]
    authenticator = LocalEvidenceAuthenticator(fs)
    assert authenticator.key_id() == created.key_id
    assert len(authenticator.attest(b"bounded evidence")) == 128
    first_binding = authenticator.bind_runtime_configuration(b"credential-bearing config one")
    assert first_binding.startswith("hmac-sha256:")
    assert len(first_binding) == 76
    assert first_binding == authenticator.bind_runtime_configuration(
        b"credential-bearing config one"
    )
    assert first_binding != authenticator.bind_runtime_configuration(
        b"credential-bearing config two"
    )
    assert local_evidence_trust_root(fs).anchors[0].key_id == created.key_id


def test_prepare_requires_both_write_gates_without_mutation() -> None:
    for write, confirm, reason in (
        (False, True, "write_authority_required"),
        (True, False, "explicit_confirmation_required"),
    ):
        fs = InMemoryFilesystem()
        with pytest.raises(EvidenceKeyError, match=reason):
            prepare_local_evidence_key(fs, write=write, confirm=confirm)
        assert _ROOT not in fs.paths()


def test_destination_appearance_race_is_never_overwritten_and_created_key_is_compensated() -> None:
    foreign = b"a" * 64

    class DestinationAppearanceFilesystem(InMemoryFilesystem):
        injected = False

        def exclusive_install(self, path, data, *, uid, gid, mode):  # noqa: ANN001, ANN201
            if path == _ANCHOR and not self.injected:
                self.injected = True
                self.seed_file(path, foreign, uid=0, gid=0, mode=0o644)
            return super().exclusive_install(path, data, uid=uid, gid=gid, mode=mode)

    fs = DestinationAppearanceFilesystem()
    with pytest.raises(EvidenceKeyError, match="evidence_key_install_failed"):
        prepare_local_evidence_key(fs, write=True, confirm=True)

    assert fs.lstat(_KEY) is None
    assert fs.safe_read(_ANCHOR, max_bytes=64, expected_uid=0) == foreign


def test_substituted_key_is_preserved_and_unproven_compensation_fails_closed() -> None:
    foreign = b"0" * 64

    class SubstitutionFilesystem(InMemoryFilesystem):
        injected = False

        def created_file_matches(self, receipt):  # noqa: ANN001, ANN201
            if receipt.path == _KEY and not self.injected:
                self.injected = True
                self.seed_file(_KEY, foreign, uid=0, gid=0, mode=0o600)
            return super().created_file_matches(receipt)

    fs = SubstitutionFilesystem()
    with pytest.raises(EvidenceKeyError, match="evidence_key_compensation_failed"):
        prepare_local_evidence_key(fs, write=True, confirm=True)

    assert fs.safe_read(_KEY, max_bytes=64, expected_uid=0) == foreign
    assert fs.lstat(_ANCHOR) is None


def test_incomplete_preexisting_pair_is_preserved_without_generation() -> None:
    fs = InMemoryFilesystem()
    fs.seed_dir(_ROOT, uid=0, gid=0, mode=0o700)
    fs.seed_file(_ANCHOR, b"f" * 64, uid=0, gid=0, mode=0o644)

    with pytest.raises(EvidenceKeyError, match="evidence_key_pair_incomplete"):
        prepare_local_evidence_key(fs, write=True, confirm=True)

    assert fs.lstat(_KEY) is None
    assert fs.safe_read(_ANCHOR, max_bytes=64, expected_uid=0) == b"f" * 64


def test_unsafe_root_created_by_makedir_race_is_reobserved_and_refused() -> None:
    class RootRaceFilesystem(InMemoryFilesystem):
        def makedir(self, path, *, uid, gid, mode):  # noqa: ANN001, ANN201
            if path == _ROOT:
                self.seed_dir(path, uid=1000, gid=1000, mode=0o777)
                return
            super().makedir(path, uid=uid, gid=gid, mode=mode)

    fs = RootRaceFilesystem()
    with pytest.raises(EvidenceKeyError, match="evidence_key_root_unsafe"):
        prepare_local_evidence_key(fs, write=True, confirm=True)

    assert fs.lstat(_ROOT).uid == 1000  # type: ignore[union-attr]
    assert fs.lstat(_KEY) is None
