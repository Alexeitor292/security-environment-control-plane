"""Operator authentication for secpctl controller commands (SECP-PR5H-B1, Phase 4).

Proves the sealed default fails closed; the access token is fully redacted (repr / pickle / str) and
exposed only as a Bearer header; the token-file content validation (bounded, one-newline trim,
grammar) is exact; and — on POSIX — the protected file provider refuses a non-0600 mode, a symlink,
and a group/other-writable parent directory. Tests never place a real-looking token in source; the
CLI/client tests inject a fake provider.
"""

from __future__ import annotations

import os
import pickle

import pytest
from secp_management.operator_auth import (
    OperatorAccessToken,
    OperatorAuthError,
    ProtectedTokenFileProvider,
    SealedOperatorAccessTokenProvider,
    parse_operator_token_bytes,
)

_TOKEN = "x" * 40  # a synthetic, obviously-fake bounded token used only in tests


def test_sealed_default_fails_closed():
    with pytest.raises(OperatorAuthError) as ei:
        SealedOperatorAccessTokenProvider().access_token()
    assert ei.value.reason_code == "secpctl_operator_auth_unavailable"


def test_access_token_is_redacted_and_non_serializable():
    tok = OperatorAccessToken(_TOKEN)
    assert tok.authorization_header() == f"Bearer {_TOKEN}"
    assert _TOKEN not in repr(tok) and "redacted" in repr(tok)
    with pytest.raises(OperatorAuthError):
        pickle.dumps(tok)


def test_access_token_rejects_a_malformed_grammar():
    for bad in ("short", "has space token here padding padding", "x\ty" * 10):
        with pytest.raises(OperatorAuthError) as ei:
            OperatorAccessToken(bad)
        assert ei.value.reason_code == "secpctl_operator_token_invalid"


def test_parse_trims_exactly_one_newline():
    assert parse_operator_token_bytes((_TOKEN + "\n").encode()) == _TOKEN
    # a second trailing newline is part of the (now-invalid) token -> refused, not silently trimmed
    with pytest.raises(OperatorAuthError):
        parse_operator_token_bytes((_TOKEN + "\n\n").encode())


@pytest.mark.parametrize(
    "raw",
    [b"", b"short\n", b"x" * (8192 + 2), ("a b" + "c" * 40).encode(), (_TOKEN + "\x00").encode()],
)
def test_parse_rejects_empty_oversized_or_control(raw):
    with pytest.raises(OperatorAuthError) as ei:
        parse_operator_token_bytes(raw)
    assert ei.value.reason_code == "secpctl_operator_token_invalid"


def test_provider_rejects_a_non_absolute_path():
    with pytest.raises(OperatorAuthError) as ei:
        ProtectedTokenFileProvider("relative/token")
    assert ei.value.reason_code == "secpctl_operator_token_invalid"


# --- POSIX file-security (skipped off-POSIX; runs on the Linux CI shards) -------------------------

_posix = pytest.mark.skipif(os.name != "posix", reason="operator token-file security is POSIX-only")


@_posix
def test_a_protected_0600_token_file_reads(tmp_path):
    path = tmp_path / "operator-token"
    path.write_text(_TOKEN + "\n", encoding="utf-8")
    os.chmod(path, 0o600)
    os.chmod(tmp_path, 0o700)
    tok = ProtectedTokenFileProvider(str(path)).access_token()
    assert tok.authorization_header() == f"Bearer {_TOKEN}"


@_posix
def test_a_group_readable_token_file_is_unsafe(tmp_path):
    path = tmp_path / "operator-token"
    path.write_text(_TOKEN, encoding="utf-8")
    os.chmod(path, 0o640)  # not 0600
    os.chmod(tmp_path, 0o700)
    with pytest.raises(OperatorAuthError) as ei:
        ProtectedTokenFileProvider(str(path)).access_token()
    assert ei.value.reason_code == "secpctl_operator_token_unsafe"


@_posix
def test_a_symlinked_token_file_is_unsafe(tmp_path):
    real = tmp_path / "real-token"
    real.write_text(_TOKEN, encoding="utf-8")
    os.chmod(real, 0o600)
    link = tmp_path / "operator-token"
    os.symlink(real, link)
    os.chmod(tmp_path, 0o700)
    with pytest.raises(OperatorAuthError) as ei:
        ProtectedTokenFileProvider(str(link)).access_token()
    assert ei.value.reason_code == "secpctl_operator_token_unsafe"


@_posix
def test_a_group_writable_parent_is_unsafe(tmp_path):
    parent = tmp_path / "loose"
    parent.mkdir()
    path = parent / "operator-token"
    path.write_text(_TOKEN, encoding="utf-8")
    os.chmod(path, 0o600)
    os.chmod(parent, 0o777)  # group/other-writable parent
    with pytest.raises(OperatorAuthError) as ei:
        ProtectedTokenFileProvider(str(path)).access_token()
    assert ei.value.reason_code == "secpctl_operator_token_unsafe"
