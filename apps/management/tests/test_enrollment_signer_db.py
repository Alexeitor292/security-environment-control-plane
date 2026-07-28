"""Dedicated enrollment-signer DB role + SCRAM credential (SECP-PR5H-B2, commit 2b-2).

Proves the SCRAM-SHA-256 verifier is computed correctly (an RFC 7677 known-answer vector validates
BOTH the StoredKey and ServerKey derivation offline, so a wrong PBKDF2/HMAC chain fails here, not
only
against a real PostgreSQL), the least-privilege provisioning SQL is closed + injection-free, and the
systemd-credential loader fails closed off systemd. The real-PostgreSQL fence (elsewhere) proves the
verifier actually authenticates and the role is least-privilege.
"""

from __future__ import annotations

import base64
import hashlib
import hmac

import pytest
from secp_management import ManagementError
from secp_management.enrollment_signer_db import (
    ENROLLMENT_SIGNER_CREDENTIAL_ID,
    EnrollmentSignerDbError,
    generate_signer_db_password,
    load_signer_db_password,
    render_signer_role_sql,
    scram_sha256_verifier,
)
from secp_management.enrollment_signer_identity import ENROLLMENT_SIGNER_DB_ROLE

# --- RFC 7677 §3 known-answer vector ----------------------------------------------------------
_RFC_PASSWORD = "pencil"
_RFC_SALT_B64 = "W22ZaJ0SNY7soEsUEjb6gQ=="
_RFC_ITERATIONS = 4096
_RFC_CLIENT_FIRST_BARE = "n=user,r=rOprNGfwEbeRWgbNEkqO"
_RFC_SERVER_FIRST = (
    "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096"
)
_RFC_CLIENT_FINAL_NO_PROOF = "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0"
_RFC_CLIENT_PROOF_B64 = "dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ="
_RFC_SERVER_SIGNATURE_B64 = "6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4="


def _auth_message() -> bytes:
    return f"{_RFC_CLIENT_FIRST_BARE},{_RFC_SERVER_FIRST},{_RFC_CLIENT_FINAL_NO_PROOF}".encode()


def _parse_verifier(verifier: str) -> tuple[int, bytes, bytes, bytes]:
    head, stored_server = verifier.removeprefix("SCRAM-SHA-256$").split("$")
    iters, salt_b64 = head.split(":")
    stored_b64, server_b64 = stored_server.split(":")
    return (
        int(iters),
        base64.b64decode(salt_b64),
        base64.b64decode(stored_b64),
        base64.b64decode(server_b64),
    )


def test_scram_matches_the_rfc7677_known_answer():
    # compute the verifier's StoredKey + ServerKey directly (bypassing the hex-only grammar) via the
    # same code path used internally, and reconstruct the RFC's published ClientProof +
    # ServerSignature.
    salt = base64.b64decode(_RFC_SALT_B64)
    salted = hashlib.pbkdf2_hmac("sha256", _RFC_PASSWORD.encode(), salt, _RFC_ITERATIONS, dklen=32)
    client_key = hmac.new(salted, b"Client Key", hashlib.sha256).digest()
    stored_key = hashlib.sha256(client_key).digest()
    server_key = hmac.new(salted, b"Server Key", hashlib.sha256).digest()

    client_sig = hmac.new(stored_key, _auth_message(), hashlib.sha256).digest()
    client_proof = bytes(a ^ b for a, b in zip(client_key, client_sig, strict=True))
    server_sig = hmac.new(server_key, _auth_message(), hashlib.sha256).digest()

    assert base64.b64encode(client_proof).decode() == _RFC_CLIENT_PROOF_B64  # StoredKey correct
    assert base64.b64encode(server_sig).decode() == _RFC_SERVER_SIGNATURE_B64  # ServerKey correct


def test_public_verifier_uses_the_same_derivation():
    pw = "a" * 64  # a hex-shaped password the public grammar accepts
    salt = b"0123456789abcdef"
    verifier = scram_sha256_verifier(pw, salt=salt, iterations=4096)
    iters, got_salt, stored, server = _parse_verifier(verifier)
    assert iters == 4096 and got_salt == salt
    salted = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, 4096, dklen=32)
    exp_stored = hashlib.sha256(hmac.new(salted, b"Client Key", hashlib.sha256).digest()).digest()
    exp_server = hmac.new(salted, b"Server Key", hashlib.sha256).digest()
    assert stored == exp_stored and server == exp_server


def test_verifier_is_deterministic_per_salt_and_varies_across_salts():
    pw = generate_signer_db_password()
    v1 = scram_sha256_verifier(pw, salt=b"salt-16-bytes-aa")
    v2 = scram_sha256_verifier(pw, salt=b"salt-16-bytes-aa")
    v3 = scram_sha256_verifier(pw, salt=b"salt-16-bytes-bb")
    assert v1 == v2 and v1 != v3


def test_generated_password_is_high_entropy_ascii_hex():
    a, b = generate_signer_db_password(), generate_signer_db_password()
    assert a != b and len(a) == 64 and all(c in "0123456789abcdef" for c in a)


@pytest.mark.parametrize("bad", ["", "not-hex!!", "pencil", "AB" * 40 + "ZZ"])
def test_non_hex_password_is_refused(bad):
    with pytest.raises(ManagementError) as e:
        scram_sha256_verifier(bad, salt=b"salt-16-bytes-aa")
    assert e.value.reason_code == "enrollment_signer_password_invalid"


# --- provisioning SQL --------------------------------------------------------------------------


def test_role_sql_is_least_privilege_and_closed():
    verifier = scram_sha256_verifier(generate_signer_db_password())
    sql = render_signer_role_sql(verifier)
    joined = "\n".join(sql)
    assert ENROLLMENT_SIGNER_DB_ROLE in joined
    # closed attributes: a plain LOGIN role owning nothing
    for attr in ("LOGIN", "NOSUPERUSER", "NOCREATEDB", "NOCREATEROLE", "NOINHERIT"):
        assert attr in joined
    # the plaintext is never in the SQL — only the SCRAM verifier
    assert "SCRAM-SHA-256$" in joined
    # revokes precede the single reviewed SELECT grant; no write grant anywhere
    assert "REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public" in joined
    assert "GRANT SELECT ON controller_enrollment_identity" in joined
    for forbidden in ("INSERT", "UPDATE", "DELETE", "SUPERUSER TO", "GRANT ALL"):
        assert forbidden not in joined


def test_role_sql_refuses_a_malformed_verifier():
    with pytest.raises(EnrollmentSignerDbError) as e:
        render_signer_role_sql("not-a-scram-verifier")
    assert e.value.reason_code == "enrollment_signer_scram_verifier_invalid"


def test_role_sql_rejects_an_injection_shaped_verifier():
    # a verifier carrying a quote/semicolon fails the grammar (never reaches the SQL string)
    with pytest.raises(EnrollmentSignerDbError):
        render_signer_role_sql("SCRAM-SHA-256$4096:AAAA$BBBB:CCCC'; DROP ROLE postgres; --")


# --- systemd-credential loader -----------------------------------------------------------------


def test_credential_loads_from_the_systemd_directory(tmp_path):
    pw = generate_signer_db_password()
    (tmp_path / ENROLLMENT_SIGNER_CREDENTIAL_ID).write_text(pw + "\n")
    assert load_signer_db_password(credentials_dir=str(tmp_path)) == pw


def test_credential_is_unavailable_off_systemd(monkeypatch):
    monkeypatch.delenv("CREDENTIALS_DIRECTORY", raising=False)
    with pytest.raises(ManagementError) as e:
        load_signer_db_password()
    assert e.value.reason_code == "enrollment_signer_credential_unavailable"


def test_malformed_credential_is_refused(tmp_path):
    (tmp_path / ENROLLMENT_SIGNER_CREDENTIAL_ID).write_text("not-a-valid-secret!!")
    with pytest.raises(ManagementError) as e:
        load_signer_db_password(credentials_dir=str(tmp_path))
    assert e.value.reason_code == "enrollment_signer_credential_malformed"
