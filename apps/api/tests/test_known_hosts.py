"""SECP-B6 §2/§6 — real known-hosts + host-key fingerprint binding verifier (no host contact).

Uses a REAL generated Ed25519 host key + its true SHA-256 fingerprint to prove the verifier accepts
a
correct plaintext/hashed pin and fail-closes on a wrong fingerprint, wrong host, wildcard-only,
malformed, duplicate-conflicting, revoked, or unbound known_hosts.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os

from secp_worker.known_hosts import FileKnownHostsBindingVerifier
from secp_worker.ssh_channel import SshBootstrapBundle


def _host_key() -> tuple[str, str, str]:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519

    key = ed25519.Ed25519PrivateKey.generate()
    openssh = (
        key.public_key()
        .public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH)
        .decode()
    )
    keytype, keyblob = openssh.split()[:2]
    blob = base64.b64decode(keyblob)
    fingerprint = "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")
    return keytype, keyblob, fingerprint


def _bundle(tmp_path, content: str, *, host="pve-a", port=22, fingerprint) -> SshBootstrapBundle:
    kh = tmp_path / "known_hosts"
    kh.write_text(content)
    return SshBootstrapBundle(host, port, "acct", "/k", str(kh), fingerprint)


def _hashed(host: str, salt: bytes) -> str:
    mac = hmac.new(salt, host.encode(), hashlib.sha1).digest()
    return f"|1|{base64.b64encode(salt).decode()}|{base64.b64encode(mac).decode()}"


def _verify(bundle) -> bool:
    return FileKnownHostsBindingVerifier().verify(bundle)


def test_valid_plaintext_pin_accepted(tmp_path):
    kt, kb, fp = _host_key()
    assert _verify(_bundle(tmp_path, f"pve-a {kt} {kb}\n", fingerprint=fp)) is True


def test_wrong_fingerprint_refused(tmp_path):
    kt, kb, _ = _host_key()
    _, _, other_fp = _host_key()
    assert _verify(_bundle(tmp_path, f"pve-a {kt} {kb}\n", fingerprint=other_fp)) is False


def test_wrong_host_refused(tmp_path):
    kt, kb, fp = _host_key()
    assert _verify(_bundle(tmp_path, f"other-host {kt} {kb}\n", fingerprint=fp)) is False


def test_wildcard_entry_cannot_pin(tmp_path):
    kt, kb, fp = _host_key()
    assert _verify(_bundle(tmp_path, f"* {kt} {kb}\n", fingerprint=fp)) is False
    assert _verify(_bundle(tmp_path, f"pve-* {kt} {kb}\n", fingerprint=fp)) is False


def test_malformed_entry_for_our_host_refused(tmp_path):
    _, kb, fp = _host_key()
    assert _verify(_bundle(tmp_path, f"pve-a not-a-keytype {kb}\n", fingerprint=fp)) is False
    bad = _bundle(tmp_path, "pve-a ssh-ed25519 !!!notbase64!!!\n", fingerprint=fp)
    assert _verify(bad) is False


def test_duplicate_conflicting_keys_refused(tmp_path):
    kt, kb, fp = _host_key()
    _, other_kb, _ = _host_key()
    content = f"pve-a {kt} {kb}\npve-a {kt} {other_kb}\n"
    assert _verify(_bundle(tmp_path, content, fingerprint=fp)) is False


def test_revoked_key_refused(tmp_path):
    kt, kb, fp = _host_key()
    assert _verify(_bundle(tmp_path, f"@revoked pve-a {kt} {kb}\n", fingerprint=fp)) is False


def test_hashed_entry_match_accepted(tmp_path):
    kt, kb, fp = _host_key()
    salt = os.urandom(20)
    content = f"{_hashed('pve-a', salt)} {kt} {kb}\n"
    assert _verify(_bundle(tmp_path, content, fingerprint=fp)) is True


def test_hashed_entry_wrong_host_refused(tmp_path):
    kt, kb, fp = _host_key()
    salt = os.urandom(20)
    content = f"{_hashed('some-other-host', salt)} {kt} {kb}\n"
    assert _verify(_bundle(tmp_path, content, fingerprint=fp)) is False


def test_non_default_port_bracket_match(tmp_path):
    kt, kb, fp = _host_key()
    content = f"[pve-a]:2222 {kt} {kb}\n"
    assert _verify(_bundle(tmp_path, content, host="pve-a", port=2222, fingerprint=fp)) is True
    # A bare-host entry must NOT satisfy a non-default port target.
    bare = _bundle(tmp_path, f"pve-a {kt} {kb}\n", host="pve-a", port=2222, fingerprint=fp)
    assert _verify(bare) is False


def test_unbound_empty_file_refused(tmp_path):
    _, _, fp = _host_key()
    assert _verify(_bundle(tmp_path, "# only a comment\n", fingerprint=fp)) is False


def test_idempotent_duplicate_expected_pin_accepted(tmp_path):
    # The SAME expected key repeated (an idempotent duplicate) is not a conflict.
    kt, kb, fp = _host_key()
    content = f"pve-a {kt} {kb}\npve-a {kt} {kb}\n"
    assert _verify(_bundle(tmp_path, content, fingerprint=fp)) is True


def test_valid_pin_plus_wildcard_line_refused(tmp_path):
    # SECP-B6 F1: a correct pin PLUS a wildcard line ssh would honor for our host => fail closed.
    kt, kb, fp = _host_key()
    _, atk, _ = _host_key()
    content = f"pve-a {kt} {kb}\n* {kt} {atk}\n"
    assert _verify(_bundle(tmp_path, content, fingerprint=fp)) is False


def test_valid_pin_plus_cert_authority_line_refused(tmp_path):
    # SECP-B6 F2: a @cert-authority line for our host lets ssh accept any CA-signed cert => refuse,
    # even alongside a correct plain pin.
    kt, kb, fp = _host_key()
    ca_kt, ca_kb, _ = _host_key()
    content = f"pve-a {kt} {kb}\n@cert-authority pve-a {ca_kt} {ca_kb}\n"
    assert _verify(_bundle(tmp_path, content, fingerprint=fp)) is False


def test_valid_pin_plus_alternate_algorithm_key_refused(tmp_path):
    # SECP-B6 F3: an alternate key for the same host (here a different-algorithm line) that ssh
    # could negotiate to is an attacker-usable alternate => the whole file fails closed.
    kt, kb, fp = _host_key()
    _, other_kb, _ = _host_key()
    content = f"pve-a {kt} {kb}\npve-a ssh-rsa {other_kb}\n"
    assert _verify(_bundle(tmp_path, content, fingerprint=fp)) is False


def test_cert_authority_wildcard_line_refused(tmp_path):
    # A @cert-authority wildcard line (no plain pin) must also fail closed.
    ca_kt, ca_kb, _ = _host_key()
    _, _, fp = _host_key()
    content = f"@cert-authority * {ca_kt} {ca_kb}\n"
    assert _verify(_bundle(tmp_path, content, fingerprint=fp)) is False
