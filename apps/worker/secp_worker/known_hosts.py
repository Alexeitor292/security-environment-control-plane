"""Real known-hosts + host-key fingerprint binding verifier (SECP-B6 §2).

Before SSH is invoked, this proves — by parsing the deployment-local mounted ``known_hosts`` file
(local read; contacts no host) — that:

- the file contains an entry matching the bundle's EXACT target host + port (plaintext or hashed);
- that entry's SHA-256 host-key fingerprint equals the bundle's expected fingerprint;
- no wildcard, negated, ``@cert-authority``, ``@revoked``-for-our-key, unbound, malformed, or
  duplicate-conflicting entry can satisfy the pin;
- hashed (``|1|salt|hash``) entries are supported via HMAC-SHA1 and equally strictly checked.

It returns only True/False (fail closed on anything unproven) and never logs or raises a raw host/
key/fingerprint value. It performs no host contact; StrictHostKeyChecking + the pinned
UserKnownHosts
file remain the enforcing mechanism at ssh time — this verifier proves the pin is present and
correct
BEFORE ssh is invoked.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
from dataclasses import dataclass

from secp_worker.ssh_channel import SshBootstrapBundle

_MAX_KNOWN_HOSTS_BYTES = 256 * 1024
_MAX_LINES = 20000
# Recognized host-key algorithms. An unrecognized keytype for our host is treated as malformed.
_KEYTYPES = frozenset(
    {
        "ssh-ed25519",
        "ssh-rsa",
        "rsa-sha2-256",
        "rsa-sha2-512",
        "ecdsa-sha2-nistp256",
        "ecdsa-sha2-nistp384",
        "ecdsa-sha2-nistp521",
        "sk-ssh-ed25519@openssh.com",
        "sk-ecdsa-sha2-nistp256@openssh.com",
    }
)
_MARKERS = frozenset({"@cert-authority", "@revoked"})


@dataclass(frozen=True)
class _MatchedEntry:
    marker: str | None
    keytype: str
    fingerprint: str | None  # None => malformed keyblob for our host


def _sha256_fingerprint(keyblob_b64: str) -> str | None:
    try:
        blob = base64.b64decode(keyblob_b64, validate=True)
    except (ValueError, binascii.Error):
        return None
    if not blob:
        return None
    digest = hashlib.sha256(blob).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")


def _target_names(host: str, port: int) -> list[str]:
    # OpenSSH stores the bare host for the default port, and ``[host]:port`` for a non-default port.
    return [host.lower()] if port == 22 else [f"[{host.lower()}]:{port}"]


def _hashed_match(host_field: str, targets: list[str]) -> bool:
    parts = host_field.split("|")
    # Format: ``|1|<b64 salt>|<b64 hash>`` => ['', '1', salt, hash]
    if len(parts) != 4 or parts[0] != "" or parts[1] != "1":
        return False
    try:
        salt = base64.b64decode(parts[2], validate=True)
        expected_hash = parts[3]
    except (ValueError, binascii.Error):
        return False
    for target in targets:
        mac = hmac.new(salt, target.encode("utf-8"), hashlib.sha1).digest()
        if hmac.compare_digest(base64.b64encode(mac).decode("ascii"), expected_hash):
            return True
    return False


def _plaintext_match(host_field: str, targets: list[str]) -> bool | None:
    """True if a plaintext pattern equals a target; None if the field contains ANY wildcard/negation
    token (ssh could honor it for our host, so it is never a valid pin and the whole file must fail
    closed); False if it simply does not match."""
    saw_wildcard = False
    matched = False
    for pattern in host_field.split(","):
        pat = pattern.strip()
        if not pat:
            continue
        if pat.startswith("!") or "*" in pat or "?" in pat:
            saw_wildcard = True
            continue
        if pat.lower() in targets:
            matched = True
    if saw_wildcard:
        return None  # wildcard/negation present — fail closed regardless of any exact match
    return matched


def _match_entry(tokens: list[str], targets: list[str]) -> _MatchedEntry | None:
    """Parse one known_hosts entry. Returns None if it does not pertain to our target; otherwise a
    typed match record, with ``fingerprint=None`` for anything ssh could honor for our host that is
    NOT a clean exact-key pin (a wildcard/negation host field, or a bad keytype/keyblob), so that
    verify() can fail the whole file closed on it."""
    marker: str | None = None
    if tokens and tokens[0] in _MARKERS:
        marker = tokens[0]
        tokens = tokens[1:]
    if len(tokens) < 3:
        return None  # too short to be a host-key line
    host_field, keytype, keyblob = tokens[0], tokens[1], tokens[2]

    if host_field.startswith("|"):
        if not _hashed_match(host_field, targets):
            return None  # hashed entry for a different host
    else:
        pm = _plaintext_match(host_field, targets)
        if pm is False:
            return None  # different host — not applicable to our target
        if pm is None:
            # a wildcard/negation pattern ssh could honor for our host — never a valid pin.
            return _MatchedEntry(marker, keytype, None)

    # Our host matched. A bad keytype or unparseable keyblob is a MALFORMED entry for our host.
    if keytype not in _KEYTYPES:
        return _MatchedEntry(marker, keytype, None)
    return _MatchedEntry(marker, keytype, _sha256_fingerprint(keyblob))


class FileKnownHostsBindingVerifier:
    """The real verifier. Reads the bundle's mounted known_hosts file and proves the exact
    host+port→fingerprint pin, fail-closed. Constructed with no state; safe to reuse."""

    def verify(self, bundle: SshBootstrapBundle) -> bool:
        try:
            with open(bundle.known_hosts_path, "rb") as fh:
                raw = fh.read(_MAX_KNOWN_HOSTS_BYTES + 1)
        except OSError:
            return False
        if len(raw) > _MAX_KNOWN_HOSTS_BYTES:
            return False
        try:
            text = raw.decode("utf-8", "strict")
        except UnicodeDecodeError:
            return False

        expected = bundle.host_key_fingerprint
        targets = _target_names(bundle.ssh_host, int(bundle.ssh_port))

        matches: list[_MatchedEntry] = []
        for i, line in enumerate(text.splitlines()):
            if i >= _MAX_LINES:
                return False  # oversized/adversarial file
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            entry = _match_entry(s.split(), targets)
            if entry is not None:
                matches.append(entry)

        if not matches:
            return False  # unbound: no entry for our exact host+port

        # A revoked entry for our exact expected key => refuse.
        for e in matches:
            if e.marker == "@revoked" and e.fingerprint == expected:
                return False
        # A @cert-authority entry for our host => refuse: ssh would accept ANY host certificate
        # signed by that CA, defeating the exact-key pin even when a correct plain pin is present.
        if any(e.marker == "@cert-authority" for e in matches):
            return False
        # Any malformed / wildcard / bad-keytype entry for our host => refuse (ambiguous/tampered,
        # and ssh could honor it for our host).
        if any(e.fingerprint is None for e in matches):
            return False

        # Exact-key pinning: every plain (non-marker) entry ssh could use for our host MUST be the
        # expected key. An alternate key — same OR different algorithm — is an attacker-usable entry
        # ssh would honor after algorithm negotiation, so its mere presence fails the file closed.
        pins = [e for e in matches if e.marker is None]
        if not any(e.fingerprint == expected for e in pins):
            return False  # expected fingerprint not present among plain pin entries
        for e in pins:
            if e.fingerprint != expected:
                return False
        return True
