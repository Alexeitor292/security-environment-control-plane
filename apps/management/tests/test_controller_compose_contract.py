"""The STRICT signed controller-Compose contract (SECP-PR5H-B2, 2b-3c-c deployability gap).

`4413f2f` closed Defect 3 for security but not for TOPOLOGY: the controller Compose template is a
SIGNED release artifact installed verbatim, and nothing proved that the signed artifact actually
mounts the readiness gate into the ordinary API. The management fixture was a placeholder comment,
so a fully green CI proved nothing about the mount at all — a release could have been signed,
verified, installed and started with no gate mount, leaving the readiness route permanently
unreachable as a byte-identical 404 with no refusal anywhere.

This suite proves the contract itself and, critically, that **a valid signature is not sufficient**:
every case below is a bundle whose ed25519 signature verifies over a manifest whose declared digest
matches the artifact exactly — and each is still refused, before any host mutation, because the
template does not satisfy the installation contract.

Offline: the hardened in-memory filesystem and an ephemeral trust root. No host, no Docker, no
network.
"""

from __future__ import annotations

import pytest
from _mgmt_support import ephemeral_trust_root, seed_signed_bundle
from secp_commissioning.canonical import sha256_bytes
from secp_commissioning.enrollment_signer_binding_digest import (
    ENROLLMENT_SIGNER_READINESS_GATE_CONTAINER_PATH as GATE_TARGET,
)
from secp_commissioning.enrollment_signer_binding_digest import (
    ENROLLMENT_SIGNER_READINESS_GATE_HOST_PATH as GATE_SOURCE,
)
from secp_commissioning.enrollment_signer_marker import ENROLLMENT_SIGNER_MARKER_PATH as MARKER
from secp_commissioning.runtime import InMemoryFilesystem
from secp_management import ManagementError
from secp_management.controller_compose_reference import reference_controller_compose
from secp_management.controller_compose_validation import (
    REQUIRED_API_MOUNTS,
    REQUIRED_MOUNT_BIND_KEYS,
    REQUIRED_MOUNT_KEYS,
    ControllerComposeContractError,
    assert_controller_compose_contract,
    canonical_container_target,
    controller_compose_contract_reason,
)
from secp_management.release_verify import verify_release_bundle

VALID = reference_controller_compose()
#: a literal newline, spelled once so the alias fixtures below read as plain YAML.
NL = chr(10)
_BD = "/opt/secp/release"


# --------------------------------------------------------------------------- template mutators
#
# Each returns a template that is byte-different from VALID in exactly ONE contract-relevant way.


def _drop_gate(text: str) -> str:
    return text[: text.index("      - type: bind\n        source: " + GATE_SOURCE)]


def _drop_marker(text: str) -> str:
    block = (
        f"      - type: bind\n        source: {MARKER}\n        target: {MARKER}\n"
        "        read_only: true\n        bind:\n          create_host_path: false\n"
    )
    assert block in text
    return text.replace(block, "", 1)


_GATE_HEAD = f"        target: {GATE_TARGET}\n        read_only: true"
_GATE_TAIL = f"{_GATE_HEAD}\n        bind:\n          create_host_path: false"

CASES: dict[str, tuple[str, str]] = {
    # name: (mutated template, expected bounded reason code)
    "signed template missing the gate mount": (
        _drop_gate(VALID.decode()),
        "controller_compose_readiness_gate_mount_missing",
    ),
    "signed template missing the marker mount": (
        _drop_marker(VALID.decode()),
        "controller_compose_marker_mount_missing",
    ),
    "writable gate": (
        VALID.decode().replace(
            _GATE_HEAD, f"        target: {GATE_TARGET}\n        read_only: false"
        ),
        "controller_compose_readiness_gate_mount_writable",
    ),
    "wrong source": (
        VALID.decode().replace(f"        source: {GATE_SOURCE}", "        source: /etc/secp/other"),
        "controller_compose_readiness_gate_mount_wrong_source",
    ),
    "wrong target": (
        VALID.decode().replace(f"        target: {GATE_TARGET}", "        target: /run/secp/other"),
        "controller_compose_readiness_gate_mount_missing",
    ),
    "duplicate gate target": (
        VALID.decode()
        + f"      - type: bind\n        source: /tmp/evil\n        target: {GATE_TARGET}\n"
        "        read_only: false\n",
        "controller_compose_readiness_gate_mount_duplicate_target",
    ),
    "short-form gate mount": (
        _drop_gate(VALID.decode()) + f'      - "{GATE_SOURCE}:{GATE_TARGET}:ro"\n',
        "controller_compose_readiness_gate_mount_short_form",
    ),
    "create_host_path true": (
        VALID.decode().replace(
            _GATE_TAIL, f"{_GATE_HEAD}\n        bind:\n          create_host_path: true"
        ),
        "controller_compose_readiness_gate_mount_create_host_path",
    ),
    "create_host_path absent": (
        VALID.decode().replace(_GATE_TAIL, _GATE_HEAD),
        "controller_compose_readiness_gate_mount_create_host_path",
    ),
    "interpolated source path": (
        VALID.decode().replace(f"        source: {GATE_SOURCE}", "        source: ${SECP_GATE}"),
        "controller_compose_readiness_gate_mount_interpolated",
    ),
    "propagation override": (
        VALID.decode().replace(
            "          create_host_path: false\n",
            "          create_host_path: false\n          propagation: rshared\n",
            1,
        ),
        "controller_compose_marker_mount_propagation_forbidden",
    ),
    "duplicate services/api/volumes key": (
        VALID.decode().replace("    volumes:", "    volumes: []\n    volumes:", 1),
        "controller_compose_duplicate_key",
    ),
    "malformed YAML": ("services:\n  api:\n   - [unclosed\n", "controller_compose_malformed"),
    "comments only": ("# compose template\n", "controller_compose_malformed"),
    "a second document": (
        VALID.decode() + "---\nservices:\n  api:\n    volumes: []\n",
        "controller_compose_multiple_documents",
    ),
    "no api service": (
        VALID.decode().replace("  api:", "  notapi:", 1),
        "controller_compose_api_service_missing",
    ),
    "api volumes is a mapping, not a list": (
        "services:\n  api:\n    volumes:\n      first: {}\n",
        "controller_compose_unsupported_volume_structure",
    ),
    "api extends another file": (
        VALID.decode().replace("  api:\n", "  api:\n    extends:\n      file: other.yml\n", 1),
        "controller_compose_indirection_forbidden",
    ),
    "top-level include": (
        "include:\n  - other.yml\n" + VALID.decode(),
        "controller_compose_indirection_forbidden",
    ),
    "api has no volumes at all": (
        "services:\n  api:\n    restart: unless-stopped\n",
        "controller_compose_api_volumes_missing",
    ),
}

_IDS = list(CASES)


# --------------------------------------------------------------------------- the validator itself


def test_the_exact_reference_template_satisfies_the_contract() -> None:
    assert controller_compose_contract_reason(VALID) is None
    assert_controller_compose_contract(VALID)  # does not raise


def test_the_contract_requires_both_reviewed_mounts_from_the_plane_neutral_constants() -> None:
    # the validator must never define a path of its own -- it would then be able to drift from the
    # marker loader, the gate primitive and the management transport that use the real constants.
    assert {(s, t) for s, t, _k in REQUIRED_API_MOUNTS} == {
        (MARKER, MARKER),
        (GATE_SOURCE, GATE_TARGET),
    }


@pytest.mark.parametrize("name", _IDS)
def test_each_invalid_template_is_refused_with_its_bounded_reason(name: str) -> None:
    template, expected = CASES[name]
    with pytest.raises(ControllerComposeContractError) as exc:
        assert_controller_compose_contract(template.encode())
    assert exc.value.reason_code == expected


@pytest.mark.parametrize("name", _IDS)
def test_no_refusal_ever_echoes_a_deployment_value(name: str) -> None:
    """A reason code names the CONTRACT CLASS that failed, never a path, image or host from the
    artifact -- a refusal is emitted to operators and must not become a disclosure channel."""
    template, _expected = CASES[name]
    reason = controller_compose_contract_reason(template.encode())
    assert reason is not None
    assert "/" not in reason and "$" not in reason and " " not in reason
    assert len(reason) <= 72 and reason.startswith("controller_compose_")


# ---------------------------------------------------- R8: normalized-alias reproduction + refusal
#
# Independent review R8. compose-go applies POSIX `path.Clean` to EVERY volume target, so four
# different strings become ONE runtime destination. The validator compared raw strings, so a VALID
# required mount could coexist with a WRITABLE alias landing on the very same path. Each template
# below was ACCEPTED before this correction; the worst is the `..` form, a writable bind with
# `create_host_path: true` on the readiness gate's destination.


def _alias_entry(target: str, *, read_only: str = "false", create: str = "true") -> str:
    """A hostile long-form bind aimed at ``target``: writable, and allowed to create its source."""
    return (
        "      - type: bind\n"
        "        source: /tmp/evil\n"
        f"        target: {target}\n"
        f"        read_only: {read_only}\n"
        "        bind:\n"
        f"          create_host_path: {create}\n"
    )


#: every lexical spelling that compose-go normalizes onto the reviewed readiness-gate target.
GATE_ALIAS_TARGETS: dict[str, str] = {
    "parent-segment": "/run/secp/../secp/enrollment-signer-readiness-gate.secret",
    "trailing-slash": GATE_TARGET + "/",
    "repeated-separator": "/run//secp/enrollment-signer-readiness-gate.secret",
    "dot-segment": "/run/secp/./enrollment-signer-readiness-gate.secret",
    "deep-parent-segment": "/run/secp/x/../enrollment-signer-readiness-gate.secret",
}

#: aliases whose target string is already canonical, so they collide by grouping rather than by
#: canonicalization: a rival representation of the same destination.
VALID_PLUS_ALIAS: dict[str, str] = {
    "short-form alias": f'      - "/tmp/evil:{GATE_TARGET}:rw"' + NL,
    "anonymous short-form alias": f'      - "{GATE_TARGET}"' + NL,
    "named-volume alias": (
        "      - type: volume"
        + NL
        + "        source: evil"
        + NL
        + f"        target: {GATE_TARGET}"
        + NL
    ),
    "tmpfs alias": "      - type: tmpfs" + NL + f"        target: {GATE_TARGET}" + NL,
    "image alias": (
        "      - type: image"
        + NL
        + "        source: evil:latest"
        + NL
        + f"        target: {GATE_TARGET}"
        + NL
    ),
    "second writable bind": _alias_entry(GATE_TARGET),
}


@pytest.mark.parametrize("name", list(GATE_ALIAS_TARGETS))
def test_a_valid_mount_plus_a_normalizing_alias_is_refused(name: str) -> None:
    template = VALID.decode() + _alias_entry(GATE_ALIAS_TARGETS[name])
    with pytest.raises(ControllerComposeContractError) as exc:
        assert_controller_compose_contract(template.encode())
    # refused for being NONCANONICAL -- never silently normalized and then accepted.
    assert exc.value.reason_code == "controller_compose_target_not_canonical"


@pytest.mark.parametrize("name", list(VALID_PLUS_ALIAS))
def test_a_valid_mount_plus_a_rival_representation_is_refused(name: str) -> None:
    template = VALID.decode() + VALID_PLUS_ALIAS[name]
    with pytest.raises(ControllerComposeContractError) as exc:
        assert_controller_compose_contract(template.encode())
    assert exc.value.reason_code == "controller_compose_readiness_gate_mount_duplicate_target"


@pytest.mark.parametrize("name", list(GATE_ALIAS_TARGETS) + list(VALID_PLUS_ALIAS))
def test_every_alias_is_refused_as_a_correctly_signed_bundle(name: str) -> None:
    """The decisive property, restated for R8: the manifest is canonical, the declared digest
    matches the mutated bytes exactly, the ed25519 signature verifies under a pinned anchor --
    and the bundle is STILL refused, before any host mutation. Docker's eventual "duplicate
    mount point" is not the gate; the signed release must never be signable or installable."""
    extra = (
        _alias_entry(GATE_ALIAS_TARGETS[name])
        if name in GATE_ALIAS_TARGETS
        else VALID_PLUS_ALIAS[name]
    )
    trust, key_id, priv, _pub = ephemeral_trust_root()
    fs = InMemoryFilesystem()
    _bundle(fs, priv, key_id, (VALID.decode() + extra).encode())
    with pytest.raises(ManagementError) as exc:
        verify_release_bundle(_BD, trust_root=trust, fs=fs)
    assert exc.value.reason_code.startswith("controller_compose_")


# ---------------------------------------------------------------- the canonicalizer, directly


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("", "controller_compose_target_invalid"),
        (None, "controller_compose_target_invalid"),
        (123, "controller_compose_target_invalid"),
        ("relative/path", "controller_compose_target_not_absolute"),
        ("./x", "controller_compose_target_not_absolute"),
        ("/", "controller_compose_target_not_canonical"),
        ("/a/", "controller_compose_target_not_canonical"),
        ("/a//b", "controller_compose_target_not_canonical"),
        ("/a/./b", "controller_compose_target_not_canonical"),
        ("/a/../b", "controller_compose_target_not_canonical"),
        ("/a/..", "controller_compose_target_not_canonical"),
        ("/a/b" + chr(92) + "c", "controller_compose_target_invalid"),
        ("/a" + chr(92) + "x00b", "controller_compose_target_invalid"),
        ("/${VAR}/b", "controller_compose_target_interpolated"),
        ("/" + "a" * 2000, "controller_compose_target_too_long"),
    ],
)
def test_the_canonicalizer_refuses_every_noncanonical_target(raw: object, expected: str) -> None:
    with pytest.raises(ControllerComposeContractError) as exc:
        canonical_container_target(raw)
    assert exc.value.reason_code == expected


@pytest.mark.parametrize("raw", ["/a", "/a/b", "/run/secp/x.secret", GATE_TARGET, MARKER])
def test_the_canonicalizer_accepts_a_canonical_target_unchanged(raw: str) -> None:
    assert canonical_container_target(raw) == raw  # byte-for-byte, never rewritten


def test_the_canonicalizer_uses_posix_not_host_semantics() -> None:
    """On Windows ``os.path`` treats a backslash as a separator and would normalize it away; the
    target is a path inside a Linux container and must read identically on every signing host."""
    backslashed = "/run/secp" + chr(92) + ".." + chr(92) + "evil"
    with pytest.raises(ControllerComposeContractError) as exc:
        canonical_container_target(backslashed)
    assert exc.value.reason_code == "controller_compose_target_invalid"


# ---------------------------------------------------- R8a: the required mount shape is CLOSED


def test_the_allowed_mount_key_sets_are_exact() -> None:
    assert REQUIRED_MOUNT_KEYS == {"type", "source", "target", "read_only", "bind"}
    assert REQUIRED_MOUNT_BIND_KEYS == {"create_host_path"}


_GATE_BLOCK_TAIL = "          create_host_path: false" + NL

R8A_EXTRA_KEYS: dict[str, tuple[str, str]] = {
    # name: (needle, replacement) -- each adds ONE key the contract does not allow
    "bind.selinux": (_GATE_BLOCK_TAIL, _GATE_BLOCK_TAIL + "          selinux: z" + NL),
    "bind.recursive": (_GATE_BLOCK_TAIL, _GATE_BLOCK_TAIL + "          recursive: disabled" + NL),
    "unknown bind key": (_GATE_BLOCK_TAIL, _GATE_BLOCK_TAIL + "          future_flag: true" + NL),
    "top-level consistency": (
        "        read_only: true" + NL,
        "        read_only: true" + NL + "        consistency: cached" + NL,
    ),
    "top-level volume map": (
        "        read_only: true" + NL,
        "        read_only: true" + NL + "        volume:" + NL + "          nocopy: true" + NL,
    ),
    "top-level tmpfs map": (
        "        read_only: true" + NL,
        "        read_only: true" + NL + "        tmpfs:" + NL + "          size: 1024" + NL,
    ),
    "top-level image map": (
        "        read_only: true" + NL,
        "        read_only: true" + NL + "        image:" + NL + "          subpath: x" + NL,
    ),
    "top-level cluster": (
        "        read_only: true" + NL,
        "        read_only: true" + NL + "        cluster:" + NL + "          group: g" + NL,
    ),
    "top-level subpath": (
        "        read_only: true" + NL,
        "        read_only: true" + NL + "        subpath: inner" + NL,
    ),
    "unknown top-level key": (
        "        read_only: true" + NL,
        "        read_only: true" + NL + "        future_option: true" + NL,
    ),
}


@pytest.mark.parametrize("name", list(R8A_EXTRA_KEYS))
def test_any_extra_mount_key_is_refused(name: str) -> None:
    """A closed allow-list, not a deny-list: a future Compose feature must not silently broaden the
    authority the ordinary API receives merely because this module has not heard of it."""
    needle, replacement = R8A_EXTRA_KEYS[name]
    template = VALID.decode().replace(needle, replacement, 1)
    assert template != VALID.decode(), name
    with pytest.raises(ControllerComposeContractError) as exc:
        assert_controller_compose_contract(template.encode())
    assert exc.value.reason_code.endswith("_mount_unexpected_key")


@pytest.mark.parametrize("name", list(R8A_EXTRA_KEYS))
def test_any_extra_mount_key_is_refused_as_a_correctly_signed_bundle(name: str) -> None:
    needle, replacement = R8A_EXTRA_KEYS[name]
    template = VALID.decode().replace(needle, replacement, 1)
    trust, key_id, priv, _pub = ephemeral_trust_root()
    fs = InMemoryFilesystem()
    _bundle(fs, priv, key_id, template.encode())
    with pytest.raises(ManagementError) as exc:
        verify_release_bundle(_BD, trust_root=trust, fs=fs)
    assert exc.value.reason_code.endswith("_mount_unexpected_key")


def test_bind_propagation_keeps_its_own_named_refusal() -> None:
    """It is the one bind option that could reopen what ``read_only`` closed, so it stays named
    rather than collapsing into the generic unexpected-key code."""
    template = VALID.decode().replace(
        _GATE_BLOCK_TAIL, _GATE_BLOCK_TAIL + "          propagation: rshared" + NL, 1
    )
    assert controller_compose_contract_reason(template.encode()) == (
        "controller_compose_marker_mount_propagation_forbidden"
    )


# ---------------------------------------------------- YAML aliases and merge structures


def test_an_alias_cannot_introduce_an_extra_mount() -> None:
    """``safe_load`` resolves anchors and aliases at PARSE time, so the validator always sees the
    EFFECTIVE structure -- an alias can never hide an entry from the canonical-target grouping."""
    hostile = (
        "x: &evil"
        + NL
        + "  type: bind"
        + NL
        + "  source: /tmp/evil"
        + NL
        + f"  target: {GATE_TARGET}"
        + NL
        + "  read_only: false"
        + NL
        + VALID.decode()
        + "      - *evil"
        + NL
    )
    assert controller_compose_contract_reason(hostile.encode()) == (
        "controller_compose_readiness_gate_mount_duplicate_target"
    )


def test_an_alias_cannot_replace_the_required_volume_list() -> None:
    hostile = "x: &empty []" + NL + "services:" + NL + "  api:" + NL + "    volumes: *empty" + NL
    assert controller_compose_contract_reason(hostile.encode()) == (
        "controller_compose_marker_mount_missing"
    )


def test_a_merge_key_cannot_graft_volumes_onto_the_api_service() -> None:
    hostile = (
        "base: &base"
        + NL
        + "  volumes: []"
        + NL
        + "services:"
        + NL
        + "  api:"
        + NL
        + "    <<: *base"
        + NL
        + "    restart: unless-stopped"
        + NL
    )
    assert controller_compose_contract_reason(hostile.encode()) is not None


def test_a_yaml_tag_cannot_construct_an_object() -> None:
    """``safe_load`` semantics: a Python-object tag is a refusal, never an instantiation."""
    hostile = "services:\n  api:\n    volumes: !!python/object/apply:os.system ['echo pwned']\n"
    assert controller_compose_contract_reason(hostile.encode()) == "controller_compose_malformed"


def test_a_deeply_nested_document_is_bounded() -> None:
    deep = "services:\n  api:\n    volumes:\n" + "".join(
        f"{' ' * (6 + 2 * i)}- a:\n" for i in range(24)
    )
    assert controller_compose_contract_reason(deep.encode()) is not None


# --------------------------------------------------------------------------- SIGNED bundle matrix


def _bundle(fs: InMemoryFilesystem, priv: str, key_id: str, compose: bytes) -> None:
    seed_signed_bundle(fs, _BD, "controller", key_id, priv, compose_bytes=compose)


@pytest.mark.parametrize("name", _IDS)
def test_a_correctly_signed_but_invalid_artifact_is_still_refused(name: str) -> None:
    """The decisive property. The manifest is canonical, the declared digest matches the artifact
    byte for byte, and the ed25519 signature verifies under a pinned anchor -- and the bundle is
    STILL refused, because signature validity says nothing about whether the ordinary API receives
    the reviewed mounts."""
    template, expected = CASES[name]
    trust, key_id, priv, _pub = ephemeral_trust_root()
    fs = InMemoryFilesystem()
    _bundle(fs, priv, key_id, template.encode())

    with pytest.raises(ManagementError) as exc:
        verify_release_bundle(_BD, trust_root=trust, fs=fs)
    assert exc.value.reason_code == expected


def test_the_valid_controller_bundle_verifies() -> None:
    trust, key_id, priv, _pub = ephemeral_trust_root()
    fs = InMemoryFilesystem()
    _bundle(fs, priv, key_id, VALID)
    verified = verify_release_bundle(_BD, trust_root=trust, fs=fs)
    assert verified.role == "controller"


def test_a_worker_bundle_is_unaffected_by_the_controller_contract() -> None:
    """The contract constrains the CONTROLLER template only. A worker release carries no controller
    template and must not be forced through a controller-shaped check."""
    trust, key_id, priv, _pub = ephemeral_trust_root()
    fs = InMemoryFilesystem()
    seed_signed_bundle(fs, _BD, "worker", key_id, priv)
    verified = verify_release_bundle(_BD, trust_root=trust, fs=fs)
    assert verified.role == "worker"


def test_the_declared_digest_still_binds_the_validated_bytes() -> None:
    """Contract validation must not become a way to accept a SUBSTITUTED artifact: the digest gate
    still runs first, so tampered bytes refuse as drift rather than being contract-checked."""
    trust, key_id, priv, _pub = ephemeral_trust_root()
    fs = InMemoryFilesystem()
    _bundle(fs, priv, key_id, VALID)
    fs.seed_file(f"{_BD}/controller-compose.yml", VALID + b"# tampered\n", mode=0o644)
    with pytest.raises(ManagementError) as exc:
        verify_release_bundle(_BD, trust_root=trust, fs=fs)
    # the hardened read is bounded by the DECLARED size, so oversized tampering refuses there;
    # same-size tampering refuses on the digest. Either way the contract check never sees the bytes.
    assert exc.value.reason_code in {
        "fs_read_size_invalid",
        "release_artifact_size_mismatch",
        "release_artifact_digest_mismatch",
    }
    assert sha256_bytes(VALID) != sha256_bytes(VALID + b"# tampered\n")
