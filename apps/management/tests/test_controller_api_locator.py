"""Controller-API locator for secpctl controller commands (SECP-PR5H-B1, Phase 4).

Hermetic (in-memory hardened filesystem). Proves the sealed default fails closed, the bootstrap
writer records a validated locator that reads back, and the reader refuses an absent / unsafe /
malformed / grammar-invalid locator — all with bounded reason codes and a redacted repr that never
leaks the origin or CA path.
"""

from __future__ import annotations

import pytest
from secp_commissioning.canonical import canonical_json
from secp_commissioning.runtime import InMemoryFilesystem
from secp_management.controller_api_locator import (
    CONTROLLER_API_LOCATOR_PATH,
    ControllerApiLocator,
    ControllerApiLocatorError,
    FileControllerApiLocatorProvider,
    SealedControllerApiLocatorProvider,
    record_controller_api_locator,
)

ORIGIN = "https://controller.example.test"
CA = "/etc/secp/controller/ca.pem"
_ANCESTORS = ("/etc", "/etc/secp", "/etc/secp/controller")
_SCHEMA = "secp.management.controller-api-locator/v1"


def _fs() -> InMemoryFilesystem:
    fs = InMemoryFilesystem()
    for d in _ANCESTORS:
        fs.seed_dir(d, uid=0, gid=0, mode=0o755)
    return fs


def _seed_locator(fs: InMemoryFilesystem, *, origin=ORIGIN, ca=CA, schema=_SCHEMA, mode=0o644, **o):
    body = {"schema": schema, "canonical_origin": origin, "ca_bundle_path": ca}
    body.update(o)
    fs.seed_file(
        CONTROLLER_API_LOCATOR_PATH,
        canonical_json(body).encode("utf-8"),
        uid=0,
        gid=0,
        mode=mode,
    )


def test_sealed_default_fails_closed():
    with pytest.raises(ControllerApiLocatorError) as ei:
        SealedControllerApiLocatorProvider().locate()
    assert ei.value.reason_code == "secpctl_controller_locator_unavailable"


def test_absent_locator_is_unavailable():
    with pytest.raises(ControllerApiLocatorError) as ei:
        FileControllerApiLocatorProvider(_fs()).locate()
    assert ei.value.reason_code == "secpctl_controller_locator_unavailable"


def test_a_recorded_locator_reads_back():
    fs = _fs()
    written = record_controller_api_locator(
        fs, canonical_origin=ORIGIN, ca_bundle_path=CA, write=True, confirm=True
    )
    assert written.canonical_origin == ORIGIN and written.ca_bundle_path == CA
    loc = FileControllerApiLocatorProvider(fs).locate()
    assert loc.canonical_origin == ORIGIN and loc.ca_bundle_path == CA
    # the repr never leaks the origin or CA path
    assert ORIGIN not in repr(loc) and CA not in repr(loc)
    assert "redacted" in repr(loc)


def test_dry_run_validates_without_writing():
    fs = _fs()
    loc = record_controller_api_locator(
        fs, canonical_origin=ORIGIN, ca_bundle_path=CA, write=True, confirm=False
    )
    assert loc.canonical_origin == ORIGIN
    assert fs.lstat(CONTROLLER_API_LOCATOR_PATH) is None  # nothing written


def test_seeded_locator_reads():
    fs = _fs()
    _seed_locator(fs)
    loc = FileControllerApiLocatorProvider(fs).locate()
    assert loc.canonical_origin == ORIGIN and loc.ca_bundle_path == CA


def test_a_group_writable_locator_is_refused():
    fs = _fs()
    _seed_locator(fs, mode=0o664)  # group-writable -> unsafe
    with pytest.raises(ControllerApiLocatorError) as ei:
        FileControllerApiLocatorProvider(fs).locate()
    assert ei.value.reason_code == "secpctl_controller_locator_invalid"


def test_a_symlinked_locator_is_refused():
    fs = _fs()
    fs.seed_file("/etc/secp/controller/real.json", b"{}", uid=0, gid=0, mode=0o644)
    fs.seed_symlink(CONTROLLER_API_LOCATOR_PATH, uid=0, gid=0)
    with pytest.raises(ControllerApiLocatorError) as ei:
        FileControllerApiLocatorProvider(fs).locate()
    assert ei.value.reason_code == "secpctl_controller_locator_invalid"


@pytest.mark.parametrize(
    "body",
    [
        b"{not json",
        canonical_json(
            {"schema": "wrong", "canonical_origin": ORIGIN, "ca_bundle_path": CA}
        ).encode(),
        canonical_json(
            {"schema": _SCHEMA, "canonical_origin": "http://x", "ca_bundle_path": CA}
        ).encode(),
        canonical_json(
            {"schema": _SCHEMA, "canonical_origin": ORIGIN, "ca_bundle_path": "rel"}
        ).encode(),
        canonical_json(
            {"schema": _SCHEMA, "canonical_origin": ORIGIN, "ca_bundle_path": "/etc/../x"}
        ).encode(),
    ],
)
def test_malformed_or_grammar_invalid_locator_is_refused(body):
    fs = _fs()
    fs.seed_file(CONTROLLER_API_LOCATOR_PATH, body, uid=0, gid=0, mode=0o644)
    with pytest.raises(ControllerApiLocatorError) as ei:
        FileControllerApiLocatorProvider(fs).locate()
    assert ei.value.reason_code == "secpctl_controller_locator_invalid"


def test_direct_value_object_validates_grammar():
    with pytest.raises(ControllerApiLocatorError):
        ControllerApiLocator(canonical_origin="ftp://x", ca_bundle_path=CA)
    with pytest.raises(ControllerApiLocatorError):
        ControllerApiLocator(canonical_origin=ORIGIN, ca_bundle_path="not-absolute")
