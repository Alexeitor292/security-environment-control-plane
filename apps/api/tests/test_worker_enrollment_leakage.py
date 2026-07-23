"""Secret/metadata leakage guards for durable worker enrollment (SECP-PR5H-A, ADR-027).

Proves the persistence + service layer stores and exposes ONLY bounded, secret-free values: no
private key, signature, raw signed handoff document, invitation artifact bytes, access token,
credential, raw internal exception, host path, provider endpoint, or arbitrary URL (beyond the
already-validated controller-origin field). Exceptions, reprs, logs and public projections carry
only bounded reason categories and safe identifiers/fingerprints.

Static half: the persisted column set is an explicit allowlist (a new secret-shaped column fails the
test). Behavioural half: every refusal code is a bounded ``enrollment_*`` value, and the public
projection is fingerprint-only.
"""

from __future__ import annotations

import re

import pytest
from secp_api import worker_enrollment_contract as contract
from secp_api.auth import Principal
from secp_api.enums import Permission, WorkerEnrollmentErrorCode
from secp_api.errors import WorkerEnrollmentError
from secp_api.models import Base
from secp_api.seed import bootstrap_dev
from secp_api.services import worker_enrollment as svc
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import Session, sessionmaker

# Column names a secret would hide behind. If a future migration adds one of these to an enrollment
# table, this guard fails until it is justified — no key material, token or credential is persisted.
_FORBIDDEN_COLUMN_FRAGMENTS = (
    "password",
    "passwd",
    "secret",
    "token",
    "credential",
    "private_key",
    "privatekey",
    "signature",
    "signed_document",
    "artifact_bytes",
    "raw_",
    "payload",
    "endpoint",
    "url",
    "path",
    "exception",
    "traceback",
    "bearer",
    "api_key",
)
_ENROLLMENT_TABLES = (
    "worker_enrollment_invitation",
    "worker_enrollment_state",
    "worker_enrollment_revision",
    "worker_enrollment_step_receipt",
)
# controller_origin is the ONE validated HTTPS-origin field the contract permits (not an arbitrary
# URL); allow it explicitly so the broad ``url`` fragment does not false-positive.
_ALLOWED_COLUMNS = {"controller_origin"}

_BOUNDED_CODE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")

CTRL_HEX = (b"\x11" * 32).hex()
CTRL_KEY = contract.sha256_digest_of_hex(CTRL_HEX)
WORKER_HEX = (b"\x22" * 32).hex()
WORKER_KEY = contract.sha256_digest_of_hex(WORKER_HEX)
RELEASE = "sha256:" + "a" * 64
TXN = "txn-0001"
NOW = "2026-07-21T00:10:00Z"


def test_no_enrollment_table_has_a_secret_shaped_column():
    engine = create_engine("sqlite+pysqlite:///:memory:", future=True)
    Base.metadata.create_all(engine)
    inspector = inspect(engine)
    offenders = []
    for table in _ENROLLMENT_TABLES:
        for col in inspector.get_columns(table):
            name = col["name"]
            if name in _ALLOWED_COLUMNS:
                continue
            low = name.lower()
            if any(frag in low for frag in _FORBIDDEN_COLUMN_FRAGMENTS):
                offenders.append(f"{table}.{name}")
    engine.dispose()
    assert not offenders, offenders


def test_every_enrollment_error_code_is_a_bounded_secret_free_category():
    for code in WorkerEnrollmentErrorCode:
        assert _BOUNDED_CODE.fullmatch(code.value), code
        # a bounded snake_case code cannot carry a path, endpoint, IP, colon-scheme or upper token
        assert "/" not in code.value and ":" not in code.value and "." not in code.value


def test_a_redacted_error_serializes_only_its_closed_code():
    err = WorkerEnrollmentError(WorkerEnrollmentErrorCode.state_corrupt)
    assert err.redacted is True
    assert err.code == "enrollment_state_corrupt"
    # the message is exactly the code — no free-form prose, input, or exception body
    assert str(err) == "enrollment_state_corrupt"


@pytest.fixture
def session_actor():
    engine = create_engine("sqlite+pysqlite:///:memory:", future=True)
    Base.metadata.create_all(engine)
    with engine.begin() as conn:
        conn.exec_driver_sql("CREATE TABLE alembic_version (version_num varchar(32) primary key)")
        conn.exec_driver_sql("INSERT INTO alembic_version VALUES ('b6e2f4a9c1d7')")
    factory = sessionmaker(bind=engine, future=True)
    session: Session = factory()
    p = bootstrap_dev(session)
    session.commit()
    actor = Principal(
        user_id=p.user_id,
        organization_id=p.organization_id,
        email=p.email,
        permissions=frozenset(Permission),
    )
    yield session, actor
    session.close()
    engine.dispose()


def _open_and_bind(session, actor):
    inv = contract.create_invitation(
        controller_installation_id="controller-aaaaaaaa",
        controller_key_id=CTRL_KEY,
        controller_trust_anchor_hex=CTRL_HEX,
        controller_origin="https://ctrl.example.com",
        release_digest=RELEASE,
        transaction_id=TXN,
        nonce="sha256:" + "b" * 64,
        created_at="2026-07-21T00:00:00Z",
        expires_at="2026-07-21T01:00:00Z",
    )
    out = svc.create_invitation_and_open(
        session,
        actor,
        invitation=inv,
        invitation_created_at="2026-07-21T00:00:00Z",
        deployment_site_label="rack-01.eu_a",
        now=NOW,
    )
    session.commit()
    state = out.state
    out = svc.bind_worker(
        session,
        actor,
        enrollment_id=state.enrollment_id,
        worker_installation_id="worker-bbbbbbbb",
        worker_key_id=WORKER_KEY,
        transaction_id=TXN,
        now=NOW,
        expected=svc.ExpectedRevision(0, state.digest(), 0, ""),
    )
    session.commit()
    return out.state


def test_public_projection_exposes_only_fingerprints_no_key_material(session_actor):
    import json

    session, actor = session_actor
    state = _open_and_bind(session, actor)
    view = svc.load_public_view(session, actor, enrollment_id=state.enrollment_id)
    blob = json.dumps(view, sort_keys=True)
    # never the full key ids, the trust anchor hex, or the raw release digest
    assert CTRL_KEY not in blob and WORKER_KEY not in blob
    assert CTRL_HEX not in blob and WORKER_HEX not in blob
    assert RELEASE not in blob
    # the transaction id (the one length-only-bounded field) is not projected at all
    assert "transaction" not in blob and TXN not in blob


def test_persisted_rows_contain_no_raw_handoff_bytes_or_key_material(session_actor):
    session, actor = session_actor
    _open_and_bind(session, actor)
    # dump every text-ish column value and assert none contains a PEM, ssh key, or bearer token
    rows = session.execute(text("SELECT * FROM worker_enrollment_state")).mappings().all()
    blob = " ".join(str(v) for row in rows for v in row.values())
    for needle in ("BEGIN", "PRIVATE KEY", "ssh-ed25519", "ssh-rsa", "Bearer ", "vault:", "-----"):
        assert needle not in blob, needle
    # only the controller public-key fingerprint identifiers and digests are present; the
    # trust-anchor HEX (a public key, but still not needed in the state row) never appears here
    assert CTRL_HEX not in blob and WORKER_HEX not in blob
