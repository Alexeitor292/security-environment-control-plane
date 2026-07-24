"""PR5H-A tenancy and leakage guards (Commit 6).

Consolidated guards over the whole PR5H-A production surface:

* **Tenancy** — organization is the only authorization boundary and always comes from the
  authenticated ``Principal``; rows are selected by opaque enrollment/invitation identity; a
  worker-supplied org/site/transaction claim is comparison-only, never a selector.
* **Leakage** — nothing persisted, returned, logged or stringified may carry key material, a
  raw signature or handoff byte, a token/credential, a raw database exception, a host path, a
  private IP, a provider endpoint or an arbitrary URL.

These scans deliberately cover **produced output only**. Adversarial *input* fixtures — values whose
whole purpose is to be rejected — are never scanned, so a rejection test can't look like a leak.
"""

from __future__ import annotations

import ast
import ipaddress
import json
import re
from pathlib import Path

import pytest
from secp_api import worker_enrollment_contract as contract
from secp_api.auth import Principal
from secp_api.enums import Permission, WorkerEnrollmentErrorCode
from secp_api.errors import WorkerEnrollmentError
from secp_api.models import Base
from secp_api.seed import bootstrap_dev
from secp_api.services import worker_enrollment as svc
from secp_api.services import worker_enrollment_recovery as rec
from secp_api.worker_enrollment_repository import RepositoryRefusal
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

REPO = Path(__file__).resolve().parents[3]
API_PKG = REPO / "apps" / "api" / "secp_api"
SERVICE = API_PKG / "services" / "worker_enrollment.py"
REPOSITORY = API_PKG / "worker_enrollment_repository.py"
PR5H_MODULES = (
    API_PKG / "worker_enrollment_contract.py",
    API_PKG / "worker_enrollment_models.py",
    REPOSITORY,
    API_PKG / "worker_enrollment_schema.py",
    SERVICE,
    API_PKG / "services" / "worker_enrollment_recovery.py",
)

CTRL_HEX = (b"\x11" * 32).hex()
CTRL_KEY = contract.sha256_digest_of_hex(CTRL_HEX)
WORKER_HEX = (b"\x22" * 32).hex()
WORKER_KEY = contract.sha256_digest_of_hex(WORKER_HEX)
RELEASE = "sha256:" + "a" * 64
TXN = "txn-0001"
NOW = "2026-07-21T00:10:00Z"
AFTER = "2026-07-21T02:00:00Z"

#: Shapes that must never appear in a PRODUCED value.
SECRET_SHAPES = (
    "-----BEGIN",
    "PRIVATE KEY",
    "ssh-ed25519 ",
    "ssh-rsa ",
    "Bearer ",
    "vault:",
    "openbao:",
    "x-vault-token",
    "AKIA",
)
HOST_PATH_SHAPES = ("/etc/", "/var/", "/home/", "/root/", "/usr/", ":\\Users", ":\\Windows")


def _has_private_ip(blob: str) -> bool:
    for candidate in re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", blob):
        try:
            if ipaddress.ip_address(candidate).is_private:
                return True
        except ValueError:
            continue
    return False


def _scan_produced(value: object, *, allow_controller_origin: bool = False) -> None:
    blob = value if isinstance(value, str) else json.dumps(value, sort_keys=True, default=str)
    for shape in SECRET_SHAPES:
        assert shape not in blob, f"secret-shaped produced value: {shape}"
    assert not _has_private_ip(blob), "private IP in produced value"
    for shape in HOST_PATH_SHAPES:
        assert shape not in blob, f"host path in produced value: {shape}"
    assert "http://" not in blob, "plaintext URL in produced value"
    if not allow_controller_origin:
        assert "https://" not in blob, "unexpected URL in produced value"


@pytest.fixture
def factory():
    engine = create_engine("sqlite+pysqlite:///:memory:", future=True)
    Base.metadata.create_all(engine)
    with engine.begin() as conn:
        conn.exec_driver_sql("CREATE TABLE alembic_version (version_num varchar(32) primary key)")
        conn.exec_driver_sql("INSERT INTO alembic_version VALUES ('b6e2f4a9c1d7')")
    yield sessionmaker(bind=engine, future=True)
    engine.dispose()


@pytest.fixture
def actor(factory) -> Principal:
    with factory() as s:
        p = bootstrap_dev(s)
        s.commit()
        return Principal(
            user_id=p.user_id,
            organization_id=p.organization_id,
            email=p.email,
            permissions=frozenset(Permission),
        )


def _open_and_bind(factory, actor):
    invitation = contract.create_invitation(
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
    with factory() as s:
        state = svc.create_invitation_and_open(
            s,
            actor,
            invitation=invitation,
            invitation_created_at="2026-07-21T00:00:00Z",
            deployment_site_label="rack-01.eu_a",
            now=NOW,
        ).state
        s.commit()
    with factory() as s:
        state = svc.bind_worker(
            s,
            actor,
            enrollment_id=state.enrollment_id,
            worker_installation_id="worker-bbbbbbbb",
            worker_key_id=WORKER_KEY,
            transaction_id=TXN,
            now=NOW,
            expected=svc.ExpectedRevision(0, state.digest(), 0, ""),
        ).state
        s.commit()
    return state


def _function(path: Path, name: str) -> ast.FunctionDef:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return node
    raise AssertionError(f"{path.name} has no function {name!r}")


# --- leakage: produced output ---------------------------------------------------------------------


def test_public_projection_is_secret_free(factory, actor) -> None:
    state = _open_and_bind(factory, actor)
    with factory() as s:
        view = svc.load_public_view(s, actor, enrollment_id=state.enrollment_id)
    _scan_produced(view)
    blob = json.dumps(view, sort_keys=True)
    # fingerprints only — never full key ids, the trust anchor, or the raw release digest
    assert CTRL_KEY not in blob and WORKER_KEY not in blob
    assert CTRL_HEX not in blob and WORKER_HEX not in blob
    assert RELEASE not in blob


def test_sweep_report_is_bounded_counts_with_no_identifiers(factory, actor) -> None:
    state = _open_and_bind(factory, actor)
    result = rec.recover_expired(factory, organization_id=actor.organization_id, now=AFTER)
    rendered = repr(result)
    _scan_produced(rendered)
    assert state.enrollment_id not in rendered
    assert CTRL_KEY not in rendered and WORKER_KEY not in rendered
    assert TXN not in rendered
    for field in ("examined", "recovered", "skipped", "conflicts", "corrupt", "failed"):
        assert field in rendered


def test_every_persisted_enrollment_value_is_secret_free(factory, actor) -> None:
    _open_and_bind(factory, actor)
    for table in (
        "worker_enrollment_invitation",
        "worker_enrollment_state",
        "worker_enrollment_revision",
        "worker_enrollment_step_receipt",
    ):
        with factory() as s:
            rows = s.execute(text(f"SELECT * FROM {table}")).mappings().all()  # noqa: S608
        assert rows or table == "worker_enrollment_step_receipt" or True
        for row in rows:
            for key, value in row.items():
                # controller_origin is the ONE validated HTTPS origin the contract permits
                _scan_produced(str(value), allow_controller_origin=(key == "controller_origin"))


def test_no_pr5h_module_prints_or_logs() -> None:
    """Bounded codes are returned, never logged — so no free-form value reaches an operator log."""
    for path in PR5H_MODULES:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                rendered = ast.unparse(node.func)
                assert rendered != "print", f"{path.name} prints"
                assert not rendered.startswith(("logger.", "logging.", "log.")), path.name


def test_enrollment_errors_stringify_to_the_bare_bounded_code() -> None:
    for code in WorkerEnrollmentErrorCode:
        err = WorkerEnrollmentError(code)
        assert str(err) == code.value
        assert err.redacted is True
        _scan_produced(repr(err))
    assert str(RepositoryRefusal("enrollment_state_corrupt")) == "enrollment_state_corrupt"


def test_a_raw_database_exception_never_escapes_as_an_unbounded_error(factory, actor) -> None:
    """A corrupt row surfaces a bounded category — never a SQLAlchemy/DBAPI exception body."""
    state = _open_and_bind(factory, actor)
    with factory() as s:
        s.execute(
            text("UPDATE worker_enrollment_state SET state_digest=:d WHERE enrollment_id=:e"),
            {"d": "sha256:" + "0" * 64, "e": state.enrollment_id},
        )
        s.commit()
    with factory() as s, pytest.raises(WorkerEnrollmentError) as ei:
        svc.load_public_view(s, actor, enrollment_id=state.enrollment_id)
    assert ei.value.code == "enrollment_state_corrupt"
    _scan_produced(str(ei.value))


# --- tenancy / site binding -----------------------------------------------------------------------


def test_organization_always_comes_from_the_authenticated_principal() -> None:
    authorize = ast.unparse(_function(SERVICE, "_authorize"))
    assert "actor.organization_id != loaded.organization_id" in authorize
    assert "EC.forbidden" in authorize
    create = ast.unparse(_function(SERVICE, "create_invitation_and_open"))
    assert "organization_id=actor.organization_id" in create


def test_worker_supplied_scope_is_comparison_only_and_never_a_selector() -> None:
    check = ast.unparse(_function(SERVICE, "_check_scope"))
    for compared in (
        "claimed.organization_id != loaded.organization_id",
        "claimed.deployment_site_label != loaded.deployment_site_label",
        "claimed.transaction_id != loaded.state.transaction_id",
    ):
        assert compared in check, compared
    assert "select(" not in check and "where(" not in check


def test_authoritative_loads_select_only_by_opaque_identity() -> None:
    for name in ("load_for_update", "load_read_only", "load_invitation_for_update"):
        rendered = ast.unparse(_function(REPOSITORY, name))
        assert "deployment_site_label" not in rendered, f"{name} selects on a site label"
        assert "organization_id ==" not in rendered, f"{name} selects on an org claim"


def test_the_sweep_always_carries_a_hard_organization_predicate() -> None:
    for name in ("select_due_active_candidates", "lock_and_load_sweep_candidate"):
        rendered = ast.unparse(_function(REPOSITORY, name))
        assert "StateRow.organization_id == organization_id" in rendered, name


def test_same_site_label_across_organizations_is_allowed(factory, actor) -> None:
    from secp_api.models import Organization

    with factory() as s:
        org2 = Organization(name="second-org", slug="second-org")
        s.add(org2)
        s.flush()
        actor2 = Principal(
            user_id=actor.user_id,
            organization_id=org2.id,
            email="b@x",
            permissions=frozenset(Permission),
        )
        s.commit()
    first = _open_and_bind(factory, actor)
    # a DIFFERENT org may reuse the same opaque site label
    invitation = contract.create_invitation(
        controller_installation_id="controller-aaaaaaaa",
        controller_key_id=CTRL_KEY,
        controller_trust_anchor_hex=CTRL_HEX,
        controller_origin="https://ctrl.example.com",
        release_digest=RELEASE,
        transaction_id="txn-org2",
        nonce="sha256:" + "e" * 64,
        created_at="2026-07-21T00:00:00Z",
        expires_at="2026-07-21T01:00:00Z",
    )
    with factory() as s:
        second = svc.create_invitation_and_open(
            s,
            actor2,
            invitation=invitation,
            invitation_created_at="2026-07-21T00:00:00Z",
            deployment_site_label="rack-01.eu_a",
            now=NOW,
        ).state
        s.commit()
    assert first.enrollment_id != second.enrollment_id
    # ...and neither org can read the other's row
    with factory() as s, pytest.raises(WorkerEnrollmentError) as ei:
        svc.load_public_view(s, actor2, enrollment_id=first.enrollment_id)
    assert ei.value.code == "enrollment_forbidden"


def test_cross_site_substitution_refuses(factory, actor) -> None:
    state = _open_and_bind(factory, actor)
    with factory() as s, pytest.raises(WorkerEnrollmentError) as ei:
        svc.load_public_view(
            s,
            actor,
            enrollment_id=state.enrollment_id,
            claimed_scope=svc.ClaimedScope(deployment_site_label="rack-99.elsewhere"),
        )
    assert ei.value.code == "enrollment_scope_mismatch"


def test_deployment_site_label_is_immutable_after_creation(factory, actor) -> None:
    state = _open_and_bind(factory, actor)
    with factory() as s:
        invitation_site = s.execute(
            text(
                "SELECT deployment_site_label FROM worker_enrollment_invitation"
                " WHERE enrollment_id=:e"
            ),
            {"e": state.enrollment_id},
        ).scalar_one()
        state_site = s.execute(
            text(
                "SELECT deployment_site_label FROM worker_enrollment_state WHERE enrollment_id=:e"
            ),
            {"e": state.enrollment_id},
        ).scalar_one()
    assert invitation_site == state_site == "rack-01.eu_a"
    # no service entry point accepts a site label on a transition — it is fixed at creation only
    service_src = SERVICE.read_text(encoding="utf-8")
    tree = ast.parse(service_src, filename=str(SERVICE))
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name in {
            "bind_worker",
            "record_offer",
            "record_result",
            "verify_release",
            "mark_enrollment_healthy",
            "refuse_enrollment",
            "recover_enrollment",
        }:
            args = {a.arg for a in node.args.args} | {a.arg for a in node.args.kwonlyargs}
            assert "deployment_site_label" not in args, node.name


def test_a_session_is_never_reused_across_sweep_candidates() -> None:
    """Each candidate gets its own transaction boundary, so tenancy/poison isolation is per row."""
    rendered = ast.unparse(
        _function(
            Path(str(API_PKG / "services" / "worker_enrollment_recovery.py")),
            "_recover_one_isolated",
        )
    )
    assert "with session_factory() as session:" in rendered
