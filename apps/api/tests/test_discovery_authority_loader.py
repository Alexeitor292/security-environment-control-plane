"""The expected authority is composed from durable rows, and refuses nineteen ways.

Before this loader existed, ``ExpectedWorkerRegistration`` was constructed only by tests. The
registered-anchor verification that the whole signed-discovery chain terminates in therefore had no
production path to it at all — the classic "correct module reached by nothing", in the one place
where the module reached by nothing decides whether a signed snapshot may be trusted.

Every test here writes real rows through the ORM and reads them back through the loader. Nothing is
faked: the refusals are produced by the actual lifecycle columns an operator would be looking at.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from secp_api.discovery_authority_loader import (
    AUTHORITY_REFUSAL_REASONS,
    DISCOVERY_ADMISSION_PURPOSE,
    AuthorizedDiscoveryOperation,
    DiscoveryAuthorityRefused,
    DiscoveryExpectedAuthority,
    load_discovery_authority,
)
from secp_api.discovery_models import DiscoveryJob, TargetDiscoveryEnrollment
from secp_api.discovery_verification import REQUIRED_WORKER_ROLE, ExpectedWorkerRegistration
from secp_api.enums import (
    DiscoveryDecisionCode,
    DiscoveryJobStatus,
    LiveReadAuthorizationStatus,
    TargetDiscoveryStatus,
    TargetStatus,
    WorkerDiscoveryAdmissionStatus,
    WorkerIdentityMechanism,
    WorkerIdentityStatus,
)
from secp_api.models import (
    ExecutionTarget,
    LiveReadAuthorization,
    TargetOnboarding,
    WorkerDiscoveryAdmission,
    WorkerIdentityRegistration,
)

NOW = datetime(2026, 8, 6, 12, 0, 0, tzinfo=UTC)
ANCHOR = "sha256:" + "a" * 64
RELEASE = "sha256:" + "r" * 64
WORKER = "wk-lab-1"
CREDENTIAL_REF = "vault:secp/discovery/target-abc"


def _build(session, principal, **overrides):
    """One complete, valid authority chain in the database. Overrides tweak exactly one row."""
    org = principal.organization_id

    target = ExecutionTarget(
        organization_id=org,
        display_name="lab",
        plugin_name="proxmox",
        config={"base_url": "https://pve.example.test:8006/api2/json"},
        config_hash="sha256:" + "c" * 64,
        provider_plan_secret_ref=overrides.get("credential_reference", CREDENTIAL_REF),
        status=TargetStatus.active,
    )
    if overrides.get("target_organization_id"):
        target.organization_id = overrides["target_organization_id"]
    session.add(target)
    session.flush()

    onboarding = TargetOnboarding(
        organization_id=org,
        execution_target_id=target.id,
        onboarding_mode="existing_environment",
        isolation_model="logical",
        declared_boundary={"note": "test"},
        boundary_hash="sha256:" + "b" * 64,
    )
    session.add(onboarding)
    session.flush()

    authorization = LiveReadAuthorization(
        organization_id=org,
        execution_target_id=target.id,
        onboarding_id=onboarding.id,
        connection_hash="sha256:" + "1" * 64,
        boundary_hash="sha256:" + "b" * 64,
        authorization_version=overrides.get("authorization_version", 2),
        authorization_expiry=overrides.get("authorization_expiry", NOW + timedelta(hours=2)),
        collector_contract_version="v1",
        endpoint_allowlist_version="v1",
        evidence_source="worker",
        verification_level="strict",
        status=overrides.get("authorization_status", LiveReadAuthorizationStatus.approved),
    )
    session.add(authorization)
    session.flush()

    registration = WorkerIdentityRegistration(
        organization_id=overrides.get("registration_organization_id", org),
        mechanism=WorkerIdentityMechanism.ed25519_signed_nonce,
        identity_label=WORKER,
        deployment_binding="site-a",
        verification_anchor_fingerprint=overrides.get("anchor", ANCHOR),
        identity_version=overrides.get("registration_identity_version", 4),
        expiry=overrides.get("registration_expiry", NOW + timedelta(days=30)),
        status=overrides.get("registration_status", WorkerIdentityStatus.approved),
    )
    session.add(registration)
    session.flush()

    if overrides.get("release", RELEASE):
        _enroll(session, org, overrides.get("release", RELEASE))

    discovery_enrollment = TargetDiscoveryEnrollment(
        organization_id=org,
        execution_target_id=target.id,
        onboarding_id=onboarding.id,
        display_name="authority loader",
        ownership_label="secp-read-only",
        resource_profile="small_lab",
        status=TargetDiscoveryStatus.plan_ready,
        decision_code=DiscoveryDecisionCode.pending,
        enrollment_version=1,
        revision=1,
    )
    session.add(discovery_enrollment)
    session.flush()

    job = DiscoveryJob(
        enrollment_id=discovery_enrollment.id,
        organization_id=org,
        operation_fingerprint="sha256:" + "5" * 64,
        enrollment_version=1,
        status=DiscoveryJobStatus.completed,
        revision=1,
        attempt_count=1,
    )
    session.add(job)
    session.flush()

    admission = WorkerDiscoveryAdmission(
        organization_id=overrides.get("admission_organization_id", org),
        worker_registration_id=registration.id,
        identity_version=overrides.get("admission_identity_version", 4),
        discovery_job_id=job.id,
        enrollment_id=discovery_enrollment.id,
        execution_target_id=target.id,
        onboarding_id=onboarding.id,
        live_read_authorization_id=authorization.id,
        authorization_version=overrides.get("admission_authorization_version", 2),
        endpoint_binding_hash="sha256:" + "e" * 64,
        purpose=overrides.get("purpose", DISCOVERY_ADMISSION_PURPOSE),
        nonce=uuid.uuid4().hex,
        status=overrides.get("admission_status", WorkerDiscoveryAdmissionStatus.admitted),
        issued_at=NOW - timedelta(minutes=5),
        expires_at=overrides.get("admission_expiry", NOW + timedelta(minutes=30)),
    )
    session.add(admission)
    session.flush()
    return admission, target, registration, authorization


def _enroll(session, org, release):
    from secp_api import worker_enrollment_models as enrollment

    session.add(
        enrollment.WorkerEnrollmentState(
            enrollment_id="sha256:" + "33" * 32,
            organization_id=org,
            deployment_site_label="site-a",
            contract_version="secp-enrollment/v1",
            state="healthy",
            revision=1,
            sequence=1,
            controller_installation_id="controller-installation-1",
            controller_key_id="sha256:" + "k" * 64,
            worker_installation_id=WORKER,
            worker_key_id=ANCHOR,
            release_digest=release,
            transaction_id="txn-0001",
            expires_at=(NOW + timedelta(days=30)).isoformat(),
            updated_at=NOW.isoformat(),
            state_digest="sha256:" + "s" * 64,
            expires_at_ts=NOW + timedelta(days=30),
        )
    )
    session.flush()


def _load(session, principal, admission, **kw):
    return load_discovery_authority(
        session,
        admission_id=admission.id,
        organization_id=principal.organization_id,
        now=kw.get("now", NOW),
    )


# === the happy path, which is the whole point ====================================================


def test_the_authority_is_composed_from_three_independent_durable_sources(session, principal):
    admission, target, registration, authorization = _build(session, principal)
    authority = _load(session, principal, admission)

    assert isinstance(authority, DiscoveryExpectedAuthority)
    assert isinstance(authority.operation, AuthorizedDiscoveryOperation)
    assert isinstance(authority.registration, ExpectedWorkerRegistration)

    # From the ADMISSION row.
    assert authority.operation.organization_identity == str(principal.organization_id)
    assert authority.operation.target_identity == str(target.id)
    assert authority.operation.operation_identity == str(admission.discovery_job_id)
    assert authority.operation.operation_generation == authorization.authorization_version

    # From the REGISTRATION row.
    assert authority.registration.worker_installation_id == WORKER
    assert authority.registration.verification_anchor_fingerprint == ANCHOR

    # From the ENROLLMENT row — a different table with a different lifecycle.
    assert authority.registration.worker_release_fingerprint == RELEASE

    # From the PROVIDER DISCOVERY CONTRACT — no row at all.
    assert authority.required_worker_role == REQUIRED_WORKER_ROLE == "proxmox_privileged"

    # From the TARGET row, as an opaque pointer.
    assert authority.operation.credential_reference == CREDENTIAL_REF


def test_no_caller_can_supply_any_expected_value(session, principal):
    """The loader takes an admission id and an organization scope. Nothing else."""
    import inspect

    params = set(inspect.signature(load_discovery_authority).parameters)
    assert params == {"session", "admission_id", "organization_id", "now"}
    for banned in (
        "expected_target",
        "target_identity",
        "worker_installation_id",
        "worker_role",
        "verification_anchor_fingerprint",
        "release",
        "generation",
        "credential",
    ):
        assert banned not in params, banned


def test_the_credential_reference_is_a_pointer_and_never_a_secret(session, principal):
    """It is carried so the worker can resolve it. It is never resolved here, and the loader
    imports nothing that could."""
    import ast
    import pathlib

    admission, _t, _r, _a = _build(session, principal)
    authority = _load(session, principal, admission)
    assert authority.operation.credential_reference.startswith("vault:")

    source = (
        pathlib.Path(__file__).resolve().parents[1] / "secp_api" / "discovery_authority_loader.py"
    )
    tree = ast.parse(source.read_text(encoding="utf-8"))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    for banned in ("subprocess", "os", "httpx", "requests", "secp_worker"):
        assert banned not in imported, banned


# === nineteen refusals, each naming the row an operator must fix =================================


@pytest.mark.parametrize(
    "overrides,reason",
    [
        ({"admission_status": WorkerDiscoveryAdmissionStatus.challenged}, "admission_not_admitted"),
        ({"admission_status": WorkerDiscoveryAdmissionStatus.consumed}, "admission_not_admitted"),
        ({"admission_expiry": NOW - timedelta(seconds=1)}, "admission_expired"),
        ({"purpose": "readonly_staging_preflight"}, "admission_purpose_mismatch"),
        (
            {"authorization_status": LiveReadAuthorizationStatus.draft},
            "live_read_authorization_not_approved",
        ),
        (
            {"authorization_status": LiveReadAuthorizationStatus.revoked},
            "live_read_authorization_not_approved",
        ),
        (
            {"authorization_expiry": NOW - timedelta(seconds=1)},
            "live_read_authorization_expired",
        ),
        (
            {"authorization_version": 3, "admission_authorization_version": 2},
            "live_read_authorization_version_superseded",
        ),
        (
            {"registration_status": WorkerIdentityStatus.draft},
            "worker_registration_not_approved",
        ),
        (
            {"registration_status": WorkerIdentityStatus.revoked},
            "worker_registration_not_approved",
        ),
        ({"registration_expiry": NOW - timedelta(seconds=1)}, "worker_registration_expired"),
        (
            {"registration_identity_version": 5, "admission_identity_version": 4},
            "worker_registration_version_superseded",
        ),
        ({"anchor": "   "}, "verification_anchor_absent"),
        ({"release": ""}, "worker_release_absent"),
        ({"credential_reference": ""}, "credential_reference_absent"),
        ({"credential_reference": "   "}, "credential_reference_absent"),
    ],
)
def test_each_broken_row_refuses_with_its_own_reason(session, principal, overrides, reason):
    admission, _t, _r, _a = _build(session, principal, **overrides)
    with pytest.raises(DiscoveryAuthorityRefused) as exc:
        _load(session, principal, admission)
    assert exc.value.reason == f"discovery_{reason}", exc.value.reason


def test_an_absent_admission_refuses(session, principal):
    with pytest.raises(DiscoveryAuthorityRefused) as exc:
        load_discovery_authority(
            session, admission_id=uuid.uuid4(), organization_id=principal.organization_id, now=NOW
        )
    assert exc.value.reason == "discovery_admission_absent"


def test_a_foreign_organization_cannot_authorize_itself(session, principal, other_org_principal):
    """The organization is CHECKED against the row, not derived from it. Deriving it is how a
    cross-tenant admission id authorizes itself."""
    admission, _t, _r, _a = _build(session, principal)
    with pytest.raises(DiscoveryAuthorityRefused) as exc:
        load_discovery_authority(
            session,
            admission_id=admission.id,
            organization_id=other_org_principal.organization_id,
            now=NOW,
        )
    assert exc.value.reason == "discovery_admission_wrong_organization"


def test_every_refusal_reason_is_in_the_closed_set(session, principal):
    """A reason outside the set would reach an operator surface unreviewed."""
    with pytest.raises(ValueError, match="unknown discovery authority refusal reason"):
        DiscoveryAuthorityRefused("something_new")
    assert len(AUTHORITY_REFUSAL_REASONS) == len(set(AUTHORITY_REFUSAL_REASONS))
    for reason in AUTHORITY_REFUSAL_REASONS:
        assert reason.startswith("discovery_"), reason


def test_the_generic_secret_ref_can_never_satisfy_a_discovery_run(session, principal):
    """The dedicated read-only provider reference, never the generic fallback. A live run that
    silently fell back would read a real target with a credential nobody dedicated to the purpose.
    """
    admission, target, _r, _a = _build(session, principal, credential_reference="")
    target.secret_ref = "vault:secp/generic/dev"
    session.flush()
    with pytest.raises(DiscoveryAuthorityRefused) as exc:
        _load(session, principal, admission)
    assert exc.value.reason == "discovery_credential_reference_absent"


def test_a_refusal_carries_no_row_contents(session, principal):
    """The reason is a closed code. A refusal that quoted the row would put a credential reference,
    a target id or an anchor into whatever logged it."""
    admission, target, registration, _a = _build(
        session, principal, admission_expiry=NOW - timedelta(seconds=1)
    )
    with pytest.raises(DiscoveryAuthorityRefused) as exc:
        _load(session, principal, admission)
    text = str(exc.value)
    assert text == "discovery_admission_expired"
    for secret_ish in (CREDENTIAL_REF, ANCHOR, RELEASE, str(target.id), str(registration.id)):
        assert secret_ish not in text
