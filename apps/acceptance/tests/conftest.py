"""Tier gating for the acceptance suite, and the session-scoped acceptance run.

``pytest_collection_modifyitems``
    When the container tier was NOT declared, container-tier tests are DESELECTED, not skipped. A
    deselected test is absent from the report; a skipped one is a green tick with a footnote, and a
    reader scanning a CI summary sees the tick.

``acceptance_run`` (session fixture)
    THE run: one recorder, one fleet, one document, shared by every stage. Session-scoped because
    four streams produce the nine evidence stages, and a per-module recorder would yield four
    partial documents that cannot be reconciled — see :mod:`secp_acceptance.run` for the four-line
    contract a stage is written against.

``pytest_sessionfinish``
    Two jobs, in this order. First it seals and writes the run's evidence, on EVERY path including
    failure — a failed run's evidence is the record of what was and was not established, and writing
    it only on success would mean it exists exactly when nobody needs it. Then, when the container
    tier WAS declared, it fails the session unless the tier left a complete witness. That second
    half is what a skip cannot satisfy and what mechanism 1 cannot catch: a container body that
    never executed at all — deselected by a stray ``-k``, renamed, or lost to a collection error —
    leaves every collected test passing and the run green. Here it does not.

All of this is scoped to ``apps/acceptance/tests`` so the ordinary CI shards, which collect this
directory for its hermetic contract tests, are unaffected except for the deselection. A hermetic
shard opens no stage, so it seals and writes nothing.
"""

from __future__ import annotations

import os
import pathlib

import pytest
from secp_acceptance import AcceptanceError
from secp_acceptance.run import AcceptanceRun
from secp_acceptance.tier import (
    ENV_TIER,
    TIERS,
    assert_tier_witnessed,
    container_tier_required,
    declared_tier,
    missing_witnesses,
)

#: Enables the ``pytester`` fixture. The tier gate's whole value is in two pytest HOOKS, and a hook
#: can only be proven by running a real pytest session over a real conftest — asserting on the hook
#: functions directly would test the bodies while leaving "is this hook actually wired up?"
#: unmeasured, which is the half that silently breaks.
pytest_plugins = ["pytester"]

#: Applied to every test that needs a real container runtime.
CONTAINER_MARKER = "container_tier"


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line(
        "markers",
        f"{CONTAINER_MARKER}: needs a real container runtime; deselected unless the container "
        f"tier is declared, and REFUSED (never skipped) when it is declared and Docker is absent",
    )
    # Fail immediately on a malformed tier declaration rather than at the first container test: a
    # typo in the acceptance workflow must not present as "no container tests were collected".
    # Reported as a UsageError so it exits as a clean, attributable configuration failure rather
    # than an INTERNALERROR traceback that a reader has to decode.
    try:
        declared_tier()
    except AcceptanceError as exc:
        raise pytest.UsageError(
            f"{exc.reason_code}: {ENV_TIER}={os.environ.get(ENV_TIER)!r} is not a known "
            f"acceptance tier. Use one of: {', '.join(sorted(TIERS))}."
        ) from None


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    if container_tier_required():
        return
    keep: list[pytest.Item] = []
    drop: list[pytest.Item] = []
    for item in items:
        (drop if item.get_closest_marker(CONTAINER_MARKER) else keep).append(item)
    if drop:
        config.hook.pytest_deselected(items=drop)
        items[:] = keep


#: Where the session's run is parked so ``pytest_sessionfinish`` can seal it. A hook cannot request
#: a fixture, and the document MUST be written on the failure paths — which is exactly when a run's
#: evidence is worth the most — so the run is reachable from the config rather than from the fixture
#: graph.
_RUN_ATTRIBUTE = "_secp_acceptance_run"


@pytest.fixture(scope="session")
def acceptance_run(request: pytest.FixtureRequest) -> AcceptanceRun:
    """THE run. One recorder, one fleet, one document, for the whole session.

    Session-scoped on purpose: four streams produce the nine stages, and a per-module recorder would
    give four partial documents that cannot be reconciled. Stages are handed this; they never build
    their own.

    Not gated on the container tier. A hermetic session may hold one and never open a stage, which
    seals nothing — the document is written only when a stage was actually opened.
    """
    run = AcceptanceRun()
    setattr(request.config, _RUN_ATTRIBUTE, run)
    return run


# --------------------------------------------------------------------------- the one fleet
#
# THE FLEET IS SESSION-SCOPED FOR THE SAME REASON THE RUN IS.
#
# The evidence document carries exactly ONE ``FleetRecord``. Two module-scoped fleets in a session
# would produce a document describing one machine pair while carrying claims gathered against two —
# and nothing downstream could tell, because the claims look identical either way. That is
# undetectable after the fact, which is why ``AcceptanceRun.set_fleet`` refuses a second, different
# record outright rather than trusting every stage to remember the convention.
#
# It is also the cheaper arrangement by a wide margin: the host image build plus two privileged
# systemd containers with nested daemons is the most expensive thing in the run, and it now happens
# once no matter how many stage modules execute.


@pytest.fixture(scope="session")
def runtime_version() -> str:
    """Prove the OUTER container runtime before anything is built.

    REFUSES when Docker is absent — never skips. This is where "Docker is down" becomes a loud,
    bounded, attributable failure instead of a quiet green run that measured nothing.
    """
    from secp_acceptance.tier import require_container_runtime_or_refuse

    return require_container_runtime_or_refuse()


@pytest.fixture(scope="session")
def fleet(runtime_version: str, acceptance_run: AcceptanceRun):
    """THE disposable two-host fleet. Built once, destroyed on every path including failure.

    The fleet RECORD is set during teardown rather than after creation, deliberately: the record
    carries ``hosts_destroyed``, so a record taken while the fleet was still up would permanently
    report zero teardown no matter what actually happened. Teardown runs before
    ``pytest_sessionfinish`` (verified, not assumed), so the record is in place before the run is
    sealed.

    ``set_fleet`` is called exactly once for that reason too — it refuses a second, differing
    record, and the pre-teardown and post-teardown records genuinely differ.
    """
    import uuid

    from secp_acceptance.hosts import HostFleet
    from secp_acceptance.release import repo_root
    from secp_acceptance.tier import witness

    built = HostFleet(prefix=f"secp-acc-{uuid.uuid4().hex[:10]}")
    infra = repo_root() / "infra" / "acceptance"
    try:
        built.build_image(context=str(infra), dockerfile=str(infra / "Dockerfile.host"))
        built.create()
        witness("fleet_created")
        yield built
    finally:
        clean, residual = built.destroy()
        witness("fleet_torn_down")
        acceptance_run.set_fleet(built.record())
        # Reported, not swallowed. A leaked privileged container with a nested Docker daemon is the
        # most expensive thing this harness can leave behind, and it must not be discoverable only
        # by noticing a slow disk on the next run.
        assert clean, f"the disposable fleet did not fully tear down: {residual}"


@pytest.fixture(scope="session")
def controller_host(fleet):
    """The controller host, for stages that need to reach it directly."""
    from secp_acceptance.hosts import ROLE_CONTROLLER

    return fleet.hosts[ROLE_CONTROLLER]


@pytest.fixture(scope="session")
def worker_host(fleet):
    """The worker host, for stages that need to reach it directly."""
    from secp_acceptance.hosts import ROLE_WORKER

    return fleet.hosts[ROLE_WORKER]


#: The run-scoped realm the acceptance operator authenticates against.
#:
#: THE NAME IS FIXED BY CHOICE, NOT BY CONSTRAINT — a correction to an earlier claim here.
#:
#: This constant previously carried a justification that the issuer had to be deterministic at
#: RELEASE-BUILD time, because the API reads it from a SIGNED Compose artifact. That was wrong, and
#: wrong in the direction that invents work: the reviewed ``infra/dev/docker-compose.yml`` supplies
#: the issuer by Compose ``${VAR}`` substitution, so it has always been a DEPLOY-TIME parameter.
#: The signed template now names the variable and the value is supplied when the stack starts —
#: after the fleet, and therefore the realm, exist. The omission was in our template, not in the
#: product; a real deployment must point at the customer's own IdP through this same variable, so
#: it could not have been baked.
#:
#: A fixed name is kept only because it is simple and the fleet is disposable — nothing is shared
#: between runs, so there is nothing for a per-run name to protect against.
ACCEPTANCE_REALM = "secp-acceptance"

#: The audience the acceptance token carries. Supplied the same deploy-time way as the issuer.
ACCEPTANCE_AUDIENCE = "secp-api"

#: The bootstrap-admin USERNAME. A name, not a credential — the password is generated per run and
#: never appears here, in the repository, or in the signed release artifact.
ACCEPTANCE_KEYCLOAK_ADMIN = "admin"

#: Where the provisioner reaches Keycloak's admin API. The controller Compose template publishes
#: the container's 8080 on the controller host's LOOPBACK only, so this address exists inside that
#: host and nowhere else on the fleet network — the worker host cannot reach it.
ACCEPTANCE_KEYCLOAK_BASE = "http://localhost:8080"


@pytest.fixture(scope="session")
def operator_token_path(controller_host, fleet):
    """An operator access token on the controller host, or ``None``.

    THE SEAM, and it has two halves that must agree on one string:

    * ``secp_acceptance.enrollment.provision_operator_realm`` (owned by the enrollment stage) makes
      the run-scoped realm, the acceptance user — created WITH id
      :data:`~secp_acceptance.install.ACCEPTANCE_OPERATOR_SUBJECT` — and the 0600 token file, and
      returns its path. Only that stage knows what the token must carry.
    * :func:`~secp_acceptance.install.provision_operator_principal` (owned here) makes the
      controller-side ``app_user`` row and role assignment carrying ``enrollment:manage``.

    BOTH ARE REQUIRED, and that is not obvious from the ask. ``secp_api.auth`` verifies the token
    and then resolves permissions from the DATABASE, explicitly never trusting token roles or
    groups; an unknown ``sub`` is unauthenticated rather than a new user. A realm and a token file
    alone therefore authenticate as nobody, and a realm role named ``enrollment_manage`` is ignored
    by design.

    RETURNS ``None`` RATHER THAN RAISING when either half cannot be completed — including when the
    enrollment stage's provisioner does not exist yet. A stage that errors out records nothing, and
    recording nothing is indistinguishable from passing, so the consumer must be able to record
    ``unproven`` instead of dying.

    Teardown is the fleet's: the realm, the user, the token file and the database row all live
    inside the controller host and are destroyed with it. Nothing here outlives the run.
    """
    from secp_acceptance.install import (
        generate_bootstrap_admin_password,
        provision_operator_principal,
        write_controller_deploy_env,
    )

    try:
        from secp_acceptance.enrollment import (
            provision_operator_realm,  # type: ignore[attr-defined]
        )
    except Exception:  # noqa: BLE001 - the provisioner is another stage's; absent is not an error
        return None
    try:
        # The issuer is supplied HERE, at deploy time, into the `.env` beside the signed compose
        # file — the signed artifact names the variable and never carries the value.
        # Generated per run, written only into the 0600 `.env` on the controller host, and handed
        # to the provisioner in memory. The enrollment stage deliberately refused to invent this —
        # a credential a module made up is one nobody can trace to a source — and it belongs to
        # whoever composes the stack, which is this fixture.
        admin_password = generate_bootstrap_admin_password()
        write_controller_deploy_env(
            controller_host,
            issuer=f"https://{controller_host.dns_name}:8443/realms/{ACCEPTANCE_REALM}",
            audience=ACCEPTANCE_AUDIENCE,
            keycloak_admin=ACCEPTANCE_KEYCLOAK_ADMIN,
            keycloak_password=admin_password,
        )
        # EXACTLY `enrollment:manage`, never the seeded platform-admin. `seed.bootstrap_dev` grants
        # a role holding every Permission, and a stage driving the enrollment API as god-mode
        # cannot detect a permission-scoping defect: anything that ought to fail for want of this
        # one permission would pass, and no check in that stage could tell.
        provision_operator_principal(controller_host, permissions=("enrollment:manage",))
        return provision_operator_realm(
            controller_host,
            realm=ACCEPTANCE_REALM,
            keycloak_base=ACCEPTANCE_KEYCLOAK_BASE,
            admin_user=ACCEPTANCE_KEYCLOAK_ADMIN,
            admin_password=admin_password,
        )
    except Exception:  # noqa: BLE001 - bounded; the consumer records unproven rather than aborting
        return None


@pytest.fixture(scope="session")
def installed_baseline(worker_host) -> dict[str, object]:
    """The worker's installed release LINEAGE, read off the host from the RELEASE RECORD.

    READS ``ManagementLocations.release_record_path("worker")`` — i.e.
    ``worker-installed-release.json``, the signed manifest the bootstrap transaction recorded.

    CORRECT FOR: rollback and upgrade lineage — the ``worker_install`` and ``lifecycle`` stages.
    Those ask "which release is installed here", and the release record is the document that
    answers it.

    NOT CORRECT FOR the enrollment/identity question "does the enrolled release equal the installed
    one". That check mirrors the product's own ``exact_release`` probe, and **that probe reads the
    IDENTITY document** (``ManagementLocations.identity_path("worker")`` —
    ``worker-identity.json``), which is a different file recording a different fact. Sourcing it
    from here would produce a check that can disagree with the probe it exists to reflect: passing
    where the product refuses, or failing where it does not. An earlier version of this docstring
    offered the fixture to "the enrollment, identity and lifecycle stages" and was wrong to — the
    phrase "the worker's installed release" names two facts, and only one of them lives here.

    WHAT IT PRESERVES: what the harness BELIEVES it installed and what the host HAS are different
    facts, and a proof built on the former would still pass if the install had quietly put
    something else there. So it re-reads the product's own record through the product's own manifest
    parser.

    ``{"present": False, ...}`` means no release record exists — record that ``unproven``, never as
    a mismatch and never as proof of removal. Absence established by a failed READ would let a
    rollback that removed nothing read as one that worked, which is why the read and the existence
    probe are separate here.

    Session-scoped so every consumer sees the same baseline. It is a READ, so it is safe to take
    before or after any stage — but a caller wanting the POST-install baseline must order itself
    after the worker install, because this fixture will truthfully report the absence that precedes
    it rather than waiting for one to appear.
    """
    from secp_acceptance.hosts import ROLE_WORKER
    from secp_acceptance.install import observe_installed_release

    return observe_installed_release(worker_host, ROLE_WORKER)


def _seal_the_run(session: pytest.Session) -> None:
    """Seal and write the evidence document for a session that actually opened a stage.

    Runs on EVERY path including failure. A failed run's evidence is the most valuable evidence the
    harness produces — it is the record of what was and was not established — and writing it only on
    success would mean the document exists exactly when nobody needs to consult it.

    A session that opened no stage writes nothing. That is not a silent skip: there is no run to
    describe, and an empty document would be a claim rather than an absence.
    """
    run = getattr(session.config, _RUN_ATTRIBUTE, None)
    if run is None or not run.stages:
        return
    reporter = session.config.pluginmanager.get_plugin("terminalreporter")
    try:
        # pytest's own rootpath, not a search for the repo root: it is always defined, it is where
        # the acceptance workflow's upload step looks, and a search would raise inside any session
        # whose working tree does not look like this repository.
        path = run.write(pathlib.Path(session.config.rootpath))
    except AcceptanceError as exc:
        # Stages ran but the document could not be sealed — most likely no fleet was ever recorded.
        # That is a harness failure and must fail the session: a run that produced observations and
        # then could not say what it observed them ABOUT is not an acceptance result.
        session.exitstatus = pytest.ExitCode.TESTS_FAILED
        if reporter is not None:
            reporter.write_sep("=", "ACCEPTANCE EVIDENCE NOT SEALED", red=True, bold=True)
            reporter.write_line(
                f"{exc.reason_code}: {len(run.stages)} stage(s) recorded checks, but the evidence "
                f"document could not be sealed. This run is NOT an acceptance result."
            )
        return
    if reporter is not None:
        document = run.sealed
        assert document is not None  # write() sealed it or raised
        reporter.write_sep("=", "ACCEPTANCE EVIDENCE", bold=True)
        reporter.write_line(
            f"outcome={document.outcome} stages={len(document.stages_attempted)}/9 "
            f"checks={len(document.checks)} violated={len(document.violated())} "
            f"unproven={len(document.unproven())} missing={len(document.missing_checks())}"
        )
        reporter.write_line(f"written to {path.name} (digest {document.digest()[:19]}...)")


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    """Seal the run's evidence, then fail a declared container tier that did not actually execute.

    Deliberately runs even when ``exitstatus`` is already non-zero: an incomplete tier is worth
    reporting alongside whatever else failed, and suppressing it on an already-failing run would
    hide it exactly when the run is most confusing.

    Sealing happens FIRST, so the document survives even when the witness check is about to fail the
    session — those are the runs whose evidence a reader most needs.

    A ``--collect-only`` session is exempt from BOTH halves. It executed no body, so it neither
    witnessed a tier nor produced an observation, and reporting on either would be describing a run
    that did not happen. This is not a loophole: a collection runs no test, so there is no result to
    falsely green, and the pin guard in ``test_acceptance_node_pin.py`` depends on collection being
    a clean read.
    """
    if getattr(session.config.option, "collectonly", False):
        return
    _seal_the_run(session)
    if not container_tier_required():
        return
    try:
        assert_tier_witnessed()
    except AcceptanceError as exc:
        missing = ", ".join(missing_witnesses())
        session.exitstatus = pytest.ExitCode.TESTS_FAILED
        reporter = session.config.pluginmanager.get_plugin("terminalreporter")
        if reporter is not None:
            reporter.write_sep("=", "ACCEPTANCE TIER NOT EXECUTED", red=True, bold=True)
            reporter.write_line(
                f"{exc.reason_code}: the container tier was declared "
                f"(SECP_ACCEPTANCE_TIER=container) but these stages left no witness: {missing}.\n"
                "Every collected test may have passed; this run is NOT an acceptance result."
            )
