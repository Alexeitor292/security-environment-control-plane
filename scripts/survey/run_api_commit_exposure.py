#!/usr/bin/env python3
"""Run the API commit-exposure survey and print its report.

    uv run python scripts/survey/run_api_commit_exposure.py

Three passes, in order, each refusing to report a zero it cannot vouch for:

  1. route census      which routes resolve a session, and at what dependency scope
  2. commit census     where anything commits, and whether that commit is on a success path
  3. measurement       a real socket, a real HTTP client, and the two timestamps that decide it

Exits non-zero if any pass fails its own non-vacuity checks. A clean exit means the numbers printed
were measured over a population the tool can account for — not that no exposure exists.
"""

from __future__ import annotations

import os
import pathlib
import sys
import tempfile
import uuid

REPO = pathlib.Path(__file__).resolve().parents[2]
for _rel in (
    "apps/api",
    "apps/worker",
    "apps/commissioning",
    "apps/deployment",
    "apps/management",
    "contracts/scenario-schema",
    "contracts/plugin-api",
    "plugins/simulator",
    "plugins/proxmox",
):
    sys.path.insert(0, str(REPO / _rel))
sys.path.insert(0, str(REPO / "apps/api/tests"))

os.environ.setdefault("SECP_APP_ENV", "test")
os.environ.setdefault("SECP_WORKFLOW_DISPATCH_MODE", "inline")

import httpx  # noqa: E402
import secp_api.immutability  # noqa: E402,F401  (registers ORM immutability guards)
from commit_exposure_survey.census import (  # noqa: E402
    census_commit_sites,
    census_routes,
    verify_commit_census,
    verify_route_census,
)
from commit_exposure_survey.live_api_server import live_api_server  # noqa: E402
from commit_exposure_survey.measure import (  # noqa: E402
    CommitRecorder,
    RequestObservation,
    timed_asgi_app,
    verify_instrument,
    verify_savepoint_discrimination,
)
from secp_api.db import get_sessionmaker, reset_engine_for_tests  # noqa: E402
from secp_api.models import Base  # noqa: E402
from secp_api.seed import bootstrap_dev  # noqa: E402

HTTP_TIMEOUT = 60.0


def rule(title: str) -> None:
    print("\n" + "=" * 96)
    print(title)
    print("=" * 96)


def build_prerequisites():
    """Create the durable state the write recipes need, directly (never over HTTP)."""
    from conftest import VALID_DEFINITION  # apps/api/tests/conftest.py
    from secp_api.services import catalog
    from test_environment_publication_service import (  # apps/api/tests
        approve_topology,
        base_definition,
    )

    factory = get_sessionmaker()
    with factory() as session:
        principal = bootstrap_dev(session)
        session.commit()
        template = catalog.create_template(
            session, principal, name="Survey", slug=f"survey-{uuid.uuid4().hex[:8]}"
        )
        session.commit()
        version = catalog.create_version(
            session, principal, template_id=template.id, definition=VALID_DEFINITION
        )
        session.commit()
        approved = approve_topology(session, principal, name="survey-doc")
        session.commit()
        return {
            "template_id": str(template.id),
            "version_id": str(version.id),
            "definition": VALID_DEFINITION,
            "publish_body": {
                "template_id": str(template.id),
                "definition": base_definition(),
                "topology_document_id": str(approved.document_id),
                "topology_revision_id": str(approved.revision_id),
                "expected_topology_content_hash": approved.content_hash,
                "validation_result_id": str(approved.validation_id),
                "base_environment_version_id": None,
            },
        }


def recipes(ctx: dict) -> list[tuple[str, str, str, dict | None]]:
    """(label, method, path, json-body). Deliberately small and hand-built: an endpoint driven with
    a guessed body returns 4xx and is reported NOT_MEASURED, which is honest but useless."""
    tid = ctx["template_id"]
    return [
        ("liveness (no session)", "GET", "/health", None),
        ("read: list templates", "GET", "/api/v1/templates", None),
        ("read: principal", "GET", "/api/v1/me", None),
        (
            "write: create template",
            "POST",
            "/api/v1/templates",
            {"name": "survey", "slug": f"survey-w-{uuid.uuid4().hex[:8]}"},
        ),
        (
            "write: create version",
            "POST",
            f"/api/v1/templates/{tid}/versions",
            {"definition": ctx["definition"]},
        ),
        (
            "write: create exercise",
            "POST",
            "/api/v1/exercises",
            {
                "template_id": tid,
                "version_id": ctx["version_id"],
                "name": f"survey-{uuid.uuid4().hex[:6]}",
            },
        ),
        # The next two live in routers that DO contain a session.commit() — but only inside an
        # except handler. Driving their SUCCESS path is the whole point: a source-level reading
        # would call these protected, and only running them shows otherwise.
        (
            "write: topology draft [router commits on error path]",
            "POST",
            "/api/v1/topology-authoring/documents",
            {"display_name": "survey draft", "document": _topology()},
        ),
        (
            "write: worker-identity register [router commits on error path]",
            "POST",
            "/api/v1/worker-identity/registrations",
            {
                "mechanism": "mtls_workload_identity",
                "identity_label": f"survey-{uuid.uuid4().hex[:6]}",
                "deployment_binding": "survey-deploy",
                "verification_anchor_fingerprint": _anchor_fingerprint(),
            },
        ),
        (
            "write: PUBLISH [router commits on success path]",
            "POST",
            "/api/v1/environment-versions/publish",
            ctx["publish_body"],
        ),
    ]


def _anchor_fingerprint() -> str:
    from secp_api.worker_identity_contract import compute_verification_anchor_fingerprint

    return compute_verification_anchor_fingerprint("survey-public-anchor-v1")


def _topology() -> dict:
    from test_environment_publication_service import base_topology

    return base_topology()


def main() -> int:
    problems: list[str] = []

    tmp = pathlib.Path(tempfile.mkdtemp(prefix="secp-survey-"))
    engine = reset_engine_for_tests(f"sqlite+pysqlite:///{(tmp / 'survey.db').as_posix()}")
    Base.metadata.create_all(engine)

    from secp_api.main import create_app

    ctx = build_prerequisites()
    app = create_app()
    app.router.on_startup.clear()
    asgi, timer = timed_asgi_app(app)

    # --- pass 1: route census -------------------------------------------------------------------
    rule("PASS 1 — ROUTE CENSUS (from the resolved Dependant tree, not from route decorators)")
    facts = census_routes(app)
    route_problems = verify_route_census(facts, app)
    problems += [f"route census: {p}" for p in route_problems]
    print(f"non-vacuity: {route_problems or 'OK — the census had a population to count'}")

    writes = [f for f in facts if f.is_write]
    reads = [f for f in facts if not f.is_write]
    write_with_session = [f for f in writes if f.uses_db_session]
    scoped = [f for f in facts if any(s is not None for s in f.db_session_scopes)]
    print(f"\n(method, path) operations : {len(facts)}")
    print(f"  write methods           : {len(writes)}")
    print(f"  read methods            : {len(reads)}")
    print(f"  write + resolves session: {len(write_with_session)}")
    print(f"  ANY dependency with an explicit scope=: {len(scoped)}")

    # --- pass 2: commit census ------------------------------------------------------------------
    rule("PASS 2 — COMMIT CENSUS (AST of the loaded modules; success path vs except handler)")
    commits = census_commit_sites()
    commit_problems = verify_commit_census(commits)
    problems += [f"commit census: {p}" for p in commit_problems]
    print(f"non-vacuity: {commit_problems or 'OK — known commits found and classified'}")
    print(f"\nmodules scanned: {commits.modules_scanned}, commit sites: {len(commits.sites)}")
    print("\nPROTECTIVE (real commit, reachable without raising):")
    for site in commits.success_path_sites():
        print(f"   {site.module}:{site.lineno}  {site.enclosing}()")
    print("\nNOT protective — only inside an except handler:")
    for site in commits.error_path_sites():
        print(f"   {site.module}:{site.lineno}  {site.enclosing}()")
    print("\nNOT protective — SAVEPOINT release (begin_nested), makes nothing durable:")
    for site in commits.savepoint_sites():
        print(f"   {site.module}:{site.lineno}  {site.enclosing}()  receiver={site.receiver!r}")

    # --- pass 3: measurement --------------------------------------------------------------------
    rule("PASS 3 — MEASUREMENT (real socket; response-completion vs writing-commit timestamps)")
    discriminates, note = verify_savepoint_discrimination(CommitRecorder())
    print(f"savepoint discrimination: {'OK' if discriminates else 'BROKEN'} — {note}")
    if not discriminates:
        problems.append(f"instrument: {note}")

    recorder = CommitRecorder()
    observations: list[RequestObservation] = []
    with recorder.installed(engine), live_api_server(asgi) as server:
        with httpx.Client(base_url=server.base_url, timeout=HTTP_TIMEOUT) as client:
            for label, method, path, body in recipes(ctx):
                recorder.reset()
                timer.reset()
                observation = RequestObservation(label=label, method=method, path=path)
                try:
                    response = client.request(method, path, json=body)
                    observation.status = response.status_code
                    if not (200 <= response.status_code < 300):
                        observation.note = f"body: {response.text[:120]}"
                except httpx.HTTPError as exc:
                    observation.note = f"transport error: {exc}"
                observation.commits = recorder.drain()
                observation.response_completed_at = timer.completed_at
                observations.append(observation)
                if label.startswith("read: list"):
                    instrument_problems = verify_instrument(recorder, timer)
                    problems += [f"instrument: {p}" for p in instrument_problems]
                    print(
                        "instrument non-vacuity (checked on a known-good request): "
                        f"{instrument_problems or 'OK — a commit and a response were both seen'}"
                    )

    print()
    width = max(len(o.label) for o in observations)
    for observation in observations:
        print(
            f"  {observation.verdict():<13} {observation.label:<{width}}  "
            f"[{observation.status}] {observation.detail()}"
        )

    rule("BLAST RADIUS")
    exposed = [o for o in observations if o.verdict() == "EXPOSED"]
    not_exposed = [o for o in observations if o.verdict() == "NOT_EXPOSED"]
    no_write = [o for o in observations if o.verdict() == "NO_WRITE"]
    unmeasured = [o for o in observations if o.verdict() == "NOT_MEASURED"]
    print(f"measured and EXPOSED      : {len(exposed)}")
    print(f"measured and NOT exposed  : {len(not_exposed)}")
    print(f"measured, no write        : {len(no_write)}")
    print(f"NOT MEASURED              : {len(unmeasured)}  <- not evidence of safety")
    protective_modules = {
        site.module for site in commits.success_path_sites() if site.module != "secp_api.db"
    }
    projected = [f for f in write_with_session if f.endpoint_module not in protective_modules]
    print(
        f"\nCENSUS PROJECTION: {len(projected)} of {len(write_with_session)} write operations that "
        "resolve a session sit in a module with NO protective success-path commit."
    )
    print(
        "  Method: census (complete, from the route table) x commit classification (complete, "
        "from the AST), with the ordering itself measured on the sample above. Endpoints in "
        f"{sorted(protective_modules) or '[]'} are excluded from the projection because they hold "
        "a real success-path commit; that exclusion is measured, not assumed."
    )

    engine.dispose()
    if problems:
        print("\nSURVEY INTEGRITY PROBLEMS — the numbers above are not trustworthy:")
        for problem in problems:
            print(f"  - {problem}")
        return 1
    print("\nAll three passes vouched for their own population.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
