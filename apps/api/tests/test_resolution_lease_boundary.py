"""SECP-B2-3 — static safety guardrails for the durable lease + sealed identity/activation gate.

Proves: the durable schema stores no secret/reference/endpoint; the API cannot import the
worker-only lease/identity/gate internals; production worker code selects ONLY the sealed
deny-by-default identity and disabled activation gate (no approved/static impl or SecretMaterial
construction in production); the lease/identity/gate modules add no backend/network/subprocess/env
client; and the frontend exposes no lease/activation/credential interface.
"""

from __future__ import annotations

import ast
import os
import re
import tempfile
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
API_PKG = REPO_ROOT / "apps" / "api" / "secp_api"
WORKER_PKG = REPO_ROOT / "apps" / "worker" / "secp_worker"
PREFLIGHT_PKG = WORKER_PKG / "preflight"
MIGRATION = (
    REPO_ROOT / "apps" / "api" / "migrations" / "versions" / "c4e9a1f7d2b3_resolution_lease.py"
)


def _py(pkg: Path) -> list[Path]:
    return [p for p in pkg.rglob("*.py") if "__pycache__" not in p.parts]


def test_lease_schema_has_no_secret_reference_or_endpoint_storage():
    from secp_api.models import ResolutionLease

    cols = set(ResolutionLease.__table__.columns.keys())
    forbidden = {
        "secret",
        "secret_ref",
        "secret_reference",
        "credential",
        "credential_ref",
        "credential_reference",
        "token",
        "endpoint",
        "base_url",
        "url",
        "host",
        "certificate",
        "config",
        "reference_hash",
        "secret_hash",
    }
    assert not (cols & forbidden), f"lease model exposes forbidden column(s): {cols & forbidden}"
    # The migration DDL must likewise never mention a secret/reference/endpoint value.
    ddl = MIGRATION.read_text(encoding="utf-8").lower()
    for token in ("secret", "credential", "endpoint", "base_url", "token", "certificate"):
        assert token not in ddl, f"migration references `{token}`"


def test_migration_columns_match_the_safe_model_shape():
    from secp_api.models import ResolutionLease

    ddl = MIGRATION.read_text(encoding="utf-8")
    # Every column defined in the model must appear in the migration by name (secret-free set).
    for col in ResolutionLease.__table__.columns.keys():
        assert f'"{col}"' in ddl, f"migration missing column {col!r}"


def test_migration_upgrade_downgrade_roundtrip_sqlite():
    """Derive revisions from the migration graph (no fragile relative offsets): head is the lease
    migration; one step down removes resolution_lease and keeps readonly_staging_preflight; the
    step below removes readonly_staging_preflight; upgrade restores both."""
    from alembic import command
    from alembic.config import Config
    from alembic.script import ScriptDirectory
    from secp_api.config import get_settings
    from sqlalchemy import create_engine, inspect

    api_dir = REPO_ROOT / "apps" / "api"
    db = os.path.join(tempfile.gettempdir(), f"secp_lease_mig_{os.getpid()}.db")
    if os.path.exists(db):
        os.remove(db)
    url = f"sqlite+pysqlite:///{db}"
    prev = os.environ.get("SECP_DATABASE_URL")
    os.environ["SECP_DATABASE_URL"] = url
    # alembic's env.py resolves the URL via the cached get_settings(); clear it so the migration
    # runs against THIS temp DB (not a URL cached by an earlier test in the suite).
    get_settings.cache_clear()
    try:
        cfg = Config(str(api_dir / "alembic.ini"))
        cfg.set_main_option("script_location", str(api_dir / "migrations"))
        cfg.set_main_option("sqlalchemy.url", url)
        script = ScriptDirectory.from_config(cfg)
        # Derive the revision that CREATES readonly_staging_preflight (robust to migrations added
        # above it, e.g. the lease + resolver-activation migrations). Downgrading to it removes
        # everything above (incl. resolution_lease) while keeping readonly_staging_preflight.
        import re

        preflight_rev = None
        for rev in script.walk_revisions():
            src = Path(rev.module.__file__).read_text(encoding="utf-8")
            if re.search(r'create_table\(\s*"readonly_staging_preflight"', src):
                preflight_rev = rev.revision
                break
        assert isinstance(preflight_rev, str)
        preflight_parent = script.get_revision(preflight_rev).down_revision
        assert isinstance(preflight_parent, str)

        command.upgrade(cfg, "head")
        eng = create_engine(url)

        def tables() -> set[str]:
            return set(inspect(eng).get_table_names())

        assert {"resolution_lease", "readonly_staging_preflight"} <= tables()
        command.downgrade(cfg, preflight_rev)
        assert "resolution_lease" not in tables()
        assert "readonly_staging_preflight" in tables()
        command.downgrade(cfg, preflight_parent)
        assert "readonly_staging_preflight" not in tables()
        command.upgrade(cfg, "head")
        assert {"resolution_lease", "readonly_staging_preflight"} <= tables()
        eng.dispose()
    finally:
        if prev is None:
            os.environ.pop("SECP_DATABASE_URL", None)
        else:
            os.environ["SECP_DATABASE_URL"] = prev
        get_settings.cache_clear()
        if os.path.exists(db):
            os.remove(db)


def test_api_cannot_import_worker_lease_identity_or_gate():
    forbidden_prefixes = (
        "secp_worker.preflight.lease",
        "secp_worker.preflight.identity",
        "secp_worker.preflight.activation_gate",
    )
    for path in _py(API_PKG):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                mod = node.module or ""
                assert not mod.startswith(forbidden_prefixes), f"{path.name} imports from {mod}"
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    assert not alias.name.startswith(forbidden_prefixes), (
                        f"{path.name} imports {alias.name}"
                    )


def _call_name(node: ast.Call) -> str:
    fn = node.func
    return fn.attr if isinstance(fn, ast.Attribute) else getattr(fn, "id", "")


def _worker_identity_calls(tree: ast.AST) -> list[ast.Call]:
    return [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and _call_name(node) == "VerifiedWorkerIdentity"
    ]


def _blessed_return_call_ids(tree: ast.AST) -> set[int]:
    """ids of ``VerifiedWorkerIdentity(...)`` calls that are the value of a ``return`` inside
    ``RegisteredWorkerIdentityVerifier._verify_claim`` — the sole reviewed success path."""
    blessed: set[int] = set()
    for cls in ast.walk(tree):
        if not (isinstance(cls, ast.ClassDef) and cls.name == "RegisteredWorkerIdentityVerifier"):
            continue
        for method in ast.walk(cls):
            if not (isinstance(method, ast.FunctionDef) and method.name == "_verify_claim"):
                continue
            for node in ast.walk(method):
                if (
                    isinstance(node, ast.Return)
                    and isinstance(node.value, ast.Call)
                    and _call_name(node.value) == "VerifiedWorkerIdentity"
                ):
                    blessed.add(id(node.value))
    return blessed


def _check_worker_identity_construction(filename: str, source: str) -> int:
    """Structural guard: a ``VerifiedWorkerIdentity(...)`` construction is permitted ONLY in
    ``worker_identity_attestation.py`` and ONLY as the value returned from the reviewed
    ``RegisteredWorkerIdentityVerifier._verify_claim`` success path. Any construction elsewhere — in
    another worker module, or unconditional/extra/non-return construction in the attestation
    module — raises ``AssertionError``. Returns the number of (blessed) constructions in source."""
    tree = ast.parse(source, filename=filename)
    calls = _worker_identity_calls(tree)
    if not calls:
        return 0
    assert filename == "worker_identity_attestation.py", (
        f"{filename} constructs a VerifiedWorkerIdentity outside the reviewed verifier module"
    )
    blessed = _blessed_return_call_ids(tree)
    for call in calls:
        assert id(call) in blessed, (
            f"{filename} constructs a VerifiedWorkerIdentity outside the reviewed "
            "RegisteredWorkerIdentityVerifier._verify_claim success return path"
        )
    return len(calls)


def test_production_worker_only_constructs_identity_in_the_reviewed_verifier_return():
    # The shipped default identity verifier denies and constructs nothing. Across the whole worker
    # package there must be EXACTLY ONE ``WorkerIdentity(...)`` construction, and it must be the
    # value returned from ``RegisteredWorkerIdentityVerifier._verify_claim`` after all durable
    # checks pass (that verifier is not wired into shipped runtime — a separate guard asserts that).
    total = 0
    for path in _py(WORKER_PKG):
        total += _check_worker_identity_construction(path.name, path.read_text(encoding="utf-8"))
    assert total == 1, (
        f"expected exactly one reviewed VerifiedWorkerIdentity construction, found {total}"
    )


def test_worker_identity_construction_guard_rejects_unsafe_additions():
    # The guard passes on the real, reviewed source...
    attest = (PREFLIGHT_PKG / "worker_identity_attestation.py").read_text(encoding="utf-8")
    assert _check_worker_identity_construction("worker_identity_attestation.py", attest) == 1
    # ...but rejects an EXTRA construction added in an unrelated function of the attestation module,
    poisoned_helper = (
        attest
        + "\n\ndef _forged_identity():\n"
        + "    return VerifiedWorkerIdentity(worker_identity_id='forged')\n"
    )
    with pytest.raises(AssertionError):
        _check_worker_identity_construction("worker_identity_attestation.py", poisoned_helper)
    # ...an UNCONDITIONAL module-level construction,
    poisoned_module = attest + "\n_FORGED = VerifiedWorkerIdentity(worker_identity_id='forged')\n"
    with pytest.raises(AssertionError):
        _check_worker_identity_construction("worker_identity_attestation.py", poisoned_module)
    # ...and ANY construction in a different worker module.
    other_module = (
        "from secp_worker.preflight.identity import WorkerIdentity\n"
        "def sneak():\n    return VerifiedWorkerIdentity(worker_identity_id='forged')\n"
    )
    with pytest.raises(AssertionError):
        _check_worker_identity_construction("consumer.py", other_module)


def test_orchestration_defaults_to_sealed_identity_and_disabled_gate():
    src = (PREFLIGHT_PKG / "orchestration.py").read_text(encoding="utf-8")
    assert "identity_verifier or DenyingWorkerIdentityVerifier()" in src
    assert "activation_gate or SealedActivationGate()" in src
    # The shipped gate always raises; there is no approving gate in the production package.
    gate_src = (PREFLIGHT_PKG / "activation_gate.py").read_text(encoding="utf-8")
    assert "raise ResolutionActivationDisabled" in gate_src
    identity_src = (PREFLIGHT_PKG / "identity.py").read_text(encoding="utf-8")
    assert "raise WorkerIdentityUnavailable" in identity_src


def test_lease_identity_gate_modules_add_no_backend_or_network_client():
    forbidden = (
        "hvac",
        "openbao",
        "import vault",
        "from vault",
        "boto3",
        "botocore",
        "azure",
        "googleapiclient",
        "keyring",
        "getpass",
        "import httpx",
        "import requests",
        "import aiohttp",
        "import socket",
        "from socket",
        "import subprocess",
        "from subprocess",
        "import ssl",
        "os.environ",
        "os.getenv",
        "pathlib",
        "open(",
    )
    for name in ("lease.py", "identity.py", "activation_gate.py"):
        src = (PREFLIGHT_PKG / name).read_text(encoding="utf-8")
        for token in forbidden:
            assert token not in src, f"{name} must not reference `{token}`"


# --- frontend activation-boundary guard -------------------------------------
#
# The frontend is ALLOWED to DISPLAY worker-side refusal vocabulary — fixed
# operator copy for closed reason codes such as worker_identity_missing /
# worker_identity_unapproved. Those are evidence a gate refused a probe, not an
# interface. What the frontend must NEVER contain is a CONTROL surface capable
# of acquiring a resolution lease, activating the worker-side resolver gate,
# entering/resolving credentials, registering/approving/enrolling worker
# identities through generic lifecycle endpoints, submitting raw worker-identity evidence, wiring
# a verifier/attestation surface, or constructing secret material. PR5F permits exactly one narrow
# browser action: a reviewed worker-node composite that atomically invokes the existing lifecycle
# server-side. It may display the resulting registration-link UUID, but no registration/evidence
# object. The guard therefore bans precise IDENTIFIER forms (method / route /
# field / component names) — never generic words, prose, the display refusal
# codes, or the sealed resolver-activation AUTHORIZATION governance surface
# (createResolverActivation / approveResolverActivation / recordResolverActivation
# Evidence / resolverGates / ResolverGate / …), which is an allowed read-only
# decision surface that "never performs activation from this interface".

# Exact worker-side mechanism identifiers (retained indicators). Identifier
# forms only — deliberately distinct from prose ("no lease is issued",
# "activation gate") and from the display refusal codes.
_FORBIDDEN_FRONTEND_LITERALS = (
    "resolution_lease",
    "resolutionLease",
    "activation-gate",
    "activationGate",
    "acquireLease",
    "beginAttempt",
)

# Precise control-interface entry points a real forbidden surface would use.
# Each is anchored to a domain noun (Lease / Gate / WorkerIdentity / Worker+
# management-noun / Credential / Secret / Material / a "password" input) so it
# matches method/route/field/component IDENTIFIERS while never matching the
# display refusal codes, explanatory prose, or the governance/read-only surface.
_FORBIDDEN_FRONTEND_PATTERNS = (
    # (1) acquiring a resolution lease — the durable lease identifier (any
    #     case/separator) and any verb that mints/obtains one.
    re.compile(r"resolution[_-]?lease", re.IGNORECASE),
    re.compile(
        r"(acquire|begin|open|obtain|renew|create|start|request|claim|mint|issue|grant|reserve|take)"
        r"(Resolution)?Lease"
    ),
    # (2) activating the worker-side resolver GATE — the sealed-gate identifier
    #     (any case/separator; e.g. ResolutionActivationGate / SealedActivationGate)
    #     and any verb that opens it. "activation gate(s)" prose has a space and
    #     is not matched; ResolverGate / resolverGates (read-only view-model) have
    #     no leading verb and are not matched.
    re.compile(r"activation[_-]?gate", re.IGNORECASE),
    re.compile(
        r"(activate|open|reopen|unseal|arm|enable|lift|trip|disarm|unlock)"
        r"(Resolution|Resolver)?Gate"
    ),
    # (3) registering / approving / enrolling a worker identity, or submitting its
    #     evidence — camelCase methods (verb+WorkerIdentity, or verb+Worker+optional
    #     management noun) and snake/kebab/path routes. The display refusal codes
    #     worker_identity_missing / worker_identity_unapproved are not management
    #     nouns, and "worker-identity registration" prose uses a space, so none match.
    re.compile(
        r"(register|approve|reject|create|enroll|provision|submit|record|activate|admit|revoke)"
        r"WorkerIdentity"
    ),
    re.compile(
        r"(register|approve|reject|enroll|provision|admit|revoke)"
        r"Worker(Identity|Registration|Admission|Enrollment|Approval|Credential)?\b"
    ),
    re.compile(
        r"worker[_/-]identity[_/-]"
        r"(?!registration[_-]id\b)"
        r"(registration|register|approval|approve|management|enroll(ment)?|evidence|provision|create|admission)"
    ),
    re.compile(r"(Registered|Denying|Sealed)?WorkerIdentity(Verifier|Attestation(Source)?|Claim)"),
    # (4) entering / resolving credentials or constructing secret material. Verb-
    #     anchored so "Credential resolution failed closed" prose and the
    #     credential_unavailable display code (no verb prefix) never match; the
    #     material nouns are Secret/Credential only (never Key/Bundle — a worker
    #     PUBLIC-key bundle is legitimate).
    re.compile(
        r"(resolve|reveal|unseal|decrypt|fetch|construct|build|assemble)"
        r"(Provider|Target|Worker|Live|Read)?(Credential|Secret)"
    ),
    re.compile(r"(Secret|Credential)(Material|Payload)"),
    # (5) a credential/password input field or component — a type-like attribute
    #     set to "password" (incl. JSX-expression / ternary / htmlType / inputType
    #     forms) or a password/secret input component. Anchored to a type= attr so
    #     the audit secret-detection regex /(...|password|...)/ is not matched.
    re.compile(r"""(type|htmlType|inputType)\s*=\s*\{?[^}"']*['"]password['"]"""),
    re.compile(r"(Password|Secret)(Input|Field)"),
)


def _forbidden_frontend_hits(source: str) -> list[str]:
    """Every forbidden control-interface indicator in a frontend source string:
    exact worker-side mechanism identifiers plus the precise lease / gate /
    worker-identity / credential / secret control-entry patterns. Display-only
    refusal codes (worker_identity_missing / _unapproved), explanatory prose, and
    the resolver-activation governance surface produce no hit."""
    hits = [lit for lit in _FORBIDDEN_FRONTEND_LITERALS if lit in source]
    for pattern in _FORBIDDEN_FRONTEND_PATTERNS:
        hits += [m.group(0) for m in pattern.finditer(source)]
    return hits


def test_frontend_has_no_lease_or_activation_interface():
    web_src = REPO_ROOT / "apps" / "web" / "src"
    scanned = 0
    for path in list(web_src.rglob("*.ts")) + list(web_src.rglob("*.tsx")):
        if ".mypy_cache" in path.parts or "node_modules" in path.parts:
            continue
        scanned += 1
        hits = _forbidden_frontend_hits(path.read_text(encoding="utf-8"))
        assert not hits, f"frontend {path.name} exposes forbidden control indicator(s): {hits}"
    assert scanned >= 5


def test_frontend_activation_guard_distinguishes_display_from_interface():
    """Regression for the removed bare-"worker_identity" ban: the guard ALLOWS
    display-only refusal codes + explanatory copy + the sealed resolver-activation
    governance surface, but REJECTS any real lease / gate / worker-identity /
    credential / secret control interface (including on-convention synonyms of the
    exact backend/API names). Proves removing the lexical ban did not weaken the
    invariant."""
    # Allowed: display-only refusal vocabulary, explanatory prose, read-only view
    # models, the governance surface, and non-secret inputs — all must be hit-free.
    allowed = "\n".join(
        (
            'worker_identity_missing: "No worker identity is available to run discovery.",',
            'worker_identity_unapproved: "The worker identity has not been approved.",',
            'credential_unavailable: "Credential resolution failed closed.",',
            "// Only the safe worker identity registration-link UUID is displayed.",
            "worker_identity_registration_id: string | null;",
            "// worker identity refused; activation gate sealed; activation gates documented;",
            "// no lease is issued and no resolution occurs from this interface.",
            "const gates = resolverGates(newest);  // read-only posture view-model",
            "interface ResolverGate { id: string }",
            "const workerActivation: ResolverGate = buildGate();",
            "api.approveResolverActivation(auth.id);  // sealed decision, not gate activation",
            "api.createResolverActivation(preflightId, ttl);",
            "api.recordResolverActivationEvidence(id, kind, status, proofId, issuer);",
            "api.revokeResolverActivation(id); api.listResolverActivations(targetId);",
            "const p = Promise.resolve([]); resolveClosedCodeCopy(code); resolveStatusTone(s);",
            "const payload = buildRegisterTargetPayload({}); const u = buildUrl(path);",
            "api.registerTarget(body); api.listWorkerNodes(); workerPostureRows(e);",
            "api.reviewAndLinkWorkerNode(nodeId, explicitReview);",
            'fetch("/read-only-bootstrap/worker-nodes/id/identity-approval-link");',
            "import { RiveWorkerBundle } from './rive'; type N = WorkerDiscoveryNode;",
            '<CyberButton type="button" /> <input type="number" /> <input type="checkbox" />',
            "const SECRETISH_KEY_RE = /(secret|token|password|credential|private|api_key|ssh)/i;",
        )
    )
    allowed_hits = _forbidden_frontend_hits(allowed)
    assert allowed_hits == [], (
        f"allowed display/governance vocabulary produced hits: {allowed_hits}"
    )

    # Rejected: each snippet is a real forbidden control interface (or an
    # on-convention synonym of the exact backend/API spelling).
    forbidden_samples = {
        "lease acquisition (retained literal)": "onClick={() => api.acquireLease(id)}",
        "lease acquisition (synonym verb)": "await api.claimResolutionLease(id);",
        "lease acquisition (request verb)": "await api.requestResolutionLease(x);",
        "resolution-lease type (PascalCase)": 'import type { ResolutionLease } from "./types";',
        "resolution-lease identifier (snake)": "const x: resolution_lease = y;",
        "resolver-gate activation (retained literal)": "import { activationGate } from './x';",
        "resolver-gate activation (verb)": "await api.activateResolverGate(id);",
        "resolver-gate activation (synonym verb)": "unsealResolverGate();",
        "activation-gate type (PascalCase)": "import type { ResolutionActivationGate } from './x';",
        "worker-identity registration method": "await api.registerWorkerIdentity(body);",
        "worker-identity approval method": "await api.approveWorkerIdentity(id);",
        "worker-identity evidence (record verb)": "await api.recordWorkerIdentityEvidence(ev);",
        "worker registration (no Identity token)": "await api.registerWorker(body);",
        "worker admission (backend vocab)": "await api.admitWorker(id);",
        "worker-identity kebab route": 'fetch("/api/v1/worker-identity/registrations");',
        "worker verifier": "const v = new RegisteredWorkerIdentityVerifier(source);",
        "worker attestation source": "const a: WorkerIdentityAttestationSource = source;",
        "credential resolution": "const c = await resolveCredential(ref);",
        "credential resolution (qualified)": "const c = await resolveProviderCredential(ref);",
        "secret reveal": "const s = revealSecret(ref);",
        "secret material construction": "const m = buildSecretMaterial(bytes);",
        "credential payload type": "type X = { m: CredentialPayload };",
        "password input field": '<input type="password" name="secret" />',
        "password input (jsx expression)": '<input type={"password"} />',
        "password input (ternary show/hide)": '<CyberInput type={masked ? "password" : "text"} />',
        "password input (htmlType wrapper prop)": '<Field htmlType="password" />',
        "secret input component": "<SecretInput value={v} onChange={f} />",
    }
    for label, sample in forbidden_samples.items():
        assert _forbidden_frontend_hits(sample), f"guard failed to reject {label}: {sample!r}"
