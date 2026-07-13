"""Static truthfulness guards for current-facing project status (Project Status Normalization).

These protect the current-facing product truth in README.md, docs/STATUS.md, and the FastAPI
metadata WITHOUT coupling to cosmetic prose: each check is a required marker or a forbidden stale
claim, compared against a normalized (markdown-bold/backtick-stripped, case-insensitive) view of
the file. They must be updated deliberately if the documented truth genuinely changes.
"""

from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
README = REPO_ROOT / "README.md"
STATUS = REPO_ROOT / "docs" / "STATUS.md"
API_MAIN = REPO_ROOT / "apps" / "api" / "secp_api" / "main.py"


def _norm(path: Path) -> str:
    """Lowercased text with markdown emphasis/backticks removed and whitespace runs collapsed to
    single spaces, so a marker matches regardless of bold/code styling, case, or line wrapping."""
    raw = path.read_text(encoding="utf-8").replace("**", "").replace("`", "")
    return " ".join(raw.split()).lower()


def _has(path: Path, marker: str) -> bool:
    return marker.lower() in _norm(path)


# --- README: stale whole-repo SECP-001 / simulated-only claims are gone -------------------------


def test_readme_links_the_status_ledger():
    assert _has(README, "docs/STATUS.md"), "README must link docs/STATUS.md (the capability ledger)"


def test_readme_no_longer_claims_whole_repo_is_secp001_simulated_only():
    forbidden = (
        "status: secp-001",  # the old whole-repo status banner
        "secp-001 — control plane foundation",
        "simulated execution only",
    )
    body = _norm(README)
    for claim in forbidden:
        assert claim.lower() not in body, f"README still carries the stale status claim: {claim!r}"


def test_readme_does_not_claim_all_execution_or_integration_is_simulated():
    body = _norm(README)
    for claim in ("all execution is simulated", "does not touch real infrastructure"):
        assert claim not in body, f"README still claims {claim!r}; that is no longer true"


# --- STATUS.md: the load-bearing current-truth markers are present ------------------------------


def test_status_states_the_controlled_live_read_only_distinction():
    assert _has(STATUS, "controlled live read-only"), (
        "STATUS.md must describe the controlled-live-read-only discovery distinction"
    )
    assert _has(STATUS, "controlled live read-only discovery is not provisioning"), (
        "STATUS.md must state controlled live read-only discovery is not provisioning"
    )


def test_status_states_real_provisioning_is_unavailable_and_sealed():
    assert _has(STATUS, "real proxmox provisioning remains unavailable")
    assert _has(STATUS, "the opentofu subprocess remains hard-sealed")


def test_status_states_oidc_bearer_and_browser_login_are_implemented():
    # OIDC-A landed backend bearer verification; OIDC-B landed the browser Authorization Code + PKCE
    # login. STATUS must state both truthfully (OIDC-C production deployment remains future work).
    assert _has(STATUS, "oidc bearer-token verification is implemented")
    assert _has(STATUS, "interactive browser login (authorization code + pkce) is implemented")


def test_status_states_topology_approval_does_not_publish_or_deploy():
    assert _has(
        STATUS, "approving a topology revision does not publish a canonical environmentversion"
    )
    assert _has(STATUS, "does not generate a deployment plan")


def test_status_does_not_claim_the_http_evidence_collector_is_activated():
    # The dormant collector must be described as dormant, and never as activated/active/live.
    assert _has(STATUS, "target-evidence collector remains dormant")
    body = _norm(STATUS)
    for false_claim in (
        "collector is activated",
        "collector is now active",
        "collector is live",
        "http target-evidence collector is active",
    ):
        assert false_claim not in body, f"STATUS.md must not claim {false_claim!r}"


def test_status_does_not_claim_approval_alone_authorizes_execution():
    # The correct, negated statement must be present (its presence is the guard: we never assert the
    # opposite). It also appears in the README safety section.
    assert _has(STATUS, "no ui or api approval alone activates infrastructure execution")
    assert _has(README, "no ui or api approval alone activates infrastructure execution")


# --- FastAPI metadata: no longer "simulated execution only" ------------------------------------


def test_fastapi_metadata_is_not_simulated_execution_only():
    body = _norm(API_MAIN)
    assert "simulated execution only" not in body, (
        "the FastAPI description must not say 'simulated execution only'"
    )
    assert "security environment control platform control plane" in body, (
        "the FastAPI description should carry a truthful current-scope summary"
    )


# --- Worker admission: CA-validated HTTPS + Ed25519 signed-nonce PoP, never client-cert mTLS ----


def test_main_does_not_describe_worker_admission_as_mtls():
    body = _norm(API_MAIN)
    for false_claim in (
        "reached only over internal mtls",
        "over internal mtls",
        "internal mtls",
        "via mtls",
        "reached over mtls",
    ):
        assert false_claim not in body, (
            f"main.py must not describe worker admission as reached over mTLS: {false_claim!r}"
        )


def test_worker_admission_states_ed25519_signed_nonce_and_not_client_cert_mtls():
    body = _norm(API_MAIN)
    assert "ed25519 signed-nonce" in body, (
        "main.py must state worker admission uses an Ed25519 signed-nonce proof-of-possession"
    )
    assert "not x.509 client-certificate mtls" in body, (
        "main.py must state worker admission is NOT X.509 client-certificate mTLS"
    )


# --- SECP-002B-1B: read-only discovery exists; the full disposable-lab lifecycle does not --------


def test_secp_002b_1b_is_not_described_as_a_complete_lifecycle():
    body = _norm(STATUS)
    assert "disposable-lab lifecycle does not exist yet" in body, (
        "STATUS.md must state the complete real disposable-lab lifecycle does not exist yet"
    )
    for false_claim in (
        "disposable-lab lifecycle is complete",
        "complete disposable-lab lifecycle exists",
        "full disposable-lab lifecycle is implemented",
    ):
        assert false_claim not in body, f"STATUS.md must not claim {false_claim!r}"


def test_controlled_read_only_discovery_not_conflated_with_full_lifecycle():
    body = _norm(STATUS)
    marker = (
        "controlled live read-only discovery is not provisioning, and is not the complete "
        "disposable-lab lifecycle"
    )
    assert marker in body, (
        "STATUS.md must distinguish controlled live read-only discovery from the full "
        "disposable-lab lifecycle"
    )
