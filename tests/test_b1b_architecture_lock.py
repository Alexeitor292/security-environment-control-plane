"""SECP-002B-1B — architecture-lock guardrails (ADR-020).

Static, cross-cutting checks that the B1-B *architecture lock* is documented truthfully and
activates nothing: the ADR/architecture/plan/runbook/checklist exist and say design-only; the
runbook is a non-runnable skeleton; the checklist checks no box; STATUS stays
partial/production-blocked and states no real plan/apply/destroy occurred; both B1-A subprocess
seals remain exactly ``True``; no tracked environment example enables real provisioning / the
OpenTofu subprocess / isolated-lab mutation; and the B1-B documents require the safe lifecycle
controls and forbid the unsafe shortcuts.

These check required explicit statements and current code constants — NOT the mere presence of words
like ``apply`` or ``destroy`` in prose. This PR changes only documentation and these tests.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

ADR = REPO_ROOT / "docs" / "adr" / "ADR-020-first-real-disposable-lab-lifecycle.md"
ARCH = REPO_ROOT / "docs" / "architecture" / "secp-002b-1b-real-lab-lifecycle.md"
PLAN = REPO_ROOT / "docs" / "implementation" / "secp-002b-1b-plan.md"
RUNBOOK = REPO_ROOT / "docs" / "runbooks" / "b1b-first-real-lab.md"
CHECKLIST = REPO_ROOT / "docs" / "proxmox" / "b1b-lab-prerequisite-checklist.md"
STATUS = REPO_ROOT / "docs" / "STATUS.md"

PROCESS_EXECUTOR = (
    REPO_ROOT / "apps" / "worker" / "secp_worker" / "provisioning" / "process_executor.py"
)
ACTIVATION = REPO_ROOT / "apps" / "worker" / "secp_worker" / "provisioning" / "activation.py"


def _norm(path: Path) -> str:
    """Lowercased text with markdown emphasis/backticks and blockquote markers removed and
    whitespace runs collapsed, so a marker matches regardless of bold/code styling, blockquote
    wrapping, case, or line wrapping (extends the STATUS truthfulness convention)."""
    raw = path.read_text(encoding="utf-8").replace("**", "").replace("`", "")
    raw = re.sub(r"(?m)^\s*>\s?", "", raw)  # drop markdown blockquote '> ' line markers
    return " ".join(raw.split()).lower()


def _corpus(*paths: Path) -> str:
    return "\n".join(_norm(p) for p in paths)


# --- the B1-B design deliverables exist and say design-only / no activation --------------------


def test_b1b_documents_exist():
    for path in (ADR, ARCH, PLAN, RUNBOOK, CHECKLIST):
        assert path.is_file(), f"missing B1-B document: {path.relative_to(REPO_ROOT)}"


def test_adr020_is_design_only_and_activates_nothing():
    body = _norm(ADR)
    assert "architecture lock" in body
    assert "design-only" in body
    assert "activates nothing" in body
    assert "does not activate or authorize anything" in _corpus(ADR, STATUS)


# --- runbook is a NON-RUNNABLE skeleton --------------------------------------------------------


def test_runbook_is_a_non_runnable_skeleton():
    body = _norm(RUNBOOK)
    assert "not an activation guide" in body
    assert "no runnable commands" in body
    assert "execution commands remain unavailable" in body
    # No shell/console fenced code blocks.
    raw = RUNBOOK.read_text(encoding="utf-8").lower()
    for fence in ("```bash", "```sh", "```shell", "```console", "```ps"):
        assert fence not in raw, f"runbook must not contain a {fence} code block"
    # No runnable provider / OpenTofu / SSH / probe command signatures (not mere prose words).
    for cmd in (
        "tofu apply",
        "tofu plan",
        "tofu destroy",
        "tofu init",
        "terraform apply",
        "pvesh ",
        "qm create",
        "pct create",
        "ssh root@",
        "curl http",
        "wget http",
        "nmap ",
    ):
        assert cmd not in body, f"runbook must not contain a runnable command: {cmd!r}"


# --- checklist checks no box in the architecture PR --------------------------------------------


def test_checklist_states_no_box_completed_by_architecture_pr():
    body = _norm(CHECKLIST)
    assert "no box in this checklist is checked by the adr-020 architecture-lock pr" in body
    # And it still forbids committing real values.
    assert "do not add any real lab value" in body


# --- STATUS truth: partial / production-blocked; no real plan/apply/destroy ---------------------


def test_status_keeps_b1b_partial_and_production_blocked():
    body = _norm(STATUS)
    assert "first real disposable-lab lifecycle | partially-implemented, production-blocked" in body
    # The load-bearing marker other STATUS tests rely on must remain.
    assert "disposable-lab lifecycle does not exist yet" in body


def test_status_states_no_real_plan_apply_or_destroy_occurred():
    body = _norm(STATUS)
    for marker in (
        "no real opentofu process has run",
        "no real plan has run",
        "no real apply or destroy has occurred",
        "no real proxmox mutation has occurred",
    ):
        assert marker in body, f"STATUS must state: {marker!r}"
    assert "the architecture lock does not activate or authorize anything" in body


def test_status_says_seals_and_read_only_status_unchanged():
    body = _norm(STATUS)
    assert "real proxmox provisioning remains unavailable" in body  # existing marker preserved
    assert "the opentofu subprocess remains hard-sealed" in body  # existing marker preserved
    assert "controlled live read-only discovery status is unchanged" in body


# --- both B1-A subprocess seals remain exactly True (code constants) ----------------------------


def test_both_b1a_subprocess_seals_remain_true():
    # Authoritative: the RUNTIME constant is exactly ``True`` in BOTH modules. This catches any
    # effective-False value regardless of formatting, aliasing (``= bool(0)`` / ``= 1 > 2``), or a
    # later reassignment — the module's final value is what governs the seal.
    from secp_worker.provisioning import activation as act
    from secp_worker.provisioning import process_executor as pe

    assert pe._B1A_SUBPROCESS_SEALED is True
    assert act._B1A_SUBPROCESS_SEALED is True

    # Belt-and-suspenders: the seal is a SINGLE, top-level, literal ``= True`` code constant (not a
    # computed expression, not reassigned) — so unsealing must be a deliberate reviewed edit.
    for src in (PROCESS_EXECUTOR, ACTIVATION):
        text = src.read_text(encoding="utf-8")
        assigns = re.findall(r"(?m)^_B1A_SUBPROCESS_SEALED\s*=.*$", text)
        assert len(assigns) == 1, (
            f"{src.relative_to(REPO_ROOT)} must have exactly one top-level seal assignment; "
            f"found {assigns}"
        )
        rhs = assigns[0].split("=", 1)[1].strip()
        assert rhs == "True", (
            f"{src.relative_to(REPO_ROOT)} seal must be the literal `True` (found {rhs!r})"
        )


# --- no tracked env example enables real provisioning / subprocess / isolated-lab mutation ------


def _env_examples() -> list[Path]:
    skip = {"node_modules", ".venv", ".git", "dist", "__pycache__"}
    found = [
        p for p in REPO_ROOT.rglob("*.env.example") if not any(part in skip for part in p.parts)
    ]
    root_env = REPO_ROOT / ".env.example"
    if root_env.is_file() and root_env not in found:
        found.append(root_env)
    return found


def test_no_env_example_enables_real_provisioning_or_subprocess_or_isolated_lab():
    examples = _env_examples()
    assert examples, "expected at least one tracked .env.example"
    for path in examples:
        compact = re.sub(r"\s*=\s*", "=", path.read_text(encoding="utf-8").lower())
        for enabling in (
            "secp_enable_real_provisioning=true",
            "secp_enable_opentofu_subprocess=true",
            "secp_provisioning_application_mode=isolated_lab",
        ):
            assert enabling not in compact, (
                f"{path.relative_to(REPO_ROOT)} must not enable {enabling!r}"
            )


def test_no_production_artifact_bundles_proxmox_credentials_or_a_real_target():
    prod = REPO_ROOT / "infra" / "production"
    if not prod.exists():
        return
    for path in prod.rglob("*"):
        if not path.is_file():
            continue
        low = path.read_text(encoding="utf-8", errors="ignore").lower()
        assert "pveapitoken" not in low, (
            f"{path.relative_to(REPO_ROOT)} bundles a Proxmox API token"
        )
        assert "@pam" not in low and "@pve" not in low, (
            f"{path.relative_to(REPO_ROOT)} bundles a Proxmox realm account"
        )
        compact = re.sub(r"\s*=\s*", "=", low)
        assert "secp_provisioning_application_mode=isolated_lab" not in compact


# --- the B1-B documents REQUIRE the safe lifecycle controls -------------------------------------


def test_documents_require_the_safe_lifecycle_controls():
    corpus = _corpus(ADR, ARCH, RUNBOOK, CHECKLIST, PLAN)
    required = (
        "read-only preflight",  # real read-only eligibility preflight
        "offline provider mirror",  # offline verified toolchain
        "no network provider download",  # runtime download prohibited
        "remote state only",  # remote state, no local
        "just-in-time",  # worker-only JIT secret resolution
        "plan-only",  # plan-only phase before apply
        "apply of the exact prepared binary plan",  # exact prepared-plan apply
        "explicit human approval of that exact change-set hash",  # exact approval
        "observed-state",  # observed-state verification
        "separate human approval of the exact destroy change-set hash",  # separate destroy approval
        "zero-residue",  # zero-residue proof
        "emergency stop",  # emergency stop
        "recovery owner",  # recovery
    )
    for marker in required:
        assert marker in corpus, f"B1-B docs must require: {marker!r}"


# --- the B1-B documents FORBID the unsafe shortcuts --------------------------------------------


def test_documents_forbid_the_unsafe_shortcuts():
    corpus = _corpus(ADR, ARCH, RUNBOOK, CHECKLIST, PLAN)
    forbidden_statements = (
        "apply is not callable directly by the api",  # no API direct execution
        "no fake-runner fallback",  # no fake fallback
        "no local fallback",  # no local state fallback
        "no network provider download",  # no runtime provider download
        "no external connectivity",  # no external connectivity
        "no stage automatically triggers the next",  # no automatic plan->apply / apply->destroy
        "no automatic reuse of the apply approval",  # destroy never reuses apply approval
        "never the raw binary plan",  # no raw plan persistence
        "no raw secret enters",  # no raw secret persistence
        "the api never resolves or receives the credential",  # no API-side secret resolution
    )
    for marker in forbidden_statements:
        assert marker in corpus, f"B1-B docs must state the prohibition: {marker!r}"
    # live values must be kept out of source control
    assert "committed to the repository" in corpus
