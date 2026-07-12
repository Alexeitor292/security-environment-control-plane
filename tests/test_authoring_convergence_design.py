"""Static guardrails for the ADR-016 authoring-convergence / publication design lock.

These are non-fragile marker checks (normalized: bold/backtick-stripped, whitespace-collapsed,
lowercased) over the ADR and architecture document — NOT paragraph-equality tests. They assert the
design lock states its non-negotiable invariants, and that this design PR carries no production
code and no real infrastructure values. The only executable artifact this PR adds is this test,
which imports nothing beyond the standard library.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
ADR = (
    REPO_ROOT / "docs" / "adr" / "ADR-016-authoring-convergence-environment-version-publication.md"
)
ARCH = REPO_ROOT / "docs" / "architecture" / "secp-b10-authoring-convergence-publication.md"


def _norm(path: Path) -> str:
    """Bold/backtick-stripped, whitespace-collapsed, lowercased view for robust marker matching."""
    raw = path.read_text(encoding="utf-8").replace("**", "").replace("`", "")
    return " ".join(raw.split()).lower()


# --- existence ---------------------------------------------------------------------------------


def test_design_documents_exist():
    assert ADR.is_file(), "ADR-016 must exist"
    assert ARCH.is_file(), "the SECP-B10 architecture document must exist"


# --- canonical-source invariants ---------------------------------------------------------------


def test_environment_version_is_the_only_canonical_deployable():
    assert "environmentversion remains the sole canonical deployable definition" in _norm(ADR)
    assert "sole canonical deployable" in _norm(ARCH)


def test_topology_revision_is_never_directly_deployable():
    assert "a topology revision is never directly deployable" in _norm(ADR)
    assert "never deployable by itself" in _norm(ARCH)


def test_requires_exact_approved_revision_and_content_hash_binding():
    marker = (
        "every published version must bind the exact approved topology revision "
        "and topology content hash"
    )
    assert marker in _norm(ADR)


def test_requires_validation_result_identity_and_result_hash_binding():
    marker = (
        "every published version must bind the exact validation-result identity "
        "and validation-result hash"
    )
    assert marker in _norm(ADR)


def test_content_hash_covers_the_topology_binding():
    adr = _norm(ADR)
    assert "cryptographically covers every canonical publication input" in adr
    assert "topology binding" in adr


def test_forbids_silent_merge_fallback_or_fabricated_values():
    assert "no silent merge, heuristic mapping, fallback, or fabricated field" in _norm(ADR)


def test_publication_is_separate_from_plan_generation_and_execution():
    adr = _norm(ADR)
    assert "publication never automatically generates, submits, or approves a deploymentplan" in adr
    assert "publication never starts a workflow or contacts infrastructure" in adr


def test_defines_idempotency_and_concurrency_behavior():
    adr = _norm(ADR)
    assert "publication is idempotent for the exact same publication inputs" in adr
    assert "concurrency" in adr
    assert "uniqueconstraint" in adr, "concurrency correctness must rest on a uniqueness constraint"
    arch = _norm(ARCH)
    assert "idempotency" in arch and "concurrency" in arch


# --- no real infrastructure values -------------------------------------------------------------

_TOKEN_SUBSTRINGS = ("akia", "ghp_", "gho_", "glpat-", "xoxb-", "xoxp-", "-----begin")


def test_documents_carry_no_real_secret_or_endpoint_values():
    for path in (ADR, ARCH):
        raw = path.read_text(encoding="utf-8")
        low = raw.lower()
        for tok in _TOKEN_SUBSTRINGS:
            assert tok not in low, f"{path.name} contains a secret-shaped value: {tok!r}"
        assert not re.search(r"\bsk-[a-z0-9]{20,}", low), f"{path.name} has an api-key-shaped value"
        assert not re.search(r"\beyj[a-z0-9_-]{10,}", low), f"{path.name} has a JWT-shaped value"
        assert not re.search(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", raw), (
            f"{path.name} contains an IPv4 literal (use placeholders only)"
        )
        assert not re.search(r"sha256:[0-9a-f]{64}\b", low), (
            f"{path.name} contains a concrete sha256 digest (use placeholders only)"
        )


# --- no production code introduced by this design PR -------------------------------------------

# Code-syntax substrings that would indicate a smuggled migration / ORM model / route / worker or
# provider import / subprocess / socket / HTTP client / OpenTofu invocation / activation flag.
# Anchored to call/import syntax so prose that merely discusses these concepts does not match.
_FORBIDDEN_CODE = (
    "op.create_table(",
    "op.add_column(",
    "op.drop_table(",
    "apirouter(",
    "@router.",
    "import subprocess",
    "subprocess.run(",
    "subprocess.popen(",
    "socket.socket(",
    "httpx.client(",
    "httpx.asyncclient(",
    "requests.get(",
    "requests.post(",
    "import secp_worker",
    "from secp_worker",
    "secp_plugin_",
    "terraform apply",
    "tofu apply",
    "opentofu apply",
    "secp_enable_",
    "enable_opentofu_subprocess",
    "enable_real_provisioning",
)


def test_design_pr_introduces_no_production_code():
    for path in (ADR, ARCH):
        assert path.suffix == ".md", "the design deliverables are markdown documents"
        low = path.read_text(encoding="utf-8").lower()
        assert "```python" not in low, f"{path.name} embeds a python code block"
        assert "```py\n" not in low, f"{path.name} embeds a python code block"
        for token in _FORBIDDEN_CODE:
            assert token not in low, f"{path.name} contains production-code token {token!r}"
        assert not re.search(r"class\s+\w+\s*\(\s*base\b", low), (
            f"{path.name} defines an ORM model class"
        )


def test_arch_document_declares_its_non_goals():
    arch = _norm(ARCH)
    assert "explicit non-goals" in arch or "non-goals" in arch
    # the non-goals must enumerate the excluded production surfaces
    for word in ("migration", "route", "subprocess", "activation flag"):
        assert word in arch, f"architecture non-goals must mention {word!r}"


# --- closed decisions (revision pass) ----------------------------------------------------------


def test_locks_v1alpha2_schema_version():
    adr = _norm(ADR)
    assert "controlplane.security/v1alpha2" in adr, (
        "the published-envelope schema version must be locked"
    )
    assert "controlplane.security/v1alpha1" in adr, (
        "v1alpha1 must be preserved for existing versions"
    )
    assert "no automatic migration" in adr


def test_hashes_the_full_environment_definition_not_nested_spec_only():
    adr = _norm(ADR)
    assert "content_hash(final_composed_environment_definition)" in adr
    assert "not only the nested spec" in adr


def test_reconstructs_canonical_topology_before_embedding():
    adr = _norm(ADR)
    assert "reconstructs the canonical topology" in adr
    assert "raw caller topology" in adr
    assert "database json array order" in adr


def test_locks_exact_role_and_network_one_to_one_rules():
    adr = _norm(ADR)
    assert "exactly one non-network topology node" in adr
    assert "node id exactly equals the role name" in adr
    assert "node kind exactly equals the role kind" in adr
    assert "node network exactly equals the role network" in adr


def test_forbids_case_folding_fuzzy_matching_and_auto_migration():
    adr = _norm(ADR)
    assert "no case folding, slug fallback, label matching, fuzzy matching" in adr
    assert "no automatic migration" in adr


def test_provenance_binds_exact_revision_and_validation_ids():
    adr = _norm(ADR)
    for field in (
        "topology_revision_id",
        "topology_validation_result_id",
        "topology_content_hash",
        "topology_validation_result_hash",
    ):
        assert field in adr, f"hash-covered provenance must include {field!r}"


def test_server_derived_fingerprint_from_final_environment_content_hash():
    adr = _norm(ADR)
    assert "publication_fingerprint" in adr
    assert "final_environment_content_hash" in adr
    assert "no caller-supplied idempotency key" in adr


def test_concurrency_uses_template_row_lock_and_both_unique_constraints():
    adr = _norm(ADR)
    assert "select for update" in adr
    assert "(template_id, version_number)" in adr
    assert "(template_id, publication_fingerprint)" in adr


def test_locks_source_base_and_template_reuse_rules():
    adr = _norm(ADR)
    assert "base_environment_version_id is required" in adr
    assert "destination template must equal the source version" in adr
    assert "no inferred ancestor" in adr


def test_stable_provenance_separated_from_publication_event_metadata():
    adr = _norm(ADR)
    assert "publication event metadata" in adr
    assert "retry cannot alter canonical content" in adr


def test_declares_zero_unresolved_architectural_ambiguities():
    assert "zero unresolved architectural ambiguities" in _norm(ADR)


# --- no hedging / no "verbatim" language -------------------------------------------------------

_FORBIDDEN_ADR_PHRASES = (
    "deferred to pr a",
    "either v1alpha1 or v1alpha2",
    "to be decided",
    "exact rule tbd",
    "embed verbatim",
    "verbatim",
)


def test_adr_contains_no_hedging_or_verbatim_language():
    adr = _norm(ADR)
    for phrase in _FORBIDDEN_ADR_PHRASES:
        assert phrase not in adr, f"ADR must not contain unresolved/verbatim phrase {phrase!r}"
