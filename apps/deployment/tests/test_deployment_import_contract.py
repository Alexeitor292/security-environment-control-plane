"""The exact public import contract expected by the fixed PR5C operator entrypoint (SECP-PR5D)."""

from __future__ import annotations


def test_exact_import_contract():
    # The literal import the rendered entrypoint performs.
    from secp_operator_deployment import compositions, runner

    assert hasattr(compositions, "build_controlled_live_compositions")
    assert hasattr(runner, "run_operator_worker")


def test_entrypoint_can_import_the_package():
    # The PR5C fixed entrypoint template's loader does exactly this import; it must resolve now that
    # the package exists (its ABSENCE was the fail-closed state).
    from secp_commissioning.operator_template import OPERATOR_ENTRYPOINT_TEMPLATE

    assert (
        "from secp_operator_deployment import compositions, runner" in OPERATOR_ENTRYPOINT_TEMPLATE
    )
    assert "compositions.build_controlled_live_compositions()" in OPERATOR_ENTRYPOINT_TEMPLATE
    assert "runner.run_operator_worker(registration)" in OPERATOR_ENTRYPOINT_TEMPLATE


def test_package_version_and_provenance_are_pinned():
    import secp_operator_deployment as pkg

    assert pkg.PACKAGE_CONTRACT_VERSION == "secp.operator-deployment/v1alpha1"
    assert pkg.PACKAGE_VERSION == "0.1.0"
    assert pkg.package_implementation_digest().startswith("sha256:")
