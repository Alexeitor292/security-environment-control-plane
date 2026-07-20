"""Truth-table coverage for staged PR5F activation status."""

from __future__ import annotations

from dataclasses import replace

import pytest
from secp_discovery_activation.status import (
    ALL_STATES,
    AWAITING_AUTHORIZATION,
    AWAITING_BOOTSTRAP_SESSION,
    AWAITING_BUNDLE,
    AWAITING_FINALIZATION,
    AWAITING_PROOF,
    BUNDLE_READY,
    DISABLED,
    DISCOVERY_CONTACTED,
    KEYS_GENERATED,
    PREPARED,
    PUBLIC_NODE_PUBLISHED,
    RECOVERY_REQUIRED,
    TLS_READY,
    WORKER_RECREATION_REQUIRED,
    WORKER_STARTING,
    ActivationObservation,
    derive_status,
)


def _runtime_ready(**updates: object) -> ActivationObservation:
    values: dict[str, object] = {
        "coherent": True,
        "activation_enabled": True,
        "artifacts_prepared": True,
        "tls_ready": True,
        "worker_config_installed": True,
        "worker_generation_changed": True,
        "worker_running": True,
        "worker_healthy": True,
        "ordinary_queue_exact": True,
        "b8_flags_enabled": True,
        "required_paths_present": True,
        "state_mount_isolated": True,
        "bundle_loop_started": True,
        "operator_absent": True,
        "safety_seals_valid": True,
    }
    values.update(updates)
    return ActivationObservation(**values)


@pytest.mark.parametrize(
    ("observation", "expected", "finding"),
    [
        (ActivationObservation(coherent=True), DISABLED, "activation_false"),
        (
            ActivationObservation(coherent=True, activation_enabled=True),
            PREPARED,
            "activation_artifacts_not_installed",
        ),
        (
            ActivationObservation(coherent=True, activation_enabled=True, artifacts_prepared=True),
            PREPARED,
            "admission_tls_not_ready",
        ),
        (
            ActivationObservation(
                coherent=True,
                activation_enabled=True,
                artifacts_prepared=True,
                tls_ready=True,
            ),
            TLS_READY,
            "worker_activation_artifact_not_installed",
        ),
        (
            _runtime_ready(worker_generation_changed=False),
            WORKER_RECREATION_REQUIRED,
            "ordinary_worker_generation_not_activated",
        ),
        (
            _runtime_ready(worker_healthy=False),
            WORKER_STARTING,
            "worker_postconditions_incomplete",
        ),
        (
            _runtime_ready(),
            WORKER_STARTING,
            "worker_keys_not_safely_generated",
        ),
        (
            _runtime_ready(keys_generated=True, key_metadata_safe=True),
            KEYS_GENERATED,
            "public_worker_node_absent",
        ),
        (
            _runtime_ready(
                keys_generated=True,
                key_metadata_safe=True,
                public_node_id="11111111-1111-4111-8111-111111111111",
                public_node_revision=1,
                public_node_public_only=True,
            ),
            PUBLIC_NODE_PUBLISHED,
            "public_node_observed",
        ),
        (
            _runtime_ready(
                keys_generated=True,
                key_metadata_safe=True,
                public_node_id="11111111-1111-4111-8111-111111111111",
                public_node_revision=1,
                public_node_public_only=True,
                publication_recorded=True,
            ),
            AWAITING_BOOTSTRAP_SESSION,
            "bootstrap_session_absent",
        ),
        (
            _runtime_ready(
                keys_generated=True,
                key_metadata_safe=True,
                public_node_id="11111111-1111-4111-8111-111111111111",
                public_node_revision=1,
                public_node_public_only=True,
                publication_recorded=True,
                bootstrap_status="pending",
            ),
            AWAITING_PROOF,
            "bootstrap_proof_pending",
        ),
        (
            _runtime_ready(
                keys_generated=True,
                key_metadata_safe=True,
                public_node_id="11111111-1111-4111-8111-111111111111",
                public_node_revision=1,
                public_node_public_only=True,
                publication_recorded=True,
                bootstrap_status="completed",
            ),
            AWAITING_AUTHORIZATION,
            "authorization_not_bound",
        ),
        (
            _runtime_ready(
                keys_generated=True,
                key_metadata_safe=True,
                public_node_id="11111111-1111-4111-8111-111111111111",
                public_node_revision=1,
                public_node_public_only=True,
                publication_recorded=True,
                bootstrap_status="bound",
                worker_identity_approved=True,
                live_read_authorization_approved=True,
            ),
            AWAITING_BUNDLE,
            "bundle_not_available",
        ),
        (
            _runtime_ready(
                keys_generated=True,
                key_metadata_safe=True,
                public_node_id="11111111-1111-4111-8111-111111111111",
                public_node_revision=1,
                public_node_public_only=True,
                publication_recorded=True,
                bootstrap_status="bound",
                worker_identity_approved=True,
                live_read_authorization_approved=True,
                bundle_ready=True,
            ),
            BUNDLE_READY,
            "target_not_contacted",
        ),
        (
            _runtime_ready(
                keys_generated=True,
                key_metadata_safe=True,
                public_node_id="11111111-1111-4111-8111-111111111111",
                public_node_revision=1,
                public_node_public_only=True,
                publication_recorded=True,
                bootstrap_status="bound",
                worker_identity_approved=True,
                live_read_authorization_approved=True,
                bundle_ready=True,
                discovery_contacted=True,
                candidate_executable=False,
            ),
            DISCOVERY_CONTACTED,
            "read_only_contact_proven",
        ),
        (
            ActivationObservation(activation_enabled=True, recovery_required=True),
            RECOVERY_REQUIRED,
            "recovery_not_proven",
        ),
    ],
)
def test_each_truthful_status_stage(
    observation: ActivationObservation, expected: str, finding: str
) -> None:
    report = derive_status(observation)

    assert report.state == expected
    assert report.findings == (finding,)


def test_truth_table_exercises_every_documented_state() -> None:
    # The parameter table above deliberately contains duplicate PREPARED/WORKER_STARTING stages,
    # so compare its distinct expected contract with the public inventory.
    expected = {
        DISABLED,
        PREPARED,
        TLS_READY,
        WORKER_RECREATION_REQUIRED,
        WORKER_STARTING,
        KEYS_GENERATED,
        PUBLIC_NODE_PUBLISHED,
        AWAITING_FINALIZATION,
        AWAITING_BOOTSTRAP_SESSION,
        AWAITING_PROOF,
        AWAITING_AUTHORIZATION,
        AWAITING_BUNDLE,
        BUNDLE_READY,
        DISCOVERY_CONTACTED,
        RECOVERY_REQUIRED,
    }
    assert set(ALL_STATES) == expected


@pytest.mark.parametrize("terminal_status", ["superseded", "refused"])
def test_terminal_bootstrap_requires_a_new_session(terminal_status: str) -> None:
    report = derive_status(
        _runtime_ready(
            keys_generated=True,
            key_metadata_safe=True,
            public_node_id="11111111-1111-4111-8111-111111111111",
            public_node_revision=2,
            public_node_public_only=True,
            publication_recorded=True,
            bootstrap_status=terminal_status,
        )
    )

    assert report.state == AWAITING_BOOTSTRAP_SESSION
    assert report.findings == ("bootstrap_session_terminal",)


def test_flags_alone_never_report_ready_and_candidate_must_remain_non_executable() -> None:
    flags_only = _runtime_ready(worker_generation_changed=False, b8_flags_enabled=True)
    assert derive_status(flags_only).state == WORKER_RECREATION_REQUIRED

    contacted = _runtime_ready(
        keys_generated=True,
        key_metadata_safe=True,
        public_node_id="11111111-1111-4111-8111-111111111111",
        public_node_revision=9,
        public_node_public_only=True,
        publication_recorded=True,
        bootstrap_status="bound",
        worker_identity_approved=True,
        live_read_authorization_approved=True,
        bundle_ready=True,
        discovery_contacted=True,
        candidate_executable=False,
    )
    assert derive_status(contacted).state == DISCOVERY_CONTACTED
    assert derive_status(replace(contacted, candidate_executable=True)).state == RECOVERY_REQUIRED
    assert derive_status(replace(contacted, candidate_executable=None)).state == RECOVERY_REQUIRED


def test_incoherent_installed_observation_and_unknown_bootstrap_are_recovery_required() -> None:
    incoherent = ActivationObservation(
        activation_enabled=True, artifacts_prepared=True, worker_config_installed=True
    )
    assert derive_status(incoherent).canonical()["state"] == RECOVERY_REQUIRED

    unknown = _runtime_ready(
        keys_generated=True,
        key_metadata_safe=True,
        public_node_id="11111111-1111-4111-8111-111111111111",
        public_node_revision=1,
        public_node_public_only=True,
        publication_recorded=True,
        bootstrap_status="invented",
    )
    assert derive_status(unknown).state == RECOVERY_REQUIRED


def test_disabled_requires_proof_that_no_activation_effects_are_installed() -> None:
    missing = derive_status(ActivationObservation())
    assert missing.state == RECOVERY_REQUIRED
    assert missing.findings == ("observation_incoherent",)

    toggled_off = ActivationObservation(
        coherent=True,
        activation_enabled=False,
        artifacts_prepared=True,
        tls_ready=True,
        worker_config_installed=True,
    )
    report = derive_status(toggled_off)
    assert report.state == RECOVERY_REQUIRED
    assert report.findings == ("activation_false_with_effects",)
    assert derive_status(replace(toggled_off, coherent=False)).state == RECOVERY_REQUIRED
