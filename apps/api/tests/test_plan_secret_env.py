"""B1B-PR5A — the two-``SecretMaterial`` plan-only child-environment projection contract (§10).

Proves the provider plan-read credential and the state-backend plan credential are projected by TWO
SEPARATE builders into DISJOINT allowlisted variables, from a fresh dict, with no ambient
inheritance and strict value validation — WITHOUT running any process (PR5A runs none).
"""

from __future__ import annotations

import pytest
from secp_api.plan_activation_contract import (
    PLAN_PROVIDER_ENV_ALLOWLIST,
    PLAN_STATE_ENV_ALLOWLIST,
)
from secp_worker.plan_gen.secret_env import (
    PlanEnvViolation,
    build_provider_plan_env,
    build_state_plan_env,
    combined_plan_env,
)
from secp_worker.preflight.secret_resolution import SecretMaterial

PROVIDER_SECRET = "pm-token-value-abc"
STATE_SECRET = "state-backend-pw-xyz"


def test_provider_and_state_project_into_their_exact_allowlisted_variables():
    provider = build_provider_plan_env(SecretMaterial(PROVIDER_SECRET))
    state = build_state_plan_env(SecretMaterial(STATE_SECRET))
    assert set(provider) == set(PLAN_PROVIDER_ENV_ALLOWLIST) == {"TF_VAR_pm_api_token"}
    assert set(state) == set(PLAN_STATE_ENV_ALLOWLIST) == {"TF_HTTP_PASSWORD"}
    assert provider["TF_VAR_pm_api_token"] == PROVIDER_SECRET
    assert state["TF_HTTP_PASSWORD"] == STATE_SECRET


def test_the_two_variable_sets_are_disjoint_and_never_cross():
    assert not (set(PLAN_PROVIDER_ENV_ALLOWLIST) & set(PLAN_STATE_ENV_ALLOWLIST))
    combined = combined_plan_env(SecretMaterial(PROVIDER_SECRET), SecretMaterial(STATE_SECRET))
    assert combined["TF_VAR_pm_api_token"] == PROVIDER_SECRET
    assert combined["TF_HTTP_PASSWORD"] == STATE_SECRET
    # Neither value landed in the other's variable.
    assert STATE_SECRET not in combined["TF_VAR_pm_api_token"]
    assert PROVIDER_SECRET not in combined["TF_HTTP_PASSWORD"]


def test_each_builder_returns_a_fresh_dict_without_ambient_inheritance():
    a = build_provider_plan_env(SecretMaterial(PROVIDER_SECRET))
    b = build_provider_plan_env(SecretMaterial(PROVIDER_SECRET))
    assert a is not b  # a fresh dict each time
    # No ambient PATH / HOME / proxy / cloud variable leaked in.
    for ambient in ("PATH", "HOME", "HTTP_PROXY", "AWS_ACCESS_KEY_ID", "SSH_AUTH_SOCK"):
        assert ambient not in a


def test_the_module_never_imports_os():
    """It must not read or mutate ``os.environ`` — it does not import ``os`` at all."""
    import secp_worker.plan_gen.secret_env as mod

    assert not hasattr(mod, "os")


@pytest.mark.parametrize("bad", ["value\nwith-newline", "value\x00nul", "value\rcr"])
def test_control_characters_in_the_value_are_refused(bad):
    with pytest.raises(PlanEnvViolation):
        build_provider_plan_env(SecretMaterial(bad))


def test_oversized_value_is_refused():
    with pytest.raises(PlanEnvViolation):
        build_state_plan_env(SecretMaterial("x" * 5000))


def test_an_empty_secret_can_never_even_be_material():
    # An empty secret is refused at SecretMaterial construction, before any projection.
    with pytest.raises(ValueError, match="non-empty"):
        SecretMaterial("")


def test_a_non_secretmaterial_input_is_refused():
    with pytest.raises(PlanEnvViolation):
        build_provider_plan_env("raw-string-not-material")  # type: ignore[arg-type]


def test_the_projected_value_is_not_in_any_dict_repr():
    """Defense in depth: the value lives only under its variable key, never leaked elsewhere."""
    env = build_provider_plan_env(SecretMaterial(PROVIDER_SECRET))
    # The only place the secret appears is the single allowlisted variable's value.
    appearances = [k for k, v in env.items() if PROVIDER_SECRET in v]
    assert appearances == ["TF_VAR_pm_api_token"]
