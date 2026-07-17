"""Single source of truth for the stable Temporal activity NAME strings (import-clean).

Pure ``str`` literals with ZERO imports — safe for both the sandbox-imported workflow module and the
host-only activity module. The workflows dispatch BY these names (so the sandbox never imports an
activity module), and the activity registrations use these EXACT names, so the dispatched name and
the
registered name can never drift. The four legacy values
(``deploy``/``reset``/``destroy``/``discover``)
equal the activities' original implicit function names, so registration is unchanged (no rename).
"""

from __future__ import annotations

# B1B-PR4/PR5B durable readiness + plan-generation activities.
REAL_PLAN_GENERATION_ACTIVITY_NAME = "real_plan_generation_activity"
ELIGIBILITY_PREFLIGHT_ACTIVITY_NAME = "eligibility_preflight_activity"
TOOLCHAIN_ATTESTATION_ACTIVITY_NAME = "toolchain_attestation_activity"
REMOTE_STATE_READINESS_ACTIVITY_NAME = "remote_state_readiness_activity"
PLAN_SECRET_READINESS_ACTIVITY_NAME = "plan_secret_readiness_activity"

# Legacy deploy/reset/destroy/discover activities. These MUST equal the original implicit function
# names, so pinning ``@activity.defn(name=...)`` does not change any registration.
DEPLOY_ACTIVITY_NAME = "deploy_activity"
RESET_ACTIVITY_NAME = "reset_activity"
DESTROY_ACTIVITY_NAME = "destroy_activity"
DISCOVER_ACTIVITY_NAME = "discover_activity"
