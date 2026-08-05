/**
 * GENERATED FILE — DO NOT EDIT.
 *
 * Source of truth: contracts/openapi/openapi.json, exported from the live FastAPI application.
 * Regenerate with:  python scripts/export_openapi.py && (cd apps/web && npm run generate:api)
 *
 * Editing this file by hand re-creates exactly the defect it exists to remove: a second,
 * divergent copy of the API contract. CI regenerates it and fails on any difference.
 *
 * These are TRANSPORT types — the shapes that cross the wire. Presentation semantics (how an
 * operator should read a value) live in hand-written view models beside them, and the members
 * this document deliberately leaves opaque are narrowed in src/api/recorded.ts.
 *
 * This is the BROWSER surface, not the whole API. The internal worker/installer routes and the
 * worker-identity registration interface are excluded by design and their schemas are pruned —
 * see BROWSER_EXCLUDED_PREFIXES in scripts/generate-api-types.mjs for the boundary and the tests
 * that enforce it. Read contracts/openapi/openapi.json for the complete contract.
 */

/* eslint-disable */
export interface paths {
    "/api/v1/activation-dossiers/{dossier_id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Get Activation Dossier */
        get: operations["get_activation_dossier_api_v1_activation_dossiers__dossier_id__get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/activation-dossiers/{dossier_id}/approve": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /**
         * Approve Activation Dossier
         * @description Approve under the DEDICATED ``activation_dossier:approve`` permission. Approving runs
         *     nothing.
         */
        post: operations["approve_activation_dossier_api_v1_activation_dossiers__dossier_id__approve_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/activation-dossiers/{dossier_id}/evidence": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Record Dossier Evidence */
        post: operations["record_dossier_evidence_api_v1_activation_dossiers__dossier_id__evidence_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/activation-dossiers/{dossier_id}/revoke": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Revoke Activation Dossier */
        post: operations["revoke_activation_dossier_api_v1_activation_dossiers__dossier_id__revoke_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/audit": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** List Audit */
        get: operations["list_audit_api_v1_audit_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/auth/config": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /**
         * Auth Config
         * @description Public authentication configuration for the browser client.
         *
         *     ``mode`` is server-derived: ``dev_fallback`` ONLY when the safe dev fallback is actually enabled
         *     (non-production + ``auth_dev_mode``), otherwise ``oidc``. Production therefore always reports
         *     ``oidc`` and can never silently become dev-fallback.
         */
        get: operations["auth_config_api_v1_auth_config_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/change-sets/{approval_id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Get Change Set */
        get: operations["get_change_set_api_v1_change_sets__approval_id__get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/change-sets/{approval_id}/approve": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /**
         * Approve Change Set
         * @description Explicit human approval of an exact dry-run change set (no AI, no bypass).
         */
        post: operations["approve_change_set_api_v1_change_sets__approval_id__approve_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/change-sets/{approval_id}/reject": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Reject Change Set */
        post: operations["reject_change_set_api_v1_change_sets__approval_id__reject_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/competitions/{competition_id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Get Competition */
        get: operations["get_competition_api_v1_competitions__competition_id__get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/competitions/{competition_id}/challenges": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** List Challenges */
        get: operations["list_challenges_api_v1_competitions__competition_id__challenges_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/competitions/{competition_id}/reset-scores": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Reset Scores */
        post: operations["reset_scores_api_v1_competitions__competition_id__reset_scores_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/competitions/{competition_id}/scoreboard": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Get Scoreboard */
        get: operations["get_scoreboard_api_v1_competitions__competition_id__scoreboard_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/competitions/{competition_id}/start": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Start Competition */
        post: operations["start_competition_api_v1_competitions__competition_id__start_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/competitions/{competition_id}/stop": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Stop Competition */
        post: operations["stop_competition_api_v1_competitions__competition_id__stop_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/competitions/{competition_id}/submissions": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** List Submissions */
        get: operations["list_submissions_api_v1_competitions__competition_id__submissions_get"];
        put?: never;
        /** Submit Flag */
        post: operations["submit_flag_api_v1_competitions__competition_id__submissions_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/competitions/{competition_id}/teams": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** List Teams */
        get: operations["list_teams_api_v1_competitions__competition_id__teams_get"];
        put?: never;
        /** Create Team */
        post: operations["create_team_api_v1_competitions__competition_id__teams_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/competitions/{competition_id}/teams/{team_id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        post?: never;
        /** Delete Team */
        delete: operations["delete_team_api_v1_competitions__competition_id__teams__team_id__delete"];
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/competitions/{competition_id}/teams/{team_id}/members": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** List Team Members */
        get: operations["list_team_members_api_v1_competitions__competition_id__teams__team_id__members_get"];
        put?: never;
        /** Add Team Member */
        post: operations["add_team_member_api_v1_competitions__competition_id__teams__team_id__members_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/competitions/{competition_id}/teams/{team_id}/members/{member_id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        post?: never;
        /** Remove Team Member */
        delete: operations["remove_team_member_api_v1_competitions__competition_id__teams__team_id__members__member_id__delete"];
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/definitions/validate": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /**
         * Validate Definition Endpoint
         * @description Validate a raw definition without persisting it (editor live-validation).
         */
        post: operations["validate_definition_endpoint_api_v1_definitions_validate_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/enrollment": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /**
         * List Enrollments
         * @description The org-scoped enrollment inventory: one bounded, keyset-paged page of status projections.
         *
         *     Declared BEFORE ``/{enrollment_id}`` so the collection path is matched as a collection.
         *     ``state`` is repeatable and closed (anything else is a 422 from the enum, never a free-form
         *     string reaching the query); ``limit`` is bounded here AND re-clamped server-side; ``after`` is
         *     the opaque cursor from a previous page's ``next_cursor``.
         *
         *     Returns ONLY :class:`EnrollmentStatusOut` items — no invitation material is reachable from a
         *     list, a status read, or a cursor (see the one-shot decision in ``schemas_enrollment``).
         */
        get: operations["list_enrollments_api_v1_enrollment_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/enrollment/{enrollment_id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Get Enrollment Status */
        get: operations["get_enrollment_status_api_v1_enrollment__enrollment_id__get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/enrollment/{enrollment_id}/exchange/bind": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Bind Worker Exchange */
        post: operations["bind_worker_exchange_api_v1_enrollment__enrollment_id__exchange_bind_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/enrollment/{enrollment_id}/exchange/result": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Record Worker Result Exchange */
        post: operations["record_worker_result_exchange_api_v1_enrollment__enrollment_id__exchange_result_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/enrollment/{enrollment_id}/recover": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /**
         * Mark Enrollment Recovery Required
         * @description Operator-triggered recovery — the complement of the scheduled expiry sweep.
         *
         *     The sweep (``secp_worker`` drives it on the ordinary Temporal queue) reaches enrollments that
         *     ran out of time; this reaches one an operator has decided is stuck, without waiting for the TTL.
         *     Requires ``enrollment:manage``, enforced in the SERVICE layer so a router bypass cannot evade
         *     it. Idempotent on an already-terminal enrollment; a stale ``expected_revision`` on a live one
         *     refuses a bounded conflict.
         */
        post: operations["mark_enrollment_recovery_required_api_v1_enrollment__enrollment_id__recover_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/enrollment/{enrollment_id}/revoke": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Revoke Enrollment */
        post: operations["revoke_enrollment_api_v1_enrollment__enrollment_id__revoke_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/enrollment/invitations": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Create Enrollment Invitation */
        post: operations["create_enrollment_invitation_api_v1_enrollment_invitations_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/environment-versions/{version_id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /**
         * Get Environment Version
         * @description Exact, organization-scoped, read-only EnvironmentVersion read (ADR-016 PR E).
         *
         *     Resolves the one version by id through ``catalog.get_version`` (Principal org boundary). Legacy
         *     v1alpha1 returns ``publication_provenance=null``; published v1alpha2 returns the typed immutable
         *     provenance. No mutation or audit event, no topology-authoring lookup, no caller template id, no
         *     list-all/latest fallback.
         */
        get: operations["get_environment_version_api_v1_environment_versions__version_id__get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/environment-versions/publish": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /**
         * Publish an approved topology revision into a new immutable EnvironmentVersion
         * @description Publish -> new immutable v1alpha2 EnvironmentVersion. 201 on creation (with one atomic
         *     ``version.published`` audit), 200 on an exact idempotent replay (same version id, no new row,
         *     no version-number increment, no duplicate mutation audit). Service refusals are durably
         *     audited and mapped to closed per-code HTTP statuses.
         */
        post: operations["publish_environment_version_api_v1_environment_versions_publish_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/exercises": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** List Exercises */
        get: operations["list_exercises_api_v1_exercises_get"];
        put?: never;
        /** Create Exercise */
        post: operations["create_exercise_api_v1_exercises_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/exercises/{exercise_id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Get Exercise */
        get: operations["get_exercise_api_v1_exercises__exercise_id__get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/exercises/{exercise_id}/deploy": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /**
         * Deploy Exercise
         * @description Approve-gated deploy. Refused unless an approved plan exists (ADR-004).
         */
        post: operations["deploy_exercise_api_v1_exercises__exercise_id__deploy_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/exercises/{exercise_id}/destroy": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Destroy Exercise */
        post: operations["destroy_exercise_api_v1_exercises__exercise_id__destroy_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/exercises/{exercise_id}/instances": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** List Instances */
        get: operations["list_instances_api_v1_exercises__exercise_id__instances_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/exercises/{exercise_id}/instances/{instance_id}/reset": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Reset Instance */
        post: operations["reset_instance_api_v1_exercises__exercise_id__instances__instance_id__reset_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/exercises/{exercise_id}/plan": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Latest Plan */
        get: operations["latest_plan_api_v1_exercises__exercise_id__plan_get"];
        put?: never;
        /** Generate Plan */
        post: operations["generate_plan_api_v1_exercises__exercise_id__plan_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/exercises/{exercise_id}/topology": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /**
         * Exercise Topology
         * @description Per-team topologies (one isolated React-Flow graph per team).
         */
        get: operations["exercise_topology_api_v1_exercises__exercise_id__topology_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/exercises/{exercise_id}/validate": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Validate Exercise */
        post: operations["validate_exercise_api_v1_exercises__exercise_id__validate_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/instances/{instance_id}/topology": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Instance Topology */
        get: operations["instance_topology_api_v1_instances__instance_id__topology_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/manifests/{manifest_id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Get Manifest */
        get: operations["get_manifest_api_v1_manifests__manifest_id__get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/manifests/{manifest_id}/change-sets": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** List Change Sets */
        get: operations["list_change_sets_api_v1_manifests__manifest_id__change_sets_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/manifests/{manifest_id}/operations": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** List Operations */
        get: operations["list_operations_api_v1_manifests__manifest_id__operations_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/me": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Me */
        get: operations["me_api_v1_me_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/onboarding/{onboarding_id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Get Onboarding */
        get: operations["get_onboarding_api_v1_onboarding__onboarding_id__get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/onboarding/{onboarding_id}/activate": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /**
         * Activate Onboarding
         * @description Activate an approved onboarding (refused on config/scope drift since approval).
         */
        post: operations["activate_onboarding_api_v1_onboarding__onboarding_id__activate_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/onboarding/{onboarding_id}/approve": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /**
         * Approve Onboarding
         * @description Explicit human approval — required before a target can become active.
         */
        post: operations["approve_onboarding_api_v1_onboarding__onboarding_id__approve_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/onboarding/{onboarding_id}/evidence": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** List Target Evidence */
        get: operations["list_target_evidence_api_v1_onboarding__onboarding_id__evidence_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/onboarding/{onboarding_id}/preflight": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** List Preflights */
        get: operations["list_preflights_api_v1_onboarding__onboarding_id__preflight_get"];
        put?: never;
        /**
         * Request Preflight
         * @description Request a SIMULATED preflight (derived from the declared boundary).
         *
         *     Takes no caller-supplied checks or collector labels: the result is always
         *     ``simulated`` / ``fake_declared_boundary`` and can never make a target eligible for
         *     live real provisioning. Live_verified evidence is produced only by the trusted
         *     worker-only provider collector (future B1-B).
         */
        post: operations["request_preflight_api_v1_onboarding__onboarding_id__preflight_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/onboarding/{onboarding_id}/reject": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Reject Onboarding */
        post: operations["reject_onboarding_api_v1_onboarding__onboarding_id__reject_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/onboarding/{onboarding_id}/retire": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Retire Onboarding */
        post: operations["retire_onboarding_api_v1_onboarding__onboarding_id__retire_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/onboarding/{onboarding_id}/submit": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Submit For Review */
        post: operations["submit_for_review_api_v1_onboarding__onboarding_id__submit_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/plan-generation-authorizations/{authorization_id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Get Plan Generation Authorization */
        get: operations["get_plan_generation_authorization_api_v1_plan_generation_authorizations__authorization_id__get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/plan-generation-authorizations/{authorization_id}/approve": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /**
         * Approve Plan Generation Authorization
         * @description Approve under the DEDICATED ``plan_generation:approve`` permission. Approving executes
         *     nothing.
         */
        post: operations["approve_plan_generation_authorization_api_v1_plan_generation_authorizations__authorization_id__approve_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/plan-generation-authorizations/{authorization_id}/revoke": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Revoke Plan Generation Authorization */
        post: operations["revoke_plan_generation_authorization_api_v1_plan_generation_authorizations__authorization_id__revoke_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/plan-secret-authorizations/{authorization_id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Get Plan Secret Authorization */
        get: operations["get_plan_secret_authorization_api_v1_plan_secret_authorizations__authorization_id__get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/plan-secret-authorizations/{authorization_id}/approve": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /**
         * Approve Plan Secret Authorization
         * @description Approve under the DEDICATED ``readiness:approve`` permission. Approving runs NO readiness.
         */
        post: operations["approve_plan_secret_authorization_api_v1_plan_secret_authorizations__authorization_id__approve_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/plan-secret-authorizations/{authorization_id}/evidence": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Record Plan Secret Evidence */
        post: operations["record_plan_secret_evidence_api_v1_plan_secret_authorizations__authorization_id__evidence_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/plan-secret-authorizations/{authorization_id}/revoke": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /**
         * Revoke Plan Secret Authorization
         * @description Revoke immediately. All FUTURE use is invalidated; historical evidence is never mutated.
         */
        post: operations["revoke_plan_secret_authorization_api_v1_plan_secret_authorizations__authorization_id__revoke_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/plans/{plan_id}/approve": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Approve Plan */
        post: operations["approve_plan_api_v1_plans__plan_id__approve_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/plans/{plan_id}/manifest": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /**
         * Generate Manifest
         * @description Generate an immutable, secret-free provisioning manifest from an approved plan.
         */
        post: operations["generate_manifest_api_v1_plans__plan_id__manifest_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/plans/{plan_id}/reject": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Reject Plan */
        post: operations["reject_plan_api_v1_plans__plan_id__reject_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/plans/{plan_id}/submit": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Submit Plan */
        post: operations["submit_plan_api_v1_plans__plan_id__submit_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/plugins": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Plugins */
        get: operations["plugins_api_v1_plugins_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/providers/capabilities": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /**
         * Provider Capabilities
         * @description What this build can actually do, derived from the live modules that implement it.
         *
         *     This endpoint used to return a hardcoded ``provisioning_enabled: False`` with the note
         *     "Proxmox provisioning is deferred to SECP-002B", and a docstring saying its purpose was to tell
         *     the UI provisioning was not enabled. It had been false for six merges: #105-#110 shipped
         *     desired-state compilation, plan generation, apply authorization, observed verification, destroy
         *     authorization and the residue proof.
         *
         *     A capability endpoint that reads a constant is a restatement — it cannot notice the capability
         *     changing, which is the one thing it exists to do. Every value here is now derived, and
         *     ``supported_unauthorized`` is distinguished from ``not_supported`` because the old single flag
         *     conflated them (along with "not for this target"), and they call for different actions.
         */
        get: operations["provider_capabilities_api_v1_providers_capabilities_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/provisioning-manifests/{manifest_id}/activation-dossiers": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /**
         * Create Activation Dossier
         * @description Create a DRAFT activation dossier. Creating it executes nothing and contacts nothing.
         */
        post: operations["create_activation_dossier_api_v1_provisioning_manifests__manifest_id__activation_dossiers_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/provisioning-manifests/{manifest_id}/plan-generation": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /**
         * Request Plan Generation
         * @description Explicitly request the worker-owned real-plan-generation operation (enqueue-only).
         *
         *     It durably enqueues a workflow run + outbox row; the inline dispatcher refuses with no fallback.
         *     The worker loads the authoritative records, evaluates combined plan-readiness, and REFUSES at
         *     the
         *     still-sealed plan-only process boundary. It is NEVER auto-triggered by readiness or approval.
         */
        post: operations["request_plan_generation_api_v1_provisioning_manifests__manifest_id__plan_generation_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/provisioning-manifests/{manifest_id}/plan-generation-authorizations": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /**
         * Create Plan Generation Authorization
         * @description Create a DRAFT plan-generation authorization. Creating it does NOT enqueue execution.
         */
        post: operations["create_plan_generation_authorization_api_v1_provisioning_manifests__manifest_id__plan_generation_authorizations_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/provisioning-manifests/{manifest_id}/plan-generation-readiness": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /**
         * Get Plan Generation Readiness
         * @description The derived combined plan-readiness view. It is NOT plan approval and launches nothing.
         */
        get: operations["get_plan_generation_readiness_api_v1_provisioning_manifests__manifest_id__plan_generation_readiness_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/provisioning-manifests/{manifest_id}/plan-secret-authorizations": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /**
         * Create Plan Secret Authorization
         * @description Create a DRAFT plan-secret authorization. Creating it does NOT run readiness.
         */
        post: operations["create_plan_secret_authorization_api_v1_provisioning_manifests__manifest_id__plan_secret_authorizations_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/provisioning-manifests/{manifest_id}/plan-secret-readiness": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Get Plan Secret Readiness */
        get: operations["get_plan_secret_readiness_api_v1_provisioning_manifests__manifest_id__plan_secret_readiness_get"];
        put?: never;
        /**
         * Request Plan Secret Readiness
         * @description Explicitly request the worker-owned plan-secret readiness operation (enqueue-only).
         *
         *     A SEPARATE operator action: it is never triggered by eligibility, toolchain attestation, or a
         *     successful state readiness, and it never advances to a plan.
         */
        post: operations["request_plan_secret_readiness_api_v1_provisioning_manifests__manifest_id__plan_secret_readiness_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/provisioning-manifests/{manifest_id}/provisioning-readiness": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /**
         * Get Provisioning Readiness
         * @description The derived combined current-readiness view. It is NOT plan approval and launches nothing.
         */
        get: operations["get_provisioning_readiness_api_v1_provisioning_manifests__manifest_id__provisioning_readiness_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/provisioning-manifests/{manifest_id}/remote-state-readiness": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Get Remote State Readiness */
        get: operations["get_remote_state_readiness_api_v1_provisioning_manifests__manifest_id__remote_state_readiness_get"];
        put?: never;
        /**
         * Request Remote State Readiness
         * @description Explicitly request the worker-owned remote-state readiness operation (enqueue-only).
         */
        post: operations["request_remote_state_readiness_api_v1_provisioning_manifests__manifest_id__remote_state_readiness_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/provisioning-manifests/{manifest_id}/toolchain-attestation": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Get Toolchain Attestation */
        get: operations["get_toolchain_attestation_api_v1_provisioning_manifests__manifest_id__toolchain_attestation_get"];
        put?: never;
        /**
         * Request Toolchain Attestation
         * @description Explicitly request the worker-owned PR2 toolchain attestation (enqueue-only).
         *
         *     A hard PREREQUISITE of BOTH readiness operations: a matching toolchain-profile hash is not an
         *     attestation. The API reads no worker-local filesystem and executes no binary.
         */
        post: operations["request_toolchain_attestation_api_v1_provisioning_manifests__manifest_id__toolchain_attestation_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/provisioning-operations/{operation_id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Get Operation */
        get: operations["get_operation_api_v1_provisioning_operations__operation_id__get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/range-operations/{operation_id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Get Range Operation */
        get: operations["get_range_operation_api_v1_range_operations__operation_id__get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/range-operations/{operation_id}/abandon": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /**
         * Abandon Range Operation
         * @description Release a stranded operation and put its range into ``recovery_required``.
         *
         *     This endpoint exists because there was previously NO way out. An operation dispatched to a
         *     worker that could not resolve it stayed ``pending`` forever, its range stayed ``resetting``
         *     forever, and ``destroy`` and ``reset`` both answered 409 because neither may start from an
         *     in-flight state. The only recovery was hand-written SQL against
         *     ``range_deployment_operation`` — on a running system, with the range's containers still up.
         *
         *     Refuses (409) while the operation is still within its lease, unless the caller passes
         *     ``force``: abandoning an operation that IS executing puts a second writer on the range. The
         *     operation becomes ``unproven``, never ``failed``; nothing here observed it fail. Every resource
         *     the range has created stays enumerated and none is marked absent, so the destroy that follows
         *     still sweeps the complete set and still has to PROVE each one gone.
         */
        post: operations["abandon_range_operation_api_v1_range_operations__operation_id__abandon_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/range-scenarios": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /**
         * List Range Scenarios
         * @description Every shipped scenario ONCE, with every provider it can run on.
         *
         *     This is the provider-compatibility view of the same catalog ``/range-templates`` lists. The
         *     templates endpoint is unchanged and still lists concrete deployable definitions — three of them,
         *     two of which are the Web Breach Lab on two substrates. Here that lab appears a single time with
         *     two provider variants, because an operator choosing a scenario is choosing a lab and then a
         *     substrate, not choosing between two labs.
         *
         *     A scenario that cannot run on a provider is RETURNED, marked ``blocked``, with its blockers
         *     named. It is never omitted and never marked eligible. The substrate-dependent Proxmox
         *     requirements are ``undetermined`` here — this endpoint names no range, so no cluster observation
         *     is in scope and nothing has been checked. ``GET /ranges/{id}/scenario`` answers them against the
         *     observation actually recorded for that range.
         */
        get: operations["list_range_scenarios_api_v1_range_scenarios_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/range-scenarios/{key}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Get Range Scenario */
        get: operations["get_range_scenario_api_v1_range_scenarios__key__get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/range-templates": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** List Range Templates */
        get: operations["list_range_templates_api_v1_range_templates_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/range-templates/{slug}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Get Range Template */
        get: operations["get_range_template_api_v1_range_templates__slug__get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/ranges": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** List Ranges */
        get: operations["list_ranges_api_v1_ranges_get"];
        put?: never;
        /** Create Range */
        post: operations["create_range_api_v1_ranges_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/ranges/{range_id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Get Range */
        get: operations["get_range_api_v1_ranges__range_id__get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/ranges/{range_id}/challenges": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** List Range Challenges */
        get: operations["list_range_challenges_api_v1_ranges__range_id__challenges_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/ranges/{range_id}/competition": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Get Competition For Range */
        get: operations["get_competition_for_range_api_v1_ranges__range_id__competition_get"];
        put?: never;
        /** Create Competition */
        post: operations["create_competition_api_v1_ranges__range_id__competition_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/ranges/{range_id}/deploy": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Deploy Range */
        post: operations["deploy_range_api_v1_ranges__range_id__deploy_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/ranges/{range_id}/destroy": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Destroy Range */
        post: operations["destroy_range_api_v1_ranges__range_id__destroy_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/ranges/{range_id}/events": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** List Range Events */
        get: operations["list_range_events_api_v1_ranges__range_id__events_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/ranges/{range_id}/operations": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** List Range Operations */
        get: operations["list_range_operations_api_v1_ranges__range_id__operations_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/ranges/{range_id}/proxmox": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /**
         * Get Proxmox Lifecycle
         * @description Every stage of the Proxmox lifecycle in one answer, for a client rendering one page.
         */
        get: operations["get_proxmox_lifecycle_api_v1_ranges__range_id__proxmox_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/ranges/{range_id}/proxmox/allocations": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /**
         * Get Proxmox Allocations
         * @description Every identifier the plan reserves — VM/LXC ids, MACs, addresses, subnets, VLANs, state keys.
         *
         *     Deterministic: the same observation and the same template always produce the same values, which
         *     is what lets a reset resolve the deploy's identifiers instead of renumbering the range.
         */
        get: operations["get_proxmox_allocations_api_v1_ranges__range_id__proxmox_allocations_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/ranges/{range_id}/proxmox/apply-authorization": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /**
         * Get Proxmox Apply Authorization
         * @description Whether apply is authorized for the plan the range currently has.
         */
        get: operations["get_proxmox_apply_authorization_api_v1_ranges__range_id__proxmox_apply_authorization_get"];
        put?: never;
        /**
         * Authorize Proxmox Apply
         * @description Authorize apply of an already-approved plan. ENQUEUES NOTHING, APPLIES NOTHING.
         *
         *     Requires an approval of the same hash first: "this is the right plan" and "apply it now" are
         *     two decisions, and the second is worth making separately because it is the one that creates
         *     real virtual machines. The apply itself is enqueued afterwards by ``POST /ranges/{id}/deploy``,
         *     which refuses without this authorization.
         */
        post: operations["authorize_proxmox_apply_api_v1_ranges__range_id__proxmox_apply_authorization_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/ranges/{range_id}/proxmox/commands": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /**
         * List Proxmox Commands
         * @description The most recent record of each command kind for this range — the audit read.
         *
         *     One row per kind rather than the full history, because this answers "where is this range in the
         *     operator workflow". The complete, ordered history is already published by
         *     ``GET /ranges/{id}/events``, which is the same log these are folded from.
         */
        get: operations["list_proxmox_commands_api_v1_ranges__range_id__proxmox_commands_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/ranges/{range_id}/proxmox/destroy-authorization": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /**
         * Get Proxmox Destroy Authorization
         * @description Whether destroy is authorized. An apply authorization never satisfies this.
         */
        get: operations["get_proxmox_destroy_authorization_api_v1_ranges__range_id__proxmox_destroy_authorization_get"];
        put?: never;
        /**
         * Authorize Proxmox Destroy
         * @description Authorize destroy of an already-approved destroy plan. ENQUEUES NOTHING, DESTROYS NOTHING.
         *
         *     Structurally distinct from the apply authorization at every level: its own path, its own
         *     required field, its own hash domain, its own event kind and its own permission. There is no
         *     body that satisfies both.
         */
        post: operations["authorize_proxmox_destroy_api_v1_ranges__range_id__proxmox_destroy_authorization_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/ranges/{range_id}/proxmox/destroy-execution-request": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /**
         * Request Proxmox Destroy Execution
         * @description Request execution of the AUTHORIZED destroy. DESTROYS NOTHING HERE.
         *
         *     Structurally incapable of being satisfied by anything from the apply family: its own path, its
         *     own required field, its own hash domain, its own generation record, its own approval, its own
         *     authorization and its own permission. There is no apply artifact that reaches any of them.
         */
        post: operations["request_proxmox_destroy_execution_api_v1_ranges__range_id__proxmox_destroy_execution_request_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/ranges/{range_id}/proxmox/destroy-plan": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /**
         * Get Proxmox Destroy Plan
         * @description The destroy plan and its OWN hash.
         *
         *     A destroy is a bounded deletion scope, not the creation plan reversed, and its hash is computed
         *     in a different domain from the plan hash — so an approved plan hash is not a valid destroy hash
         *     for the same range, even when the underlying document is byte-identical.
         */
        get: operations["get_proxmox_destroy_plan_api_v1_ranges__range_id__proxmox_destroy_plan_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/ranges/{range_id}/proxmox/destroy-plan-approval": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /**
         * Approve Proxmox Destroy Plan
         * @description Approve the exact destroy plan, by its own hash. STARTS NOTHING.
         *
         *     Takes ``destroy_hash`` and rejects unknown fields, so a body built for the apply approval does
         *     not validate here.
         */
        post: operations["approve_proxmox_destroy_plan_api_v1_ranges__range_id__proxmox_destroy_plan_approval_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/ranges/{range_id}/proxmox/destroy-plan-generation": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /**
         * Generate Proxmox Destroy Plan
         * @description Materialise the deletion scope as its own durable record. DESTROYS NOTHING.
         *
         *     Takes ``destroy_hash`` and requires ``exercise:destroy``. Holding ``exercise:apply`` does not
         *     let you enumerate a deletion, and an apply body does not validate against this schema.
         */
        post: operations["generate_proxmox_destroy_plan_api_v1_ranges__range_id__proxmox_destroy_plan_generation_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/ranges/{range_id}/proxmox/evidence": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /**
         * Get Proxmox Evidence
         * @description Which evidence exists for this range and what identifies it. REFERENCES, never payloads.
         *
         *     Every class is listed whether or not it exists. Omitting the absent ones would make "we have no
         *     residue proof" indistinguishable from "nobody asked about residue".
         */
        get: operations["get_proxmox_evidence_api_v1_ranges__range_id__proxmox_evidence_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/ranges/{range_id}/proxmox/execution-request": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /**
         * Request Proxmox Execution
         * @description Request execution of the AUTHORIZED apply. APPLIES NOTHING HERE.
         *
         *     Requires the whole chain, each link refusing with its own stable code: generated, submitted,
         *     approved by hash, and apply authorized against that same hash. ``202`` because what it produced
         *     is a queued operation, not a finished apply.
         */
        post: operations["request_proxmox_execution_api_v1_ranges__range_id__proxmox_execution_request_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/ranges/{range_id}/proxmox/observation": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /**
         * Get Proxmox Observation
         * @description Which discovery snapshot this range plans against, and how stale it is.
         *
         *     ``freshness`` is ``absent`` when the worker has recorded no observation. That is the honest
         *     answer, not an error: the compiler needs facts a live cluster scan proves, and none may be
         *     assumed.
         */
        get: operations["get_proxmox_observation_api_v1_ranges__range_id__proxmox_observation_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/ranges/{range_id}/proxmox/ownership": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /**
         * Get Proxmox Ownership
         * @description How this range stamps what it creates, and which provenance classes a sweep never touches.
         */
        get: operations["get_proxmox_ownership_api_v1_ranges__range_id__proxmox_ownership_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/ranges/{range_id}/proxmox/plan": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /**
         * Get Proxmox Plan
         * @description The plan document, its hash, its approval state, and the isolation it proves.
         *
         *     The isolation findings here are properties of the COMPILED firewall, established before
         *     anything is applied. They are a different claim from the observed isolation in the verification
         *     report and are deliberately not merged with it.
         */
        get: operations["get_proxmox_plan_api_v1_ranges__range_id__proxmox_plan_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/ranges/{range_id}/proxmox/plan-approval": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /**
         * Approve Proxmox Plan
         * @description Approve the exact compiled plan, by hash. STARTS NOTHING.
         *
         *     409 if the hash is not the plan's current hash — which is the point of approving by hash. If the
         *     observation was re-recorded between reading the plan and approving it, the document the operator
         *     read is not the document that would be applied, and the approval must not silently transfer.
         */
        post: operations["approve_proxmox_plan_api_v1_ranges__range_id__proxmox_plan_approval_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/ranges/{range_id}/proxmox/plan-generation": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /**
         * Generate Proxmox Plan
         * @description Materialise the compiled plan as a durable, hash-identified record. STARTS NOTHING.
         */
        post: operations["generate_proxmox_plan_api_v1_ranges__range_id__proxmox_plan_generation_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/ranges/{range_id}/proxmox/plan-review-submission": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /**
         * Submit Proxmox Plan For Review
         * @description Put an exact generated plan in front of a reviewer. APPROVES NOTHING.
         *
         *     A separate act from approval and a separate permission (``plan:approve`` here,
         *     ``exercise:apply`` to approve). Submitting says "this is ready to be looked at"; approving says
         *     "I looked at it and it is right". Collapsing them lets whoever prepared a plan sign it off.
         */
        post: operations["submit_proxmox_plan_for_review_api_v1_ranges__range_id__proxmox_plan_review_submission_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/ranges/{range_id}/proxmox/readiness": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /**
         * Get Proxmox Readiness
         * @description Whether the PLAN would constitute a runnable two-team competition.
         *
         *     Says nothing about a deployed range — for that, read the verification report.
         */
        get: operations["get_proxmox_readiness_api_v1_ranges__range_id__proxmox_readiness_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/ranges/{range_id}/proxmox/reconciliation": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /**
         * Get Proxmox Reconciliation
         * @description Whether reconciliation was asked for, and whether anything has answered.
         *
         *     Two independent facts. ``requested`` says an operator asked; ``state`` says whether a worker
         *     recorded an observation, and stays ``undetermined`` until one does. Neither implies the other.
         */
        get: operations["get_proxmox_reconciliation_api_v1_ranges__range_id__proxmox_reconciliation_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/ranges/{range_id}/proxmox/reconciliation-request": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /**
         * Request Proxmox Reconciliation
         * @description Request reconciliation of the deployed range against its desired state.
         *
         *     ``201`` and not ``202``, because ``202`` would claim the work was accepted for processing and
         *     nothing has taken it: the response carries ``enqueued: false`` with
         *     ``not_enqueued_reason: reconciliation_consumer_unavailable``. The intent is durable and
         *     auditable; a worker picking it up is a separate, later fact. See
         *     :func:`secp_api.services.proxmox_commands.request_reconciliation` for why enqueueing it as a
         *     range operation would run a deploy.
         */
        post: operations["request_proxmox_reconciliation_api_v1_ranges__range_id__proxmox_reconciliation_request_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/ranges/{range_id}/proxmox/reset-authorization": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /**
         * Get Proxmox Reset Authorization
         * @description Whether a reset is authorized, and exactly which guests it would DESTROY.
         *
         *     Neither an apply nor a destroy authorization satisfies this. The scope is published because
         *     that is what is being approved: approving a reset without seeing the guests that will be
         *     deleted would be approving a deletion sight unseen.
         */
        get: operations["get_proxmox_reset_authorization_api_v1_ranges__range_id__proxmox_reset_authorization_get"];
        put?: never;
        /**
         * Authorize Proxmox Reset
         * @description Authorize a reset of an already-approved reset scope. ENQUEUES NOTHING, RESETS NOTHING.
         *
         *     Structurally distinct from the apply and destroy authorizations at every level: its own path,
         *     its own required field, its own hash domain, its own event kind and its own permission. There
         *     is no body that satisfies more than one of the three.
         */
        post: operations["authorize_proxmox_reset_api_v1_ranges__range_id__proxmox_reset_authorization_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/ranges/{range_id}/proxmox/reset-dispositions": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /**
         * Get Proxmox Reset Dispositions
         * @description What a reset did to each guest, as the worker observed it.
         *
         *     ``undetermined`` (no reset recorded) is distinct from a reset that ran and reported guests as
         *     ``recovery_required``.
         */
        get: operations["get_proxmox_reset_dispositions_api_v1_ranges__range_id__proxmox_reset_dispositions_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/ranges/{range_id}/proxmox/reset-plan": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /**
         * Get Proxmox Reset Plan
         * @description What a reset WOULD do to each guest.
         *
         *     A different endpoint and a different shape from ``/proxmox/reset-dispositions``, which reports
         *     what the worker OBSERVED a reset doing. A plan and an observation are different claims, and the
         *     moment they share a surface a client starts reading one as the other.
         */
        get: operations["get_proxmox_reset_plan_api_v1_ranges__range_id__proxmox_reset_plan_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/ranges/{range_id}/proxmox/reset-plan-approval": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /**
         * Approve Proxmox Reset Plan
         * @description Approve the exact reset scope, by its own hash. STARTS NOTHING.
         *
         *     Takes ``reset_hash`` and rejects unknown fields, so neither an apply nor a destroy body
         *     validates here. Requires ``exercise:reset``.
         */
        post: operations["approve_proxmox_reset_plan_api_v1_ranges__range_id__proxmox_reset_plan_approval_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/ranges/{range_id}/proxmox/reset-request": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /**
         * Request Proxmox Reset
         * @description Request a reset of the authorized reset scope. RESETS NOTHING HERE.
         *
         *     Gated on the RESET authorization, not the apply one. A reset DESTROYS every guest in the range
         *     and rebuilds it — ``proxmox_reset.plan_reset`` gives ``ResetSubject.guests`` the disposition
         *     ``recreated``, defined there as "Destroyed and rebuilt from the reviewed base image" — so an
         *     approval to create those guests does not authorize deleting the ones currently running.
         */
        post: operations["request_proxmox_reset_api_v1_ranges__range_id__proxmox_reset_request_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/ranges/{range_id}/proxmox/residue": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /**
         * Get Proxmox Residue
         * @description The zero-residue proof: what a teardown actually PROVED absent.
         *
         *     ``unproven`` is a verdict in its own right and is never folded into ``clean``.
         */
        get: operations["get_proxmox_residue_api_v1_ranges__range_id__proxmox_residue_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/ranges/{range_id}/proxmox/topology": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /**
         * Get Proxmox Topology
         * @description The compiled desired state — what would exist if this plan were applied exactly.
         *
         *     Each guest carries three separate addresses: the ``published_address`` a participant is told to
         *     use, the ``probe_address`` readiness verification actually connects to, and the
         *     ``observed_address`` the provider reported after apply. The published address is not
         *     necessarily reachable from the worker — #103 was exactly that — so none of the three is ever
         *     substituted for another, and an unobserved address stays null.
         */
        get: operations["get_proxmox_topology_api_v1_ranges__range_id__proxmox_topology_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/ranges/{range_id}/proxmox/topology-compilation": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /**
         * Compile Proxmox Topology
         * @description Recompile the topology from the observation of record. CONTACTS NOTHING.
         *
         *     "Refresh" means recompile against the newest observation the WORKER recorded. This process
         *     cannot go and look at a cluster, and an observation the control plane invented would be
         *     indistinguishable downstream from one discovery proved — which is the assumption the entire
         *     compiler safety argument rests on not being made.
         */
        post: operations["compile_proxmox_topology_api_v1_ranges__range_id__proxmox_topology_compilation_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/ranges/{range_id}/proxmox/verification": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /**
         * Get Proxmox Verification
         * @description What was OBSERVED after an apply, with infrastructure and isolation reported separately.
         *
         *     ``state`` is ``undetermined`` until the worker records a report. Undetermined is not a pass:
         *     nobody has looked yet.
         */
        get: operations["get_proxmox_verification_api_v1_ranges__range_id__proxmox_verification_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/ranges/{range_id}/proxmox/worker": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /**
         * Get Proxmox Worker
         * @description The enrolled worker that would execute for this range, and whether it may.
         *
         *     Installation, enrollment state, identity, release and eligibility in one answer. ``enrolled:
         *     false`` is a real response rather than a 404 — "nobody is enrolled" is something an operator
         *     needs to be told, and it is a different answer from "a worker is enrolled but is not healthy".
         *
         *     Publishes public identity only: no transaction id, no compare-and-swap digests, no key material.
         */
        get: operations["get_proxmox_worker_api_v1_ranges__range_id__proxmox_worker_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/ranges/{range_id}/proxmox/workload": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /**
         * Get Proxmox Workload
         * @description The per-guest workload and bootstrap contracts — including the WORKER's own addresses.
         *
         *     ``/proxmox/topology`` publishes the topology's ``published_address`` and ``probe_address`` plus
         *     the observed one. This publishes the bootstrap contract's ``probe_address``/``probe_port`` (what
         *     the worker connects to when it checks a guest came up) and ``report_address``/``report_port``
         *     (where the guest reports back), which had no route at all. They are separate concepts from the
         *     topology's addresses, none is ever substituted for another, and an absent one stays null.
         *
         *     Bootstrap material appears as a REFERENCE and never as material.
         */
        get: operations["get_proxmox_workload_api_v1_ranges__range_id__proxmox_workload_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/ranges/{range_id}/reset": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Reset Range */
        post: operations["reset_range_api_v1_ranges__range_id__reset_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/ranges/{range_id}/resources": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** List Range Resources */
        get: operations["list_range_resources_api_v1_ranges__range_id__resources_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/ranges/{range_id}/scenario": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /**
         * Get Range Scenario For Range
         * @description This range's scenario, with compatibility answered against ITS recorded observation.
         *
         *     The difference from the catalog read matters: there, every substrate-dependent Proxmox
         *     requirement is ``undetermined`` because no cluster is in scope. Here the requirements are
         *     answered from the observation the worker recorded for this range — so a missing management CIDR
         *     or an unobserved VLAN list becomes a NAMED blocker with the same ``reason_id`` the plan compiler
         *     would block on, rather than a generic "not ready".
         *
         *     A non-Proxmox range still gets an answer: its own provider's requirements are decidable from the
         *     catalog, and the Proxmox column stays ``undetermined`` because this range records no cluster
         *     observation.
         */
        get: operations["get_range_scenario_for_range_api_v1_ranges__range_id__scenario_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/ranges/{range_id}/scoreboard": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Get Range Scoreboard */
        get: operations["get_range_scoreboard_api_v1_ranges__range_id__scoreboard_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/ranges/{range_id}/teams": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** List Range Teams */
        get: operations["list_range_teams_api_v1_ranges__range_id__teams_get"];
        put?: never;
        /** Create Range Team */
        post: operations["create_range_team_api_v1_ranges__range_id__teams_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/ranges/{range_id}/teams/{team_id}/members": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** List Range Team Members */
        get: operations["list_range_team_members_api_v1_ranges__range_id__teams__team_id__members_get"];
        put?: never;
        /** Add Range Team Member */
        post: operations["add_range_team_member_api_v1_ranges__range_id__teams__team_id__members_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/ranges/{range_id}/teams/{team_id}/members/{member_id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        post?: never;
        /** Remove Range Team Member */
        delete: operations["remove_range_team_member_api_v1_ranges__range_id__teams__team_id__members__member_id__delete"];
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/ranges/{range_id}/teardown-evidence": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** List Range Teardown Evidence */
        get: operations["list_range_teardown_evidence_api_v1_ranges__range_id__teardown_evidence_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/readonly-preflight": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** List Preflights */
        get: operations["list_preflights_api_v1_readonly_preflight_get"];
        put?: never;
        /**
         * Queue Preflight
         * @description QUEUE durable read-only preflight intent. The API never executes collection; a worker does.
         *
         *     Read-only readiness verification only — it creates/alters/starts/stops nothing.
         */
        post: operations["queue_preflight_api_v1_readonly_preflight_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/readonly-preflight/{preflight_id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Get Preflight */
        get: operations["get_preflight_api_v1_readonly_preflight__preflight_id__get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/readonly-preflight/authorizations": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** List Authorizations */
        get: operations["list_authorizations_api_v1_readonly_preflight_authorizations_get"];
        put?: never;
        /**
         * Create Authorization
         * @description Create a DRAFT short-lived live-read authorization (hashes derived server-side).
         */
        post: operations["create_authorization_api_v1_readonly_preflight_authorizations_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/readonly-preflight/authorizations/{authorization_id}/approve": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Approve Authorization */
        post: operations["approve_authorization_api_v1_readonly_preflight_authorizations__authorization_id__approve_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/readonly-preflight/authorizations/{authorization_id}/revoke": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Revoke Authorization */
        post: operations["revoke_authorization_api_v1_readonly_preflight_authorizations__authorization_id__revoke_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/readonly-preflight/substrates": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /**
         * List Substrates
         * @description Eligible Proxmox staging substrates (same-org, active, eligible, onboarded); aliases only.
         */
        get: operations["list_substrates_api_v1_readonly_preflight_substrates_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/resolver-activation/authorizations": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** List Authorizations */
        get: operations["list_authorizations_api_v1_resolver_activation_authorizations_get"];
        put?: never;
        /** Create Authorization */
        post: operations["create_authorization_api_v1_resolver_activation_authorizations_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/resolver-activation/authorizations/{authorization_id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Get Authorization */
        get: operations["get_authorization_api_v1_resolver_activation_authorizations__authorization_id__get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/resolver-activation/authorizations/{authorization_id}/approve": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Approve Authorization */
        post: operations["approve_authorization_api_v1_resolver_activation_authorizations__authorization_id__approve_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/resolver-activation/authorizations/{authorization_id}/evidence": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Record Evidence */
        post: operations["record_evidence_api_v1_resolver_activation_authorizations__authorization_id__evidence_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/resolver-activation/authorizations/{authorization_id}/revoke": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Revoke Authorization */
        post: operations["revoke_authorization_api_v1_resolver_activation_authorizations__authorization_id__revoke_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/snapshots/{snapshot_id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Get Snapshot */
        get: operations["get_snapshot_api_v1_snapshots__snapshot_id__get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/snapshots/{snapshot_id}/resources": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** List Snapshot Resources */
        get: operations["list_snapshot_resources_api_v1_snapshots__snapshot_id__resources_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/staging-deployments": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** List Deployments */
        get: operations["list_deployments_api_v1_staging_deployments_get"];
        put?: never;
        /**
         * Create Deployment
         * @description Create a draft deployment bound to an active onboarding (all labels are server-owned).
         */
        post: operations["create_deployment_api_v1_staging_deployments_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/staging-deployments/{deployment_id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Get Deployment */
        get: operations["get_deployment_api_v1_staging_deployments__deployment_id__get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/staging-deployments/{deployment_id}/approve": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /**
         * Approve Deployment
         * @description Approve the EXACT reviewed plan (awaiting_approval -> approved), binding every drift anchor.
         *     Approval alone contacts nothing; it only authorizes a later worker-executed apply.
         */
        post: operations["approve_deployment_api_v1_staging_deployments__deployment_id__approve_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/staging-deployments/{deployment_id}/bootstrap-availability": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /**
         * Get Bootstrap Availability
         * @description A SAFE boolean + closed reason only. The one-time SSH bootstrap authority is worker-local and
         *     deployment-mounted; the API cannot and must not read it, so it is always reported unavailable
         *     here with a closed reason (never its location or contents).
         */
        get: operations["get_bootstrap_availability_api_v1_staging_deployments__deployment_id__bootstrap_availability_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/staging-deployments/{deployment_id}/deploy": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /**
         * Deploy
         * @description approved -> bootstrap_pending; ENQUEUES the durable apply operation (never run by the API).
         *
         *     The apply only proceeds if a worker-local bootstrap bundle has been injected into the running
         *     worker AND the exact approved plan still re-verifies; the API neither knows nor controls this.
         */
        post: operations["deploy_api_v1_staging_deployments__deployment_id__deploy_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/staging-deployments/{deployment_id}/plan": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /**
         * Get Plan
         * @description The immutable content-addressed plan: safe resource CATEGORIES + counts + generated refs.
         */
        get: operations["get_plan_api_v1_staging_deployments__deployment_id__plan_get"];
        put?: never;
        /**
         * Generate Plan
         * @description Compile the immutable content-addressed plan (draft -> planned). No infrastructure hit.
         */
        post: operations["generate_plan_api_v1_staging_deployments__deployment_id__plan_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/staging-deployments/{deployment_id}/reject": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /**
         * Reject Deployment
         * @description Reject a deployment awaiting approval. Records the closed decision code (no free text).
         */
        post: operations["reject_deployment_api_v1_staging_deployments__deployment_id__reject_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/staging-deployments/{deployment_id}/resources": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /**
         * List Resources
         * @description Resources the deployment created — safe category, ownership tag, generated ref, and state.
         */
        get: operations["list_resources_api_v1_staging_deployments__deployment_id__resources_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/staging-deployments/{deployment_id}/submit": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /**
         * Submit For Approval
         * @description planned -> awaiting_approval.
         */
        post: operations["submit_for_approval_api_v1_staging_deployments__deployment_id__submit_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/staging-deployments/{deployment_id}/teardown": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /**
         * Request Teardown
         * @description ready/failed/rolled_back -> teardown_requested; enqueues the durable teardown operation.
         */
        post: operations["request_teardown_api_v1_staging_deployments__deployment_id__teardown_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/staging-deployments/{deployment_id}/verifications": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /**
         * List Verifications
         * @description Post-apply verification results — closed check code + status only.
         */
        get: operations["list_verifications_api_v1_staging_deployments__deployment_id__verifications_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/staging-labs": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** List Staging Labs */
        get: operations["list_staging_labs_api_v1_staging_labs_get"];
        put?: never;
        /** Create Staging Lab */
        post: operations["create_staging_lab_api_v1_staging_labs_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/staging-labs/{lab_id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Get Staging Lab */
        get: operations["get_staging_lab_api_v1_staging_labs__lab_id__get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/staging-labs/{lab_id}/approve": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /**
         * Approve Staging Lab
         * @description Approve the exact reviewed plan. Grants permission to ENQUEUE fake simulation only —
         *     this is not a live-read authorization. Records the closed decision code (no free text).
         */
        post: operations["approve_staging_lab_api_v1_staging_labs__lab_id__approve_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/staging-labs/{lab_id}/plan": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /**
         * Generate Plan
         * @description Compile the immutable logical plan (no infrastructure is created).
         */
        post: operations["generate_plan_api_v1_staging_labs__lab_id__plan_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/staging-labs/{lab_id}/reject": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /**
         * Reject Staging Lab
         * @description Reject a lab awaiting approval. Records the closed decision code (no free text).
         */
        post: operations["reject_staging_lab_api_v1_staging_labs__lab_id__reject_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/staging-labs/{lab_id}/simulate": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /**
         * Queue Simulation
         * @description QUEUE a fake simulation. Simulation only — no infrastructure will be created. The lab
         *     enters ``simulation_queued``; a worker records completion later. The work identity is a
         *     server-generated fingerprint (no caller idempotency key).
         */
        post: operations["queue_simulation_api_v1_staging_labs__lab_id__simulate_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/staging-labs/{lab_id}/submit": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Submit For Approval */
        post: operations["submit_for_approval_api_v1_staging_labs__lab_id__submit_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/staging-labs/{lab_id}/teardown": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /**
         * Queue Teardown
         * @description QUEUE a fake teardown. Simulation only — no infrastructure exists to destroy. The lab
         *     enters ``teardown_queued``; a worker records completion later.
         */
        post: operations["queue_teardown_api_v1_staging_labs__lab_id__teardown_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/staging-labs/{lab_id}/work-items": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** List Work Items */
        get: operations["list_work_items_api_v1_staging_labs__lab_id__work_items_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/staging-labs/eligible-substrates": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /**
         * List Eligible Substrates
         * @description Substrates the UI may offer: same-org, active, Proxmox, eligible, onboarded (aliases).
         */
        get: operations["list_eligible_substrates_api_v1_staging_labs_eligible_substrates_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/target-discovery": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** List Enrollments */
        get: operations["list_enrollments_api_v1_target_discovery_get"];
        put?: never;
        /** Request Discovery */
        post: operations["request_discovery_api_v1_target_discovery_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/target-discovery/{enrollment_id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Get Enrollment */
        get: operations["get_enrollment_api_v1_target_discovery__enrollment_id__get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/target-discovery/{enrollment_id}/apply-status": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Get Apply Status */
        get: operations["get_apply_status_api_v1_target_discovery__enrollment_id__apply_status_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/target-discovery/{enrollment_id}/approve": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /**
         * Approve Candidate Plan
         * @description Approve the EXACT candidate plan. Grants NO execution — live apply remains sealed.
         */
        post: operations["approve_candidate_plan_api_v1_target_discovery__enrollment_id__approve_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/target-discovery/{enrollment_id}/bootstrap-availability": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /**
         * Get Bootstrap Availability
         * @description A SAFE boolean + closed reason only. The worker-local read-only SSH authority is
         *     worker-mounted
         *     and the API cannot read it, so it is always reported unavailable here (never its location).
         */
        get: operations["get_bootstrap_availability_api_v1_target_discovery__enrollment_id__bootstrap_availability_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/target-discovery/{enrollment_id}/candidate-plan": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Get Candidate Plan */
        get: operations["get_candidate_plan_api_v1_target_discovery__enrollment_id__candidate_plan_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/target-discovery/{enrollment_id}/evidence": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /**
         * Get Evidence
         * @description The safe capability/eligibility outcome from the latest immutable discovery snapshot.
         */
        get: operations["get_evidence_api_v1_target_discovery__enrollment_id__evidence_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/target-discovery/{enrollment_id}/reject": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Reject Candidate Plan */
        post: operations["reject_candidate_plan_api_v1_target_discovery__enrollment_id__reject_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/target-discovery/{enrollment_id}/rerun": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Rerun Discovery */
        post: operations["rerun_discovery_api_v1_target_discovery__enrollment_id__rerun_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/target-discovery/read-only-bootstrap/enrollments/{enrollment_id}/binding-descriptor": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Get Binding Descriptor */
        get: operations["get_binding_descriptor_api_v1_target_discovery_read_only_bootstrap_enrollments__enrollment_id__binding_descriptor_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/target-discovery/read-only-bootstrap/enrollments/{enrollment_id}/bundle-descriptor": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /**
         * Get Bundle Descriptor
         * @description SECP-B8: the secret-free superset the worker assembles its mounted bundle from. Fails closed
         *     unless the session is fully bound AND the host public key was captured.
         */
        get: operations["get_bundle_descriptor_api_v1_target_discovery_read_only_bootstrap_enrollments__enrollment_id__bundle_descriptor_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/target-discovery/read-only-bootstrap/enrollments/{enrollment_id}/readiness": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /**
         * Get Discovery Readiness
         * @description SECP-B8: precise missing-prerequisite diagnostic so the UI/worker never fails opaquely.
         */
        get: operations["get_discovery_readiness_api_v1_target_discovery_read_only_bootstrap_enrollments__enrollment_id__readiness_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/target-discovery/read-only-bootstrap/sessions": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** List Sessions */
        get: operations["list_sessions_api_v1_target_discovery_read_only_bootstrap_sessions_get"];
        put?: never;
        /** Create Session */
        post: operations["create_session_api_v1_target_discovery_read_only_bootstrap_sessions_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/target-discovery/read-only-bootstrap/sessions/{session_id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Get Session */
        get: operations["get_session_api_v1_target_discovery_read_only_bootstrap_sessions__session_id__get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/target-discovery/read-only-bootstrap/sessions/{session_id}/bind": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Bind Session */
        post: operations["bind_session_api_v1_target_discovery_read_only_bootstrap_sessions__session_id__bind_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/target-discovery/read-only-bootstrap/sessions/{session_id}/complete": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Complete Session */
        post: operations["complete_session_api_v1_target_discovery_read_only_bootstrap_sessions__session_id__complete_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/target-discovery/read-only-bootstrap/sessions/{session_id}/script": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Get Script */
        get: operations["get_script_api_v1_target_discovery_read_only_bootstrap_sessions__session_id__script_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/target-discovery/read-only-bootstrap/targets/{execution_target_id}/substrate-eligibility": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /**
         * Grant Substrate Eligibility
         * @description SECP-B8: guided target-admin action to grant staging-substrate eligibility (fixes the B7
         *     ``readonly_preflight_substrate_ineligible`` gap). Requires ``staging_substrate:manage`` — the
         *     service enforces it and NEVER silently auto-grants.
         */
        post: operations["grant_substrate_eligibility_api_v1_target_discovery_read_only_bootstrap_targets__execution_target_id__substrate_eligibility_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/target-discovery/read-only-bootstrap/worker-nodes": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** List Worker Nodes */
        get: operations["list_worker_nodes_api_v1_target_discovery_read_only_bootstrap_worker_nodes_get"];
        put?: never;
        /** Register Worker Node */
        post: operations["register_worker_node_api_v1_target_discovery_read_only_bootstrap_worker_nodes_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/target-discovery/read-only-bootstrap/worker-nodes/{node_id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Get Worker Node */
        get: operations["get_worker_node_api_v1_target_discovery_read_only_bootstrap_worker_nodes__node_id__get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/target-discovery/read-only-bootstrap/worker-nodes/{node_id}/identity-approval-link": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /**
         * Approve And Link Worker Identity
         * @description Perform one explicit reviewed registration/evidence/approval/link transaction.
         *
         *     This is a composition of the existing worker-identity lifecycle operations. It does not add a
         *     second lifecycle, infer evidence, or silently approve publication.
         */
        post: operations["approve_and_link_worker_identity_api_v1_target_discovery_read_only_bootstrap_worker_nodes__node_id__identity_approval_link_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/targets": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** List Targets */
        get: operations["list_targets_api_v1_targets_get"];
        put?: never;
        /** Register Target */
        post: operations["register_target_api_v1_targets_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/targets/{target_id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Get Target */
        get: operations["get_target_api_v1_targets__target_id__get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/targets/{target_id}/address-spaces": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** List Address Spaces */
        get: operations["list_address_spaces_api_v1_targets__target_id__address_spaces_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/targets/{target_id}/disable": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Disable Target */
        post: operations["disable_target_api_v1_targets__target_id__disable_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/targets/{target_id}/discover": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /**
         * Request Discovery
         * @description Queue a READ-ONLY discovery. Refused in inline dev mode (requires Temporal).
         */
        post: operations["request_discovery_api_v1_targets__target_id__discover_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/targets/{target_id}/onboarding": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** List Onboardings */
        get: operations["list_onboardings_api_v1_targets__target_id__onboarding_get"];
        put?: never;
        /** Create Onboarding */
        post: operations["create_onboarding_api_v1_targets__target_id__onboarding_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/targets/{target_id}/reservations": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** List Reservations */
        get: operations["list_reservations_api_v1_targets__target_id__reservations_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/targets/{target_id}/rotate-credential": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /**
         * Rotate Target Credential
         * @description The SUPPORTED path for replacing a target's opaque credential reference (B1B-PR4 §2).
         *
         *     Requires the dedicated ``credential_binding:manage`` permission and ROTATES the target's opaque
         *     credential binding, which invalidates every prior plan-secret authorization and readiness record
         *     without modifying any historical evidence. Credential replacement is never invisible.
         */
        post: operations["rotate_target_credential_api_v1_targets__target_id__rotate_credential_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/targets/{target_id}/rotate-operation-credential": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /**
         * Rotate Target Operation Credential
         * @description Replace an OPERATION-SPECIFIC opaque credential reference (B1B-PR5A, ADR-022).
         *
         *     Requires ``credential_binding:manage`` and rotates ONLY the matching opaque binding
         *     (``provider_plan_read`` or ``state_backend_plan``), invalidating every prior activation dossier,
         *     readiness record, and plan-generation authorization that folded the old binding version. Apply
         *     and destroy purposes are unrepresentable.
         */
        post: operations["rotate_target_operation_credential_api_v1_targets__target_id__rotate_operation_credential_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/targets/{target_id}/snapshots": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** List Snapshots */
        get: operations["list_snapshots_api_v1_targets__target_id__snapshots_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/targets/{target_id}/toolchain-profiles": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** List Toolchain Profiles */
        get: operations["list_toolchain_profiles_api_v1_targets__target_id__toolchain_profiles_get"];
        put?: never;
        /**
         * Register Toolchain Profile
         * @description Register an immutable, secret-free toolchain profile for an execution target.
         */
        post: operations["register_toolchain_profile_api_v1_targets__target_id__toolchain_profiles_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/templates": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** List Templates */
        get: operations["list_templates_api_v1_templates_get"];
        put?: never;
        /** Create Template */
        post: operations["create_template_api_v1_templates_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/templates/{template_id}/versions": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** List Versions */
        get: operations["list_versions_api_v1_templates__template_id__versions_get"];
        put?: never;
        /** Create Version */
        post: operations["create_version_api_v1_templates__template_id__versions_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/toolchain-profiles/{profile_id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Get Toolchain Profile */
        get: operations["get_toolchain_profile_api_v1_toolchain_profiles__profile_id__get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/toolchain-profiles/{profile_id}/disable": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Disable Toolchain Profile */
        post: operations["disable_toolchain_profile_api_v1_toolchain_profiles__profile_id__disable_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/topology-authoring/documents": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Create Draft */
        post: operations["create_draft_api_v1_topology_authoring_documents_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/topology-authoring/documents/{document_id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Get Document */
        get: operations["get_document_api_v1_topology_authoring_documents__document_id__get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/topology-authoring/documents/{document_id}/revisions": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** List Revisions */
        get: operations["list_revisions_api_v1_topology_authoring_documents__document_id__revisions_get"];
        put?: never;
        /** Create Revision */
        post: operations["create_revision_api_v1_topology_authoring_documents__document_id__revisions_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/topology-authoring/documents/{document_id}/revisions/{revision_id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Get Revision */
        get: operations["get_revision_api_v1_topology_authoring_documents__document_id__revisions__revision_id__get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/topology-authoring/documents/{document_id}/revisions/{revision_id}/approve": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Approve Revision */
        post: operations["approve_revision_api_v1_topology_authoring_documents__document_id__revisions__revision_id__approve_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/topology-authoring/documents/{document_id}/revisions/{revision_id}/reject": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Reject Revision */
        post: operations["reject_revision_api_v1_topology_authoring_documents__document_id__revisions__revision_id__reject_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/topology-authoring/documents/{document_id}/revisions/{revision_id}/submit": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Submit Revision */
        post: operations["submit_revision_api_v1_topology_authoring_documents__document_id__revisions__revision_id__submit_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/topology-authoring/documents/{document_id}/revisions/{revision_id}/validate": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Validate Revision */
        post: operations["validate_revision_api_v1_topology_authoring_documents__document_id__revisions__revision_id__validate_post"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/topology-authoring/documents/{document_id}/revisions/{revision_id}/validation": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Get Validation */
        get: operations["get_validation_api_v1_topology_authoring_documents__document_id__revisions__revision_id__validation_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/health": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /**
         * Health
         * @description Liveness probe used by Docker Compose and load balancers.
         */
        get: operations["health_health_get"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
}
export type webhooks = Record<string, never>;
export interface components {
    schemas: {
        /** AccessTargetOut */
        AccessTargetOut: {
            /** Component Key */
            component_key: string;
            /** Host */
            host: string;
            /** Name */
            name: string;
            /** Observed At */
            observed_at?: string | null;
            /** Port */
            port: number;
            /** Protocol */
            protocol: string;
            /** Reachable */
            reachable: boolean;
            /** Url */
            url: string;
        };
        /**
         * ActivationDossierEvidenceKind
         * @description The complete human-review evidence set required before an activation dossier may be approved.
         *
         *     Every kind must be present and ``verified``. Each carries only an opaque UUID proof id, a
         *     bounded
         *     issuer label, a status, and timestamps — never any live deployment value or raw proof text.
         * @enum {string}
         */
        ActivationDossierEvidenceKind: "target_boundary_reviewed" | "isolated_network_reviewed" | "dedicated_storage_reviewed" | "protected_route_absence_reviewed" | "resource_quotas_reviewed" | "provider_plan_credential_reviewed" | "state_backend_credential_reviewed" | "remote_state_recovery_reviewed" | "emergency_stop_owner_assigned" | "manual_containment_owner_assigned" | "plan_only_process_boundary_reviewed";
        /**
         * ActivationDossierEvidenceStatus
         * @description Status of one activation-dossier evidence item.
         * @enum {string}
         */
        ActivationDossierEvidenceStatus: "pending" | "verified";
        /** ActivationDossierOut */
        ActivationDossierOut: {
            /** Activation Dossier Id */
            activation_dossier_id: string;
            /** Approved At */
            approved_at?: string | null;
            /** Authorization Expiry */
            authorization_expiry: string;
            /** Dossier Hash */
            dossier_hash: string;
            /** Dossier Revision */
            dossier_revision: number;
            /** Evidence */
            evidence?: components["schemas"]["DossierEvidenceOut"][];
            /** Evidence Fingerprint */
            evidence_fingerprint: string;
            /** Execution Target Id */
            execution_target_id: string;
            /** Operation Kind */
            operation_kind: string;
            /** Provider Credential Binding Id */
            provider_credential_binding_id: string;
            /** Provider Credential Binding Version */
            provider_credential_binding_version: number;
            /** Provisioning Manifest Id */
            provisioning_manifest_id: string;
            /**
             * Revocation Reason Code
             * @default
             */
            revocation_reason_code: string;
            /** Revoked At */
            revoked_at?: string | null;
            /** State Credential Binding Id */
            state_credential_binding_id: string;
            /** State Credential Binding Version */
            state_credential_binding_version: number;
            /** Status */
            status: string;
        };
        /** AddressSpaceIn */
        AddressSpaceIn: {
            /** Cidr Block */
            cidr_block: string;
            /** Subnet Prefix */
            subnet_prefix: number;
        };
        /** AddressSpaceOut */
        AddressSpaceOut: {
            /** Cidr Block */
            cidr_block: string;
            /** Subnet Prefix */
            subnet_prefix: number;
        };
        /** ApprovalDecision */
        ApprovalDecision: {
            /**
             * Reason
             * @default
             */
            reason: string;
        };
        /**
         * ApprovalKind
         * @description Which of the six authorization acts a recorded approval is.
         *
         *     Three families — apply, reset, destroy — each with an approve step and an authorize step, each
         *     over a digest from its own hash domain. No member stands for more than one family, so a record
         *     read out of its response is still unambiguous about what was authorized.
         * @enum {string}
         */
        ApprovalKind: "plan_approval" | "apply_authorization" | "reset_plan_approval" | "reset_authorization" | "destroy_plan_approval" | "destroy_authorization";
        /**
         * ApprovalOut
         * @description A recorded approval or authorization, as it was made.
         *
         *     ``operation_kind`` names WHICH act this was, in the payload rather than only in the URL
         *     that returned it. Without it an approval record is a bare hash plus a principal, and an
         *     apply approval is indistinguishable from a destroy approval once it has been read out of
         *     its response. The hash domains already make one unusable as the other; this makes the
         *     difference legible as well.
         */
        ApprovalOut: {
            /** Approved By */
            approved_by: string | null;
            /** Approved Hash */
            approved_hash: string;
            /**
             * At
             * Format: date-time
             */
            at: string;
            operation_kind: components["schemas"]["ApprovalKind"];
        };
        /** AuditEventOut */
        AuditEventOut: {
            /** Action */
            action: string;
            /** Actor */
            actor: string;
            /**
             * Created At
             * Format: date-time
             */
            created_at: string;
            /** Data */
            data: {
                [key: string]: unknown;
            };
            /**
             * Id
             * Format: uuid
             */
            id: string;
            /** Outcome */
            outcome: string;
            /** Resource Id */
            resource_id: string | null;
            /** Resource Type */
            resource_type: string;
        };
        /**
         * AuthConfigOut
         * @description Public, SECRET-FREE browser authentication configuration (ADR-018 / OIDC-B).
         *
         *     Everything here is non-secret and server-owned. ``mode`` is derived from the dev-fallback gate;
         *     ``scope`` is a fixed value that excludes ``offline_access``; ``redirect_path`` /
         *     ``post_logout_redirect_path`` are fixed relative application paths. There is NO client secret,
         *     token, or endpoint credential — a public browser client has none, and the backend remains the
         *     authoritative token verifier (OIDC-A / ADR-017).
         */
        AuthConfigOut: {
            /** Audience */
            audience: string;
            /** Client Id */
            client_id: string;
            /** Issuer */
            issuer: string;
            /**
             * Mode
             * @enum {string}
             */
            mode: "dev_fallback" | "oidc";
            /** Post Logout Redirect Path */
            post_logout_redirect_path: string;
            /** Redirect Path */
            redirect_path: string;
            /** Scope */
            scope: string;
        };
        /**
         * AuthorizationState
         * @description Whether an apply/destroy authorization exists, folded from the log.
         * @enum {string}
         */
        AuthorizationState: "absent" | "authorized" | "superseded" | "undetermined";
        /**
         * BindExchangeOut
         * @description The bind-exchange response: the internally-signed controller offer + the bounded status.
         */
        BindExchangeOut: {
            enrollment: components["schemas"]["EnrollmentStatusOut"];
            signed_offer: components["schemas"]["SignedControllerOfferOut"];
        };
        /**
         * BindExchangeRequest
         * @description The worker-initiated bind exchange (proof-of-possession). Carries ONLY the worker's presented
         *     public key, its claimed installation label, the detached PoP attestation, and the last-observed
         *     revision. ``worker_key_id`` is NEVER accepted — it is derived from ``worker_public_key_hex``.
         */
        BindExchangeRequest: {
            attestation: components["schemas"]["DetachedAttestationIn"];
            /** Expected Revision */
            expected_revision: number;
            /** Worker Installation Id */
            worker_installation_id: string;
            /** Worker Public Key Hex */
            worker_public_key_hex: string;
        };
        /**
         * BindingDescriptorOut
         * @description The worker's secret-free ``binding.json`` — exactly the non-secret fields the mounted bundle
         *     requires. Contains no host/port/key material.
         */
        BindingDescriptorOut: {
            /**
             * Authorization Id
             * Format: uuid
             */
            authorization_id: string;
            /** Authorization Version */
            authorization_version: number;
            /** Endpoint Binding Hash */
            endpoint_binding_hash: string;
            /**
             * Enrollment Id
             * Format: uuid
             */
            enrollment_id: string;
            /**
             * Execution Target Id
             * Format: uuid
             */
            execution_target_id: string;
            /**
             * Onboarding Id
             * Format: uuid
             */
            onboarding_id: string;
            /**
             * Organization Id
             * Format: uuid
             */
            organization_id: string;
        };
        /**
         * BlockedReasonOut
         * @description One named missing prerequisite. ``reason_id`` is a stable key a client may branch on.
         */
        BlockedReasonOut: {
            /** Detail */
            detail: string;
            /** Observation */
            observation: string;
            /** Reason Id */
            reason_id: string;
        };
        /**
         * BootstrapAvailabilityOut
         * @description A SAFE boolean + closed refusal reason only — never the bootstrap bundle's location/contents.
         *
         *     From the control plane's perspective the one-time SSH bootstrap authority is worker-local and
         *     deployment-mounted, so it is reported as unavailable here with a closed reason; the API cannot
         *     and must not read it.
         */
        BootstrapAvailabilityOut: {
            /**
             * Available
             * @default false
             */
            available: boolean;
            /**
             * Reason Code
             * @default deployment_local_bootstrap_not_mounted
             */
            reason_code: string;
        };
        /** BootstrapCompleteRequest */
        BootstrapCompleteRequest: {
            /** Host Key Fingerprint */
            host_key_fingerprint: string;
            /** Host Public Key */
            host_public_key?: string | null;
            /** Proof Text */
            proof_text?: string | null;
        };
        /** BootstrapOperationOut */
        BootstrapOperationOut: {
            /** Description */
            description: string;
            /** Key */
            key: string;
            /** Timeout Seconds */
            timeout_seconds: number;
        };
        /** BootstrapScriptOut */
        BootstrapScriptOut: {
            /** Account */
            account: string;
            /** Pve Role */
            pve_role: string;
            /** Script */
            script: string;
            /**
             * Session Id
             * Format: uuid
             */
            session_id: string;
            /** Worker Ssh Public Key Fingerprint */
            worker_ssh_public_key_fingerprint: string;
        };
        /** BootstrapSessionCreate */
        BootstrapSessionCreate: {
            /**
             * Execution Target Id
             * Format: uuid
             */
            execution_target_id: string;
            /**
             * Ssh Port
             * @default 22
             */
            ssh_port: number;
            /** Worker Ssh Public Key */
            worker_ssh_public_key: string;
        };
        /** BootstrapSessionOut */
        BootstrapSessionOut: {
            /** Account */
            account: string;
            /** Authorization Version */
            authorization_version?: number | null;
            /**
             * Created At
             * Format: date-time
             */
            created_at: string;
            /** Endpoint Binding Hash */
            endpoint_binding_hash?: string | null;
            /**
             * Execution Target Id
             * Format: uuid
             */
            execution_target_id: string;
            /**
             * Expires At
             * Format: date-time
             */
            expires_at: string;
            /** Failure Code */
            failure_code?: string | null;
            /** Host Key Fingerprint */
            host_key_fingerprint?: string | null;
            /**
             * Id
             * Format: uuid
             */
            id: string;
            /** Live Read Authorization Id */
            live_read_authorization_id?: string | null;
            /**
             * Onboarding Id
             * Format: uuid
             */
            onboarding_id: string;
            /** Pve Role */
            pve_role: string;
            /** Ssh Port */
            ssh_port: number;
            /** Status */
            status: string;
            /**
             * Updated At
             * Format: date-time
             */
            updated_at: string;
            /** Worker Ssh Public Key Fingerprint */
            worker_ssh_public_key_fingerprint: string;
        };
        /**
         * BundleDescriptorOut
         * @description SECP-B8: the SECRET-FREE superset the worker's bundle manager assembles the mounted bundle
         *     from — the ``binding.json`` fields PLUS the SSH endpoint facts, the public host-key fingerprint,
         *     and the host PUBLIC key line for ``known_hosts``. NEVER contains a private key or credential.
         */
        BundleDescriptorOut: {
            /** Account */
            account: string;
            /**
             * Authorization Id
             * Format: uuid
             */
            authorization_id: string;
            /** Authorization Version */
            authorization_version: number;
            /** Endpoint Binding Hash */
            endpoint_binding_hash: string;
            /**
             * Enrollment Id
             * Format: uuid
             */
            enrollment_id: string;
            /**
             * Execution Target Id
             * Format: uuid
             */
            execution_target_id: string;
            /** Host Key Fingerprint */
            host_key_fingerprint: string;
            /** Host Public Key */
            host_public_key: string;
            /**
             * Onboarding Id
             * Format: uuid
             */
            onboarding_id: string;
            /**
             * Organization Id
             * Format: uuid
             */
            organization_id: string;
            /** Ssh Host */
            ssh_host: string;
            /** Ssh Port */
            ssh_port: number;
        };
        /** CandidatePlanOut */
        CandidatePlanOut: {
            /** Capacity Snapshot Hash */
            capacity_snapshot_hash: string;
            /** Enrollment Version */
            enrollment_version: number;
            /** Evidence Hash */
            evidence_hash: string;
            /** Executable */
            executable: boolean;
            /**
             * Expires At
             * Format: date-time
             */
            expires_at: string;
            /** Node */
            node: string;
            /** Ownership Tag */
            ownership_tag: string;
            /** Plan Hash */
            plan_hash: string;
            /** Plan Version */
            plan_version: number;
            /** Resource Profile */
            resource_profile: string;
            /** Resources */
            resources: components["schemas"]["CandidatePlanResourceOut"][];
            /** Status */
            status: string;
            /** Storage */
            storage: string;
            /** Worker Identity Version */
            worker_identity_version: number;
        };
        /**
         * CandidatePlanResourceOut
         * @description A candidate resource CATEGORY + generated ownership-safe identifiers. Never a
         *     secret/endpoint.
         */
        CandidatePlanResourceOut: {
            /** Kind */
            kind: string;
            /** Ownership Marker */
            ownership_marker: string;
            /** Resource Ref */
            resource_ref: string;
        };
        /**
         * CapabilityState
         * @description Whether this build can do something, and whether this caller may.
         *
         *     ``supported_unauthorized`` and ``not_supported`` were the same value before, and they are the
         *     two an operator most needs to tell apart: one is fixed by granting a permission, the other
         *     cannot be fixed at all in this build.
         * @enum {string}
         */
        CapabilityState: "not_supported" | "supported_unauthorized" | "supported_authorized" | "undetermined";
        /**
         * ChallengeOut
         * @description NOTE: there is deliberately no flag field. Adding one would leak solutions.
         */
        ChallengeOut: {
            /** Category */
            category: string;
            /**
             * Competition Id
             * Format: uuid
             */
            competition_id: string;
            /** Component Key */
            component_key?: string | null;
            /** Description */
            description: string;
            /** Hint */
            hint?: string | null;
            /**
             * Id
             * Format: uuid
             */
            id: string;
            /** Key */
            key: string;
            /** Max Attempts */
            max_attempts: number;
            /** Points */
            points: number;
            /** Solve Count */
            solve_count: number;
            /** Solved By Team Ids */
            solved_by_team_ids: string[];
            /** Title */
            title: string;
        };
        /** ChangeSetApprovalOut */
        ChangeSetApprovalOut: {
            /** Authorizes Kind */
            authorizes_kind: string;
            /** Change Set Hash */
            change_set_hash: string;
            /**
             * Created At
             * Format: date-time
             */
            created_at: string;
            /** Decided At */
            decided_at: string | null;
            /** Decision Reason */
            decision_reason: string;
            /**
             * Id
             * Format: uuid
             */
            id: string;
            /** Manifest Content Hash */
            manifest_content_hash: string;
            /**
             * Manifest Id
             * Format: uuid
             */
            manifest_id: string;
            /** Module Bundle Hash */
            module_bundle_hash: string;
            /**
             * Organization Id
             * Format: uuid
             */
            organization_id: string;
            /** Rendered Workspace Hash */
            rendered_workspace_hash: string;
            /** Renderer Version */
            renderer_version: string;
            /** Reservations Hash */
            reservations_hash: string;
            /** Status */
            status: string;
            /** Summary */
            summary: {
                [key: string]: unknown;
            };
            /** Target Scope Policy Hash */
            target_scope_policy_hash: string;
            /** Toolchain Profile Hash */
            toolchain_profile_hash: string;
            /**
             * Toolchain Profile Id
             * Format: uuid
             */
            toolchain_profile_id: string;
        };
        /**
         * CommandKind
         * @description Which operator act a durable command record is.
         *
         *     Each member is its own act with its own permission, its own preconditions and its own request
         *     schema. There is deliberately no ``approve`` or ``execute`` member that could stand for either
         *     an apply or a destroy — see the module docstring. ``operation_kind`` on the wire is exactly one
         *     of these, never derived by a client from the path it called.
         * @enum {string}
         */
        CommandKind: "compile_topology" | "generate_plan" | "submit_plan_for_review" | "request_execution" | "request_reset" | "request_reconciliation" | "generate_destroy_plan" | "request_destroy_execution";
        /** CompetitionCreate */
        CompetitionCreate: {
            /** Name */
            name?: string | null;
        };
        /** CompetitionOut */
        CompetitionOut: {
            /** Challenge Count */
            challenge_count: number;
            /**
             * Created At
             * Format: date-time
             */
            created_at: string;
            /**
             * Id
             * Format: uuid
             */
            id: string;
            /** Name */
            name: string;
            /**
             * Range Id
             * Format: uuid
             */
            range_id: string;
            /** Started At */
            started_at?: string | null;
            state: components["schemas"]["CompetitionState"];
            /** Stopped At */
            stopped_at?: string | null;
            /** Team Count */
            team_count: number;
            /** Total Points */
            total_points: number;
        };
        /**
         * CompetitionState
         * @enum {string}
         */
        CompetitionState: "draft" | "running" | "stopped";
        /**
         * CreateActivationDossierIn
         * @description Create a DRAFT activation dossier. Owner proofs are opaque tokens, never a real identity.
         */
        CreateActivationDossierIn: {
            /** Emergency Stop Owner Proof */
            emergency_stop_owner_proof: string;
            /** Recovery Owner Proof */
            recovery_owner_proof: string;
            /**
             * Ttl Seconds
             * @default 86400
             */
            ttl_seconds: number;
        };
        /**
         * CreateEnrollmentInvitation
         * @description Create a single-use worker-enrollment invitation. The controller identity, nonce, transaction
         *     id and timestamps are all server-owned; the enrollment id is derived from the invitation
         *     digest. Retry-safe: an exact retry with the same ``idempotency_key`` returns the original.
         */
        CreateEnrollmentInvitation: {
            /** Deployment Site Label */
            deployment_site_label: string;
            /** Idempotency Key */
            idempotency_key: string;
            /**
             * Ttl Seconds
             * @default 3600
             */
            ttl_seconds: number;
        };
        /**
         * CreatePlanGenerationAuthorizationIn
         * @description Create a DRAFT plan-generation authorization.
         *
         *     ``purpose`` is a closed enum whose ONLY member is ``plan_generation``: apply/destroy purposes
         *     are
         *     unrepresentable, so pydantic refuses such a body before any service code runs.
         */
        CreatePlanGenerationAuthorizationIn: {
            /** @default plan_generation */
            purpose: components["schemas"]["PlanGenerationPurpose"];
            /**
             * Ttl Seconds
             * @default 3600
             */
            ttl_seconds: number;
        };
        /**
         * CreatePlanSecretAuthorizationIn
         * @description Create a DRAFT plan-secret authorization.
         *
         *     ``purpose`` is a closed enum whose ONLY member is ``plan_read``: an ``apply`` or ``destroy``
         *     secret purpose is not merely rejected — it is unrepresentable, so pydantic refuses the request
         *     body before any service code runs.
         */
        CreatePlanSecretAuthorizationIn: {
            /** @default plan_read */
            purpose: components["schemas"]["PlanSecretPurpose"];
            /**
             * Ttl Seconds
             * @default 3600
             */
            ttl_seconds: number;
        };
        /** CreatePreflightAuthorization */
        CreatePreflightAuthorization: {
            /**
             * Execution Target Id
             * Format: uuid
             */
            execution_target_id: string;
            /**
             * Ttl Seconds
             * @default 900
             */
            ttl_seconds: number;
        };
        /** CreateResolverActivation */
        CreateResolverActivation: {
            /**
             * Preflight Id
             * Format: uuid
             */
            preflight_id: string;
            /**
             * Ttl Seconds
             * @default 3600
             */
            ttl_seconds: number;
        };
        /**
         * CredentialPurposeClass
         * @description The credential purpose classes a binding may serve (B1B-PR5A adds operation separation).
         *
         *     Two distinct real-plan purposes exist:
         *
         *     * ``provider_plan_read`` — the READ-ONLY provider (Proxmox) credential used to generate a plan.
         *       By declared purpose it is non-mutating; least privilege is NOT claimed from the label alone —
         *       the actual scope must be backed by reviewed activation-dossier evidence.
         *     * ``state_backend_plan`` — the SEPARATE remote-state-backend credential. It is never the same
         *       binding as the provider credential and never falls back to the generic ``secret_ref``.
         *
         *     **Apply and destroy credential purposes remain unrepresentable** — absent from this enum, so no
         *     caller can mint an apply/destroy credential binding. Each purpose sources its own dedicated
         *     opaque
         *     reference and rotates independently.
         * @enum {string}
         */
        CredentialPurposeClass: "provider_plan_read" | "state_backend_plan";
        /** DecisionBody */
        DecisionBody: {
            /**
             * Reason
             * @default
             */
            reason: string;
        };
        /** DeploymentApprove */
        DeploymentApprove: {
            /** Expected Plan Hash */
            expected_plan_hash: string;
        };
        /**
         * DeploymentCreate
         * @description All persisted labels are server-owned. Only a substrate UUID, a closed resource profile, and
         *     an optional strict logical name are accepted — never a host/endpoint/credential/free option.
         */
        DeploymentCreate: {
            /**
             * Execution Target Id
             * Format: uuid
             */
            execution_target_id: string;
            /** Logical Name */
            logical_name?: string | null;
            /**
             * Resource Profile
             * @default small_lab
             * @enum {string}
             */
            resource_profile: "small_lab" | "medium_lab";
        };
        /** DeploymentOut */
        DeploymentOut: {
            /** Approved At */
            approved_at: string | null;
            /** Approved Plan Hash */
            approved_plan_hash: string;
            /**
             * Created At
             * Format: date-time
             */
            created_at: string;
            /** Decision Code */
            decision_code: string;
            /** Display Name */
            display_name: string;
            /**
             * Execution Target Id
             * Format: uuid
             */
            execution_target_id: string;
            /** Failure Code */
            failure_code: string | null;
            /**
             * Id
             * Format: uuid
             */
            id: string;
            /**
             * Organization Id
             * Format: uuid
             */
            organization_id: string;
            /** Ownership Label */
            ownership_label: string;
            /** Plan Hash */
            plan_hash: string;
            /** Plan Version */
            plan_version: number;
            /** Resource Profile */
            resource_profile: string;
            /** Revision */
            revision: number;
            /** Status */
            status: string;
        };
        /** DeploymentPlanOut */
        DeploymentPlanOut: {
            /** Artifact Manifest Id */
            artifact_manifest_id: string;
            /** Capacity Assessment Hash */
            capacity_assessment_hash: string;
            /** Ownership Tag */
            ownership_tag: string;
            /** Plan Hash */
            plan_hash: string;
            /** Plan Version */
            plan_version: number;
            /** Resources */
            resources: components["schemas"]["PlannedResourceOut"][];
        };
        /** DeploymentResourceOut */
        DeploymentResourceOut: {
            /** Inverse Op */
            inverse_op: string;
            /** Ownership Tag */
            ownership_tag: string;
            /** Resource Kind */
            resource_kind: string;
            /** Resource Ref */
            resource_ref: string;
            /** State */
            state: string;
        };
        /** DeploymentVerificationOut */
        DeploymentVerificationOut: {
            /** Check Code */
            check_code: string;
            /** Status */
            status: string;
        };
        /**
         * DetachedAttestationIn
         * @description A detached Ed25519 attestation presented by the worker. PUBLIC material only.
         */
        DetachedAttestationIn: {
            /**
             * Algorithm
             * @constant
             */
            algorithm: "Ed25519";
            /** Key Id */
            key_id: string;
            /** Public Key Hex */
            public_key_hex: string;
            /** Signature */
            signature: string;
        };
        /**
         * DetachedAttestationOut
         * @description A detached Ed25519 attestation returned to the worker (the controller offer signature).
         */
        DetachedAttestationOut: {
            /** Algorithm */
            algorithm: string;
            /** Key Id */
            key_id: string;
            /** Public Key Hex */
            public_key_hex: string;
            /** Signature */
            signature: string;
        };
        /** DiscoveryApprove */
        DiscoveryApprove: {
            /** Expected Plan Hash */
            expected_plan_hash: string;
        };
        /**
         * DiscoveryBootstrapAvailabilityOut
         * @description A SAFE boolean + closed reason only — never the bootstrap bundle's location/contents. The
         *     worker-local read-only SSH authority is worker-mounted; the API cannot read it, so it is
         *     reported
         *     unavailable here with a closed reason.
         */
        DiscoveryBootstrapAvailabilityOut: {
            /**
             * Available
             * @default false
             */
            available: boolean;
            /**
             * Reason Code
             * @default worker_local_bootstrap_not_mounted
             */
            reason_code: string;
        };
        /**
         * DiscoveryEvidenceOut
         * @description The safe capability/eligibility outcome from the latest immutable discovery snapshot.
         *     Bounded,
         *     typed, secret-free facts only — never raw output, endpoint, address, or credential.
         */
        DiscoveryEvidenceOut: {
            /** Bundle Available */
            bundle_available: boolean;
            /** Candidate Vmids */
            candidate_vmids: number[];
            /** Contact State */
            contact_state: string;
            /** Cpu Total */
            cpu_total: number | null;
            /**
             * Created At
             * Format: date-time
             */
            created_at: string;
            /** Eligibility */
            eligibility: string;
            /** Evidence Hash */
            evidence_hash: string;
            /** Is Clustered */
            is_clustered: boolean | null;
            /** Mem Free Mb */
            mem_free_mb: number | null;
            /** Mem Total Mb */
            mem_total_mb: number | null;
            /** Nested Available */
            nested_available: boolean | null;
            /** Node */
            node: string | null;
            /** Node Count */
            node_count: number | null;
            /** Reason Code */
            reason_code: string | null;
            /** Selected Storage */
            selected_storage: string | null;
            /** Storage Count */
            storage_count: number;
            /** Version Major */
            version_major: number | null;
            /** Version Minor */
            version_minor: number | null;
        };
        /**
         * DiscoveryReadinessOut
         * @description SECP-B8: a precise, secret-free readiness diagnostic — which prerequisite is missing for an
         *     enrollment's live discovery path (so the worker never fails opaquely with sealed probes).
         */
        DiscoveryReadinessOut: {
            /** Bootstrap Session Id */
            bootstrap_session_id?: string | null;
            /** Bootstrap Status */
            bootstrap_status?: string | null;
            /** Checks */
            checks: {
                [key: string]: boolean;
            };
            /**
             * Enrollment Id
             * Format: uuid
             */
            enrollment_id: string;
            /**
             * Execution Target Id
             * Format: uuid
             */
            execution_target_id: string;
            /** Missing Prerequisites */
            missing_prerequisites: string[];
            /**
             * Onboarding Id
             * Format: uuid
             */
            onboarding_id: string;
            /** Ready */
            ready: boolean;
        };
        /**
         * DiscoveryRequest
         * @description Only a substrate UUID, a closed resource profile, and an optional strict logical name.
         */
        DiscoveryRequest: {
            /**
             * Execution Target Id
             * Format: uuid
             */
            execution_target_id: string;
            /** Logical Name */
            logical_name?: string | null;
            /**
             * Resource Profile
             * @default small_lab
             * @enum {string}
             */
            resource_profile: "small_lab" | "medium_lab";
        };
        /** DossierEvidenceOut */
        DossierEvidenceOut: {
            /** Issuer */
            issuer: string;
            /** Kind */
            kind: string;
            /** Proof Id */
            proof_id: string;
            /** Status */
            status: string;
        };
        /** EligibleSubstrateOut */
        EligibleSubstrateOut: {
            /** Alias */
            alias: string;
            /**
             * Id
             * Format: uuid
             */
            id: string;
        };
        /**
         * EnrollmentInvitationOut
         * @description The non-secret invitation an operator hands to a worker to begin enrollment.
         */
        EnrollmentInvitationOut: {
            /** Controller Installation Id */
            controller_installation_id: string;
            /** Controller Key Id */
            controller_key_id: string;
            /** Controller Origin */
            controller_origin: string;
            /** Controller Trust Anchor Hex */
            controller_trust_anchor_hex: string;
            /** Created At */
            created_at: string;
            /** Deployment Site Label */
            deployment_site_label: string;
            /** Enrollment Id */
            enrollment_id: string;
            /** Expires At */
            expires_at: string;
            /** Invitation Id */
            invitation_id: string;
            /** Release Digest */
            release_digest: string;
            /** Revision */
            revision: number;
            /** State */
            state: string;
            /** Transaction Id */
            transaction_id: string;
        };
        /**
         * EnrollmentListOut
         * @description One org-scoped page of the enrollment inventory.
         *
         *     NO invitation material appears here — a list carries only the bounded status projection. The
         *     single-use invitation is returned exactly once, by the create call (see the one-shot decision in
         *     this module's docstring); it is never re-derivable from a list, a status read, or a cursor.
         *
         *     ``next_cursor`` is an OPAQUE keyset continuation token over the ``(expires_at, enrollment_id)``
         *     order. It is null when this page was the last one. Clients must treat it as a blob: pass it back
         *     verbatim as ``after`` and never parse, construct, or persist its decoded form.
         */
        EnrollmentListOut: {
            /** Items */
            items: components["schemas"]["EnrollmentStatusOut"][];
            /** Next Cursor */
            next_cursor?: string | null;
        };
        /** EnrollmentOut */
        EnrollmentOut: {
            /** Active Plan Hash */
            active_plan_hash: string;
            /** Approved At */
            approved_at: string | null;
            /** Approved Plan Hash */
            approved_plan_hash: string;
            /**
             * Created At
             * Format: date-time
             */
            created_at: string;
            /** Decision Code */
            decision_code: string;
            /** Display Name */
            display_name: string;
            /** Enrollment Version */
            enrollment_version: number;
            /**
             * Execution Target Id
             * Format: uuid
             */
            execution_target_id: string;
            /** Failure Code */
            failure_code: string | null;
            /**
             * Id
             * Format: uuid
             */
            id: string;
            /**
             * Organization Id
             * Format: uuid
             */
            organization_id: string;
            /** Ownership Label */
            ownership_label: string;
            /** Resource Profile */
            resource_profile: string;
            /** Revision */
            revision: number;
            /** Status */
            status: string;
        };
        /**
         * EnrollmentStatusOut
         * @description The bounded, secret-free enrollment status projection (mirror of the durable public view).
         */
        EnrollmentStatusOut: {
            /** Controller Installation Id */
            controller_installation_id: string;
            /** Controller Key Fingerprint */
            controller_key_fingerprint: string;
            /** Deployment Site Label */
            deployment_site_label: string;
            /** Enrollment Id */
            enrollment_id: string;
            /** Expires At */
            expires_at: string;
            /** Offer Fingerprint */
            offer_fingerprint: string;
            /** Refusal Reason */
            refusal_reason: string;
            /** Release Fingerprint */
            release_fingerprint: string;
            /** Result Fingerprint */
            result_fingerprint: string;
            /** Revision */
            revision: number;
            /** State */
            state: string;
            /** Updated At */
            updated_at: string;
            /** Worker Installation Id */
            worker_installation_id: string;
            /** Worker Key Fingerprint */
            worker_key_fingerprint: string;
        };
        /**
         * EnvironmentPublicationRequest
         * @description Publish an approved topology revision + non-topology v1alpha2 definition into a new
         *     immutable EnvironmentVersion. ``definition`` stays a raw mapping because the publication
         *     service is the authoritative validator; the server owns hashing, provenance, and the
         *     idempotency fingerprint (none of which the caller may supply).
         */
        EnvironmentPublicationRequest: {
            /** Base Environment Version Id */
            base_environment_version_id?: string | null;
            /** Definition */
            definition: {
                [key: string]: unknown;
            };
            /** Expected Topology Content Hash */
            expected_topology_content_hash: string;
            /**
             * Template Id
             * Format: uuid
             */
            template_id: string;
            /**
             * Topology Document Id
             * Format: uuid
             */
            topology_document_id: string;
            /**
             * Topology Revision Id
             * Format: uuid
             */
            topology_revision_id: string;
            /**
             * Validation Result Id
             * Format: uuid
             */
            validation_result_id: string;
        };
        /**
         * EvidenceReferenceOut
         * @description One pointer to evidence. A reference and a timestamp, never a payload.
         *
         *     ``present`` is false with ``reference: null`` when this class of evidence does not exist yet —
         *     which is a different fact from evidence that exists and could not be read, and both are
         *     different from evidence that exists and is clean.
         */
        EvidenceReferenceOut: {
            /** Detail */
            detail?: string | null;
            /** Kind */
            kind: string;
            /** Observed At */
            observed_at?: string | null;
            /** Present */
            present: boolean;
            /** Reference */
            reference?: string | null;
        };
        /** ExerciseCreate */
        ExerciseCreate: {
            /** Execution Target Id */
            execution_target_id?: string | null;
            /** Name */
            name: string;
            /**
             * Template Id
             * Format: uuid
             */
            template_id: string;
            /**
             * Version Id
             * Format: uuid
             */
            version_id: string;
        };
        /** ExerciseOut */
        ExerciseOut: {
            /**
             * Created At
             * Format: date-time
             */
            created_at: string;
            /**
             * Environment Version Id
             * Format: uuid
             */
            environment_version_id: string;
            /** Execution Target Id */
            execution_target_id?: string | null;
            /**
             * Id
             * Format: uuid
             */
            id: string;
            /** Lifecycle State */
            lifecycle_state: string;
            /** Name */
            name: string;
            /**
             * Organization Id
             * Format: uuid
             */
            organization_id: string;
            /** Team Count */
            team_count: number;
            /**
             * Template Id
             * Format: uuid
             */
            template_id: string;
        };
        /** HTTPValidationError */
        HTTPValidationError: {
            /** Detail */
            detail?: components["schemas"]["ValidationError"][];
        };
        /** InstanceOut */
        InstanceOut: {
            /**
             * Exercise Id
             * Format: uuid
             */
            exercise_id: string;
            /**
             * Id
             * Format: uuid
             */
            id: string;
            /** Instance Ref */
            instance_ref: string;
            /** Lifecycle State */
            lifecycle_state: string;
            /** Provider */
            provider: string;
            /** Team Index */
            team_index: number;
            /** Team Ref */
            team_ref: string;
        };
        /**
         * IsolationFindingOut
         * @description One isolation property, proved or violated against the COMPILED firewall.
         *
         *     This is a property of the document, established before anything is applied. It is deliberately
         *     not the same claim as the observed isolation in the verification report, which is why the two
         *     appear in different places and are never merged.
         */
        IsolationFindingOut: {
            /** Detail */
            detail: string;
            /** Holds */
            holds: boolean;
            /** Property */
            property: string;
        };
        /**
         * IsolationModel
         * @description Target isolation model (SECP-002B-1B-0, ADR-014).
         *
         *     ``physical`` — a dedicated host/cluster (recommended secure preset).
         *     ``logical`` — a shared environment with an explicitly declared, enforceable,
         *     auditable, independently verifiable logical isolation boundary.
         * @enum {string}
         */
        IsolationModel: "physical" | "logical";
        /** ManifestOut */
        ManifestOut: {
            /** Content */
            content: {
                [key: string]: unknown;
            };
            /** Content Hash */
            content_hash: string;
            /**
             * Created At
             * Format: date-time
             */
            created_at: string;
            /**
             * Deployment Plan Id
             * Format: uuid
             */
            deployment_plan_id: string;
            /**
             * Execution Target Id
             * Format: uuid
             */
            execution_target_id: string;
            /**
             * Id
             * Format: uuid
             */
            id: string;
            /**
             * Organization Id
             * Format: uuid
             */
            organization_id: string;
            /** Target Config Hash */
            target_config_hash: string;
            /** Target Scope Policy Hash */
            target_scope_policy_hash?: string | null;
            /** Toolchain Profile Hash */
            toolchain_profile_hash?: string | null;
            /** Toolchain Profile Id */
            toolchain_profile_id?: string | null;
            /** Validated At */
            validated_at: string | null;
        };
        /**
         * MarkRecoveryRequired
         * @description Operator-triggered recovery: mark an enrollment as needing operator remediation.
         *
         *     The complement of the scheduled expiry sweep — the sweep reaches enrollments that ran out of
         *     time, this reaches one an operator has decided is stuck, without waiting for the TTL. Carries
         *     ONLY the last-observed ``expected_revision``; the reason code is server-owned (a bounded code,
         *     never caller free-text) and the durable CAS coordinates are derived server-side.
         */
        MarkRecoveryRequired: {
            /** Expected Revision */
            expected_revision: number;
        };
        /**
         * MaterialRefOut
         * @description A REFERENCE to post-provisioning material. Never the material.
         *
         *     The reference names where something lives and on which channel it travels. Publishing the
         *     reference lets an operator reason about a stuck bootstrap; publishing the material would put
         *     it in a response, a log and a browser cache.
         */
        MaterialRefOut: {
            /** Channel */
            channel: string;
            /** Purpose */
            purpose: string;
            /** Ref */
            ref: string;
            /** Scope */
            scope: string;
        };
        /**
         * ObservationFreshness
         * @description How much the recorded cluster observation can still be relied on.
         * @enum {string}
         */
        ObservationFreshness: "fresh" | "stale" | "undetermined" | "absent";
        /** OnboardingCreate */
        OnboardingCreate: {
            /** Declared Boundary */
            declared_boundary: {
                [key: string]: unknown;
            };
            isolation_model: components["schemas"]["IsolationModel"];
            onboarding_mode: components["schemas"]["OnboardingMode"];
        };
        /** OnboardingDecision */
        OnboardingDecision: {
            /**
             * Reason
             * @default
             */
            reason: string;
        };
        /**
         * OnboardingMode
         * @description How a target is brought under SECP management (SECP-002B-1B-0, ADR-014).
         *
         *     ``clean_server`` — the user brings a new/empty eligible server; SECP guides safe
         *     setup and then creates scenario infrastructure automatically.
         *     ``existing_environment`` — the user selects an existing node/cluster and declares an
         *     explicit, enforceable boundary; SECP deploys only inside it.
         * @enum {string}
         */
        OnboardingMode: "clean_server" | "existing_environment";
        /** OnboardingOut */
        OnboardingOut: {
            /** Activated At */
            activated_at: string | null;
            /** Approved Boundary Hash */
            approved_boundary_hash: string | null;
            /** Approved Preflight Evidence Hash */
            approved_preflight_evidence_hash: string | null;
            /** Approved Preflight Id */
            approved_preflight_id: string | null;
            /** Approved Scope Policy Hash */
            approved_scope_policy_hash: string | null;
            /** Approved Target Config Hash */
            approved_target_config_hash: string | null;
            /** Approved Verification Level */
            approved_verification_level: string | null;
            /** Boundary Hash */
            boundary_hash: string;
            /**
             * Created At
             * Format: date-time
             */
            created_at: string;
            /** Decided At */
            decided_at: string | null;
            /** Decision Reason */
            decision_reason: string;
            /** Declared Boundary */
            declared_boundary: {
                [key: string]: unknown;
            };
            /**
             * Execution Target Id
             * Format: uuid
             */
            execution_target_id: string;
            /**
             * Id
             * Format: uuid
             */
            id: string;
            /** Isolation Model */
            isolation_model: string;
            /**
             * Isolation Profile
             * @description Declared isolation profile (backward-compatible default: fully_segregated).
             */
            readonly isolation_profile: string;
            /**
             * Network Approach
             * @description Durable network approach declared in the boundary (backward-compatible default).
             */
            readonly network_approach: string;
            /** Onboarding Mode */
            onboarding_mode: string;
            /**
             * Organization Id
             * Format: uuid
             */
            organization_id: string;
            /** Status */
            status: string;
        };
        /**
         * OperationCapabilityOut
         * @description One operator verb and whether this caller can use it.
         */
        OperationCapabilityOut: {
            /** Detail */
            detail: string;
            /** Operation */
            operation: string;
            /** Required Permission */
            required_permission: string;
            state: components["schemas"]["CapabilityState"];
        };
        /** OperationOut */
        OperationOut: {
            /** Attempts */
            attempts: number;
            /**
             * Created At
             * Format: date-time
             */
            created_at: string;
            /** Error */
            error: string | null;
            /** Finished At */
            finished_at: string | null;
            /**
             * Id
             * Format: uuid
             */
            id: string;
            /** Idempotency Key */
            idempotency_key: string;
            /** Kind */
            kind: string;
            /**
             * Manifest Id
             * Format: uuid
             */
            manifest_id: string;
            /** Operation Ref */
            operation_ref: string | null;
            /** Result */
            result: {
                [key: string]: unknown;
            };
            /** Runner */
            runner: string;
            /** Status */
            status: string;
        };
        /**
         * OwnershipClassOut
         * @description How this range stamps the objects it creates, and what that excludes.
         *
         *     Ownership is decided by TAGS and never by name: a name collision or a recycled id must not put
         *     an unrelated guest in this range's destroy scope.
         */
        OwnershipClassOut: {
            /** Acts On */
            acts_on: string[];
            /** Generation */
            generation: number;
            /** Never Touches */
            never_touches: string[];
            /** Operation Generation */
            operation_generation: number;
            /** Organization Id */
            organization_id: string;
            /** Range Id */
            range_id: string;
            /** Tags */
            tags: {
                [key: string]: string;
            };
            /** Target Id */
            target_id: string;
        };
        /**
         * PlanEnvironmentVersionBindingOut
         * @description Typed read model for the ONE EnvironmentVersion a DeploymentPlan binds (ADR-016 PR E).
         *
         *     Derived from the exact immutable EnvironmentVersion the plan pins via
         *     ``environment_version_id`` + ``version_content_hash`` — NOT from plan.summary, the version
         *     spec, or any topology-authoring row. It carries no full spec and adds no second canonical
         *     binding: the plan's only canonical version binding stays ``environment_version_id`` +
         *     ``version_content_hash``. ``publication_provenance`` is the same server-owned provenance
         *     surfaced by ``VersionOut`` (null for legacy/manual v1alpha1).
         */
        PlanEnvironmentVersionBindingOut: {
            /** Api Version */
            api_version: string;
            /** Content Hash */
            content_hash: string;
            /**
             * Environment Version Id
             * Format: uuid
             */
            environment_version_id: string;
            publication_provenance: components["schemas"]["VersionPublicationProvenanceOut"] | null;
            /**
             * Template Id
             * Format: uuid
             */
            template_id: string;
            /** Version Number */
            version_number: number;
        };
        /** PlanGenerationAuthorizationOut */
        PlanGenerationAuthorizationOut: {
            /** Activation Dossier Id */
            activation_dossier_id: string;
            /** Approved At */
            approved_at?: string | null;
            /** Authorization Expiry */
            authorization_expiry: string;
            /** Authorization Version */
            authorization_version: number;
            /** Consumed At */
            consumed_at?: string | null;
            /** Evidence Fingerprint */
            evidence_fingerprint: string;
            /** Operation Fingerprint */
            operation_fingerprint: string;
            /** Plan Generation Authorization Id */
            plan_generation_authorization_id: string;
            /** Plan Only Capability Contract Version */
            plan_only_capability_contract_version: string;
            /** Provisioning Manifest Id */
            provisioning_manifest_id: string;
            /** Purpose */
            purpose: string;
            /**
             * Revocation Reason Code
             * @default
             */
            revocation_reason_code: string;
            /** Revoked At */
            revoked_at?: string | null;
            /** Status */
            status: string;
        };
        /**
         * PlanGenerationPurpose
         * @description The SOLE representable real-plan authorization purpose (B1B-PR5A, ADR-022).
         *
         *     ``plan_generation`` authorizes generating a real plan and NOTHING else. Apply, destroy, provider
         *     mutation, state mutation, credential rotation, and dossier approval are **unrepresentable**
         *     here,
         *     so pydantic refuses any other purpose before service code runs.
         * @enum {string}
         */
        PlanGenerationPurpose: "plan_generation";
        /**
         * PlanGenerationReadinessOut
         * @description The derived combined plan-readiness view. It is NOT plan approval and launches nothing.
         */
        PlanGenerationReadinessOut: {
            /** Activation Dossier Id */
            activation_dossier_id?: string | null;
            /** Plan Generation Authorization Id */
            plan_generation_authorization_id?: string | null;
            /** Plan Secret Readiness Id */
            plan_secret_readiness_id?: string | null;
            /** Provider Credential Binding Id */
            provider_credential_binding_id?: string | null;
            /** Readiness Policy Version */
            readiness_policy_version: string;
            /** Ready */
            ready: boolean;
            /** Reasons */
            reasons?: string[];
            /** Remote State Readiness Id */
            remote_state_readiness_id?: string | null;
            /** State Credential Binding Id */
            state_credential_binding_id?: string | null;
        };
        /**
         * PlanGenerationRequestAccepted
         * @description The API durably ENQUEUED the operation. It executed nothing and contacted nothing.
         */
        PlanGenerationRequestAccepted: {
            /** Operation Kind */
            operation_kind: string;
            /** Provisioning Manifest Id */
            provisioning_manifest_id: string;
            /**
             * Status
             * @default queued
             */
            status: string;
        };
        /**
         * PlannedResourceOut
         * @description One planned resource CATEGORY + bounded count + generated ownership-bound reference. NEVER a
         *     secret, endpoint, host, or real bridge/VMID/storage name.
         */
        PlannedResourceOut: {
            /** Count */
            count: number;
            /** Kind */
            kind: string;
            /** Resource Ref */
            resource_ref: string;
        };
        /** PlanOut */
        PlanOut: {
            /** Approved Content Hash */
            approved_content_hash: string | null;
            /**
             * Created At
             * Format: date-time
             */
            created_at: string;
            /** Decided At */
            decided_at: string | null;
            environment_version_binding?: components["schemas"]["PlanEnvironmentVersionBindingOut"] | null;
            /**
             * Environment Version Id
             * Format: uuid
             */
            environment_version_id: string;
            /** Execution Target Id */
            execution_target_id?: string | null;
            /**
             * Exercise Id
             * Format: uuid
             */
            exercise_id: string;
            /**
             * Id
             * Format: uuid
             */
            id: string;
            /** Status */
            status: string;
            /** Summary */
            summary: {
                [key: string]: unknown;
            };
            /** Target Config Hash */
            target_config_hash?: string | null;
            /** Version Content Hash */
            version_content_hash: string;
        };
        /** PlanSecretAuthorizationOut */
        PlanSecretAuthorizationOut: {
            /** Approved At */
            approved_at?: string | null;
            /** Authorization Expiry */
            authorization_expiry: string;
            /** Authorization Id */
            authorization_id: string;
            /** Authorization Version */
            authorization_version: number;
            /** Credential Binding Id */
            credential_binding_id: string;
            /** Credential Binding Version */
            credential_binding_version: number;
            /** Credential Reference Scheme */
            credential_reference_scheme: string;
            /** Deployment Plan Id */
            deployment_plan_id: string;
            /** Evidence */
            evidence?: components["schemas"]["PlanSecretEvidenceOut"][];
            /** Evidence Fingerprint */
            evidence_fingerprint: string;
            /** Execution Target Id */
            execution_target_id: string;
            /** Operation Fingerprint */
            operation_fingerprint: string;
            /** Provisioning Manifest Id */
            provisioning_manifest_id: string;
            /** Readiness Policy Version */
            readiness_policy_version: string;
            /** Resolver Contract Version */
            resolver_contract_version: string;
            /**
             * Revocation Reason Code
             * @default
             */
            revocation_reason_code: string;
            /** Revoked At */
            revoked_at?: string | null;
            /** Secret Purpose */
            secret_purpose: string;
            /** Status */
            status: string;
            /** Target Onboarding Id */
            target_onboarding_id: string;
            /** Toolchain Attestation Id */
            toolchain_attestation_id: string;
        };
        /**
         * PlanSecretEvidenceKind
         * @description The closed human-review evidence package a plan-secret authorization must carry.
         *
         *     Every kind must be present and ``verified`` before approval. These are REVIEW facts about the
         *     deployment, recorded as opaque proof metadata only — never a reference, endpoint, or secret.
         * @enum {string}
         */
        PlanSecretEvidenceKind: "least_privileged_plan_credential_review" | "credential_rotation_revocation_review" | "worker_only_jit_injection_review" | "no_apply_or_destroy_capability_review" | "secret_backend_access_policy_review" | "independent_adversarial_review";
        /** PlanSecretEvidenceOut */
        PlanSecretEvidenceOut: {
            /** Issuer */
            issuer: string;
            /** Kind */
            kind: string;
            /** Proof Id */
            proof_id: string;
            /** Status */
            status: string;
        };
        /**
         * PlanSecretEvidenceStatus
         * @enum {string}
         */
        PlanSecretEvidenceStatus: "pending" | "verified" | "failed";
        /**
         * PlanSecretPurpose
         * @description The ONLY secret purpose PR4 may bind (ADR-021 §7 / plan-only phase).
         *
         *     ``plan_read`` is a READ-ONLY provider credential class for a future ``init``/``plan``/``show``
         *     operation. Apply and destroy purposes are DELIBERATELY ABSENT from this enum, so an
         *     apply/destroy secret purpose is not merely rejected — it is unrepresentable. Adding one is a
         *     reviewed code change in that capability's own separately-reviewed phase.
         * @enum {string}
         */
        PlanSecretPurpose: "plan_read";
        /** PlanSecretReadinessOut */
        PlanSecretReadinessOut: {
            /** Adapter Registration Id */
            adapter_registration_id: string;
            /** Authorization Id */
            authorization_id: string;
            /** Authorization Version */
            authorization_version: number;
            /** Capability Class */
            capability_class: string;
            /** Collected At */
            collected_at: string;
            /** Credential Binding Id */
            credential_binding_id: string;
            /** Credential Binding Version */
            credential_binding_version: number;
            /** Current */
            current: boolean;
            /** Eligibility Evidence Hash */
            eligibility_evidence_hash: string;
            /** Env Contract Version */
            env_contract_version: string;
            /** Evidence Hash */
            evidence_hash: string;
            /** Expired */
            expired: boolean;
            /** Expires At */
            expires_at: string;
            /** Facets */
            facets?: components["schemas"]["ReadinessFacetOut"][];
            /** Operation Fingerprint */
            operation_fingerprint: string;
            /** Operation Kind */
            operation_kind: string;
            /** Outcome */
            outcome: string;
            /** Provisioning Manifest Id */
            provisioning_manifest_id: string;
            /** Readiness Policy Version */
            readiness_policy_version: string;
            /** Reason Codes */
            reason_codes?: string[];
            /** Record Id */
            record_id: string;
            /** Remote State Readiness Id */
            remote_state_readiness_id: string;
            /** Resolver Contract Version */
            resolver_contract_version: string;
            /** Secret Purpose */
            secret_purpose: string;
            /** Self Test Policy Version */
            self_test_policy_version: string;
            /** Self Test Proof Id */
            self_test_proof_id: string;
            /** Toolchain Attestation Hash */
            toolchain_attestation_hash: string;
            /** Toolchain Attestation Id */
            toolchain_attestation_id: string;
            /** Toolchain Profile Hash */
            toolchain_profile_hash: string;
        };
        /**
         * PlanState
         * @description Where the compiled plan stands.
         * @enum {string}
         */
        PlanState: "compiled" | "approved" | "superseded" | "blocked";
        /** PluginOut */
        PluginOut: {
            /** Capabilities */
            capabilities: string[];
            /** Contract Version */
            contract_version: string;
            /** Healthy */
            healthy: boolean;
            /** Name */
            name: string;
            /** Simulated */
            simulated: boolean;
            /** Version */
            version: string;
        };
        /** PreflightAuthorizationOut */
        PreflightAuthorizationOut: {
            /** Approved At */
            approved_at: string | null;
            /**
             * Authorization Expiry
             * Format: date-time
             */
            authorization_expiry: string;
            /** Authorization Version */
            authorization_version: number;
            /**
             * Created At
             * Format: date-time
             */
            created_at: string;
            /**
             * Execution Target Id
             * Format: uuid
             */
            execution_target_id: string;
            /**
             * Id
             * Format: uuid
             */
            id: string;
            /**
             * Onboarding Id
             * Format: uuid
             */
            onboarding_id: string;
            /**
             * Organization Id
             * Format: uuid
             */
            organization_id: string;
            /** Revoked At */
            revoked_at: string | null;
            /** Status */
            status: string;
        };
        /** PreflightOut */
        PreflightOut: {
            /** Checks */
            checks: unknown[];
            /** Collector */
            collector: string;
            /** Collector Identity */
            collector_identity: string;
            /** Collector Kind */
            collector_kind: string;
            /**
             * Created At
             * Format: date-time
             */
            created_at: string;
            /** Evidence Hash */
            evidence_hash: string;
            /** Evidence Version */
            evidence_version: number;
            /**
             * Id
             * Format: uuid
             */
            id: string;
            /**
             * Onboarding Id
             * Format: uuid
             */
            onboarding_id: string;
            /**
             * Organization Id
             * Format: uuid
             */
            organization_id: string;
            /** Passed */
            passed: boolean;
            /** Target Evidence Hash */
            target_evidence_hash: string | null;
            /** Target Evidence Id */
            target_evidence_id: string | null;
            /** Verification Level */
            verification_level: string;
        };
        /** PreflightSubstrateOut */
        PreflightSubstrateOut: {
            /** Alias */
            alias: string;
            /**
             * Id
             * Format: uuid
             */
            id: string;
        };
        /** PrincipalOut */
        PrincipalOut: {
            /** Email */
            email: string;
            /** Is Dev Fallback */
            is_dev_fallback: boolean;
            /**
             * Organization Id
             * Format: uuid
             */
            organization_id: string;
            /** Permissions */
            permissions: string[];
            /**
             * User Id
             * Format: uuid
             */
            user_id: string;
        };
        /**
         * ProviderCapabilitiesOut
         * @description Derived capability. No field here is a constant somebody chose.
         */
        ProviderCapabilitiesOut: {
            /** Authorized Operations */
            authorized_operations?: string[];
            /** Discovery */
            discovery: string;
            /** Discovery Detail */
            discovery_detail: string;
            /** Operations */
            operations: components["schemas"]["OperationCapabilityOut"][];
            /** Providers */
            providers: components["schemas"]["ProviderCapabilityOut"][];
            /** Unauthorized Operations */
            unauthorized_operations?: string[];
            /** Unsupported Operations */
            unsupported_operations?: string[];
        };
        /**
         * ProviderCapabilityOut
         * @description What one provider substrate can do in this build.
         */
        ProviderCapabilityOut: {
            /** Deployable */
            deployable: boolean;
            /** Detail */
            detail: string;
            /** Lifecycle Operations */
            lifecycle_operations?: string[];
            /** Provider */
            provider: string;
        };
        /**
         * ProviderCompatibilityOut
         * @description How one scenario stands on one provider — including when the answer is "it cannot run".
         */
        ProviderCompatibilityOut: {
            /** Blocked */
            blocked: boolean;
            /** Blockers */
            blockers: components["schemas"]["RequirementFindingOut"][];
            /** Max Teams */
            max_teams?: number | null;
            /** Min Teams */
            min_teams?: number | null;
            /** Provider */
            provider: string;
            /** Requirements */
            requirements: components["schemas"]["RequirementFindingOut"][];
            support: components["schemas"]["ProviderSupport"];
            /** Template Slug */
            template_slug?: string | null;
            /** Unmet Capabilities */
            unmet_capabilities: components["schemas"]["RequirementFindingOut"][];
        };
        /**
         * ProviderSupport
         * @description Whether a scenario can run on a provider at all — a property of the shipped catalog.
         * @enum {string}
         */
        ProviderSupport: "supported" | "unsupported";
        /**
         * ProvisioningReadinessOut
         * @description The derived combined current-readiness view. It is NOT plan approval and launches nothing.
         */
        ProvisioningReadinessOut: {
            /** Credential Binding Id */
            credential_binding_id?: string | null;
            /** Credential Binding Version */
            credential_binding_version?: number | null;
            /** Eligibility Preflight Id */
            eligibility_preflight_id?: string | null;
            /** Plan Secret Authorization Id */
            plan_secret_authorization_id?: string | null;
            /** Plan Secret Readiness Id */
            plan_secret_readiness_id?: string | null;
            /** Readiness Policy Version */
            readiness_policy_version: string;
            /** Ready */
            ready: boolean;
            /** Reasons */
            reasons?: string[];
            /** Remote State Readiness Id */
            remote_state_readiness_id?: string | null;
            /** Toolchain Attestation Id */
            toolchain_attestation_id?: string | null;
        };
        /**
         * ProxmoxAllocationOut
         * @description One deterministic allocation. The same binding always produces the same value.
         */
        ProxmoxAllocationOut: {
            /** Kind */
            kind: string;
            /** Label */
            label: string;
            /** Purpose */
            purpose: string;
            /** Team Ref */
            team_ref?: string | null;
            /** Value */
            value: string;
        };
        /**
         * ProxmoxAllocationsOut
         * @description Every identifier the plan reserves, before any of them exists on the cluster.
         */
        ProxmoxAllocationsOut: {
            /** Allocations */
            allocations?: components["schemas"]["ProxmoxAllocationOut"][] | null;
            /** Blocked Reasons */
            blocked_reasons?: components["schemas"]["BlockedReasonOut"][];
            /** Ledger Hash */
            ledger_hash?: string | null;
            /** Plan Hash */
            plan_hash?: string | null;
            state: components["schemas"]["PlanState"];
        };
        /**
         * ProxmoxApplyAuthorizationOut
         * @description Whether apply is authorized for the plan the range currently has.
         */
        ProxmoxApplyAuthorizationOut: {
            approval?: components["schemas"]["ApprovalOut"] | null;
            authorization?: components["schemas"]["ApprovalOut"] | null;
            /** Blocked Reason */
            blocked_reason?: string | null;
            /** Plan Hash */
            plan_hash?: string | null;
            plan_state: components["schemas"]["PlanState"];
            state: components["schemas"]["AuthorizationState"];
        };
        /**
         * ProxmoxApplyAuthorizationRequest
         * @description Authorize apply of an already-approved plan. Deliberately carries ``plan_hash`` ONLY.
         */
        ProxmoxApplyAuthorizationRequest: {
            /** Plan Hash */
            plan_hash: string;
        };
        /**
         * ProxmoxCommandOut
         * @description One durable command record, as it was accepted.
         */
        ProxmoxCommandOut: {
            /** Accepted Version */
            accepted_version: number;
            /**
             * At
             * Format: date-time
             */
            at: string;
            /** Cluster Fingerprint */
            cluster_fingerprint: string;
            /**
             * Deduplicated
             * @default false
             */
            deduplicated: boolean;
            /**
             * Enqueued
             * @default false
             */
            enqueued: boolean;
            /** Idempotency Key */
            idempotency_key: string;
            not_enqueued_reason?: components["schemas"]["RefusalCode"] | null;
            /** Operation Generation */
            operation_generation: number;
            /** Operation Id */
            operation_id?: string | null;
            operation_kind: components["schemas"]["CommandKind"];
            /**
             * Organization Id
             * Format: uuid
             */
            organization_id: string;
            /**
             * Range Id
             * Format: uuid
             */
            range_id: string;
            /** Requested By */
            requested_by?: string | null;
            /** Sequence */
            sequence: number;
            /** Subject Hash */
            subject_hash?: string | null;
            /** Target Id */
            target_id: string;
        };
        /**
         * ProxmoxCompileTopologyRequest
         * @description Recompile the topology from the observation of record.
         *
         *     Deliberately carries NO hash: this is the act that produces one. Requiring the caller to name
         *     the hash they expect would make it impossible to refresh after the observation changed, which
         *     is the only case in which refreshing is interesting.
         */
        ProxmoxCompileTopologyRequest: {
            /** Cluster Fingerprint */
            cluster_fingerprint: string;
            /** Expected Version */
            expected_version: number;
            /** Idempotency Key */
            idempotency_key: string;
            /** Operation Generation */
            operation_generation: number;
            /** Target Id */
            target_id: string;
        };
        /**
         * ProxmoxDestroyAuthorizationOut
         * @description Whether destroy is authorized. Never satisfied by an apply authorization.
         */
        ProxmoxDestroyAuthorizationOut: {
            approval?: components["schemas"]["ApprovalOut"] | null;
            authorization?: components["schemas"]["ApprovalOut"] | null;
            /** Blocked Reason */
            blocked_reason?: string | null;
            /** Destroy Hash */
            destroy_hash?: string | null;
            destroy_plan_state: components["schemas"]["PlanState"];
            state: components["schemas"]["AuthorizationState"];
        };
        /**
         * ProxmoxDestroyAuthorizationRequest
         * @description Authorize destroy of an already-approved destroy plan. ``destroy_hash`` ONLY.
         */
        ProxmoxDestroyAuthorizationRequest: {
            /** Destroy Hash */
            destroy_hash: string;
        };
        /**
         * ProxmoxDestroyExecutionRequest
         * @description Request execution of the authorized destroy. ``destroy_hash`` ONLY.
         */
        ProxmoxDestroyExecutionRequest: {
            /** Cluster Fingerprint */
            cluster_fingerprint: string;
            /** Destroy Hash */
            destroy_hash: string;
            /** Expected Version */
            expected_version: number;
            /** Idempotency Key */
            idempotency_key: string;
            /** Operation Generation */
            operation_generation: number;
            /** Release Digest */
            release_digest: string;
            /** Target Id */
            target_id: string;
            /** Worker Installation Id */
            worker_installation_id: string;
        };
        /**
         * ProxmoxDestroyPlanApprovalRequest
         * @description Approve the exact destroy plan. Deliberately carries ``destroy_hash`` ONLY.
         */
        ProxmoxDestroyPlanApprovalRequest: {
            /** Destroy Hash */
            destroy_hash: string;
        };
        /**
         * ProxmoxDestroyPlanGenerateRequest
         * @description Materialise the deletion scope. ``destroy_hash`` ONLY.
         *
         *     An apply body cannot validate here: ``plan_hash`` is rejected as an unknown field and the
         *     required ``destroy_hash`` is absent.
         */
        ProxmoxDestroyPlanGenerateRequest: {
            /** Cluster Fingerprint */
            cluster_fingerprint: string;
            /** Destroy Hash */
            destroy_hash: string;
            /** Expected Version */
            expected_version: number;
            /** Idempotency Key */
            idempotency_key: string;
            /** Operation Generation */
            operation_generation: number;
            /** Target Id */
            target_id: string;
        };
        /**
         * ProxmoxDestroyPlanOut
         * @description The destroy plan and its own hash — a deletion scope, not the creation plan reversed.
         */
        ProxmoxDestroyPlanOut: {
            approval?: components["schemas"]["ApprovalOut"] | null;
            /** Approved Hash Is Current */
            approved_hash_is_current?: boolean | null;
            /** Blocked Reasons */
            blocked_reasons?: components["schemas"]["BlockedReasonOut"][];
            /** Deletion Set */
            deletion_set?: {
                [key: string]: unknown;
            }[] | null;
            /** Deletion Set Size */
            deletion_set_size?: number | null;
            /** Destroy Hash */
            destroy_hash?: string | null;
            state: components["schemas"]["PlanState"];
        };
        /**
         * ProxmoxEvidenceOut
         * @description Every evidence reference this range has, in one place.
         *
         *     References only. The verification report, the residue proof and the discovery snapshot are each
         *     reachable through their own endpoints; this says WHICH of them exist and what identifies them,
         *     so an operator assembling a record for an event knows what they have before they fetch it.
         */
        ProxmoxEvidenceOut: {
            /**
             * Range Id
             * Format: uuid
             */
            range_id: string;
            /** References */
            references: components["schemas"]["EvidenceReferenceOut"][];
            /** Teardown Evidence Ids */
            teardown_evidence_ids?: string[];
        };
        /**
         * ProxmoxExecutionRequest
         * @description Request execution of the authorized apply. ``plan_hash`` ONLY — never ``destroy_hash``.
         */
        ProxmoxExecutionRequest: {
            /** Cluster Fingerprint */
            cluster_fingerprint: string;
            /** Expected Version */
            expected_version: number;
            /** Idempotency Key */
            idempotency_key: string;
            /** Operation Generation */
            operation_generation: number;
            /** Plan Hash */
            plan_hash: string;
            /** Release Digest */
            release_digest: string;
            /** Target Id */
            target_id: string;
            /** Worker Installation Id */
            worker_installation_id: string;
        };
        /**
         * ProxmoxGeneratePlanRequest
         * @description Materialise the compiled plan as a durable record. Carries ``plan_hash`` ONLY.
         */
        ProxmoxGeneratePlanRequest: {
            /** Cluster Fingerprint */
            cluster_fingerprint: string;
            /** Expected Version */
            expected_version: number;
            /** Idempotency Key */
            idempotency_key: string;
            /** Operation Generation */
            operation_generation: number;
            /** Plan Hash */
            plan_hash: string;
            /** Target Id */
            target_id: string;
        };
        /**
         * ProxmoxGuestAddressOut
         * @description A guest's addresses, kept strictly separate — THREE concepts, never one.
         *
         *     This repository has already paid for conflating them. A worker probed the address the range
         *     had *published* — a loopback address, from inside a container where the port was not — so
         *     readiness could never be observed and the range hung. #103 fixed it by separating the two, and
         *     :class:`~secp_api.range_providers.proxmox_model.GuestAddress` refuses to fall back from one to
         *     the other for the same reason: a readiness check that quietly probes the published address
         *     proves the address was published, not that the guest is reachable.
         *
         *     The wire has to keep them apart too, or a client re-derives the same wrong conclusion:
         *
         *     ``published_address``  what a scoreboard or a participant is told to use. NOT NECESSARILY
         *                            REACHABLE from the worker.
         *     ``probe_address``      what readiness verification actually connects to. ``None`` means no
         *                            distinct probe address was assigned — never "use the published one".
         *     ``observed_address``   what the provider actually reported for this guest after apply.
         *                            ``None`` means not observed, which is not an address and not a failure.
         */
        ProxmoxGuestAddressOut: {
            /**
             * Observed
             * @default false
             */
            observed: boolean;
            /** Observed Address */
            observed_address?: string | null;
            /** Probe Address */
            probe_address?: string | null;
            /** Probe Is Distinct */
            probe_is_distinct: boolean;
            /** Published Address */
            published_address: string;
        };
        /**
         * ProxmoxGuestBootstrapOut
         * @description One guest's bootstrap contract — the WORKER's view, kept apart from the topology's.
         *
         *     ``probe_address`` here is what the worker connects to in order to check this guest came up. It
         *     is NOT the topology's ``published_address`` (what a participant is told to use) and NOT the
         *     topology's own ``probe_address``, and there is no fallback between any of them. A readiness
         *     check that quietly probes the published address proves the address was published.
         *
         *     ``report_address`` is a fourth thing again: where the guest reports its own bootstrap result.
         */
        ProxmoxGuestBootstrapOut: {
            attestation_ref: components["schemas"]["MaterialRefOut"];
            /** Deadline Seconds */
            deadline_seconds: number;
            /** Guest Ref */
            guest_ref: string;
            /** Image Digest */
            image_digest: string;
            /**
             * Observed
             * @default false
             */
            observed: boolean;
            /** Observed Address */
            observed_address?: string | null;
            /** Operations */
            operations?: components["schemas"]["BootstrapOperationOut"][];
            /** Probe Address */
            probe_address?: string | null;
            /** Probe Port */
            probe_port?: number | null;
            /** Report Address */
            report_address: string;
            /** Report Port */
            report_port: number;
            /** Team Ref */
            team_ref: string;
            /** Vmid */
            vmid: number;
            /** Workload Key */
            workload_key: string;
            /** Workload Version */
            workload_version: string;
        };
        /**
         * ProxmoxGuestOut
         * @description One planned guest, typed — so the contract carries it rather than an opaque blob.
         */
        ProxmoxGuestOut: {
            address: components["schemas"]["ProxmoxGuestAddressOut"];
            /** Generation */
            generation?: number | null;
            /** Guest Ref */
            guest_ref: string;
            /** Kind */
            kind: string;
            /** Mac Addresses */
            mac_addresses?: string[];
            /** Name */
            name: string;
            /** Node Name */
            node_name?: string | null;
            /** Operation Generation */
            operation_generation?: number | null;
            /** Team Ref */
            team_ref?: string | null;
            /** Template Ref */
            template_ref?: string | null;
            /** Vmid */
            vmid?: number | null;
        };
        /**
         * ProxmoxLifecycleOut
         * @description One request that answers "where is this range in the Proxmox lifecycle".
         *
         *     A convenience over the individual surfaces, for a client that would otherwise open eight
         *     connections to render one page. Every field is the same value the dedicated endpoint returns.
         */
        ProxmoxLifecycleOut: {
            apply_authorization: components["schemas"]["AuthorizationState"];
            /** Blocked Reasons */
            blocked_reasons?: components["schemas"]["BlockedReasonOut"][];
            destroy_authorization: components["schemas"]["AuthorizationState"];
            /** Destroy Hash */
            destroy_hash?: string | null;
            /** Isolation Holds */
            isolation_holds?: boolean | null;
            observation: components["schemas"]["ProxmoxObservationOut"];
            /** Plan Hash */
            plan_hash?: string | null;
            plan_state: components["schemas"]["PlanState"];
            /** Provider */
            provider: string;
            /**
             * Range Id
             * Format: uuid
             */
            range_id: string;
            /** Range State */
            range_state: string;
            /** Readiness Satisfied */
            readiness_satisfied?: boolean | null;
            reset_dispositions: components["schemas"]["RecordedStageState"];
            residue: components["schemas"]["RecordedStageState"];
            verification: components["schemas"]["RecordedStageState"];
        };
        /**
         * ProxmoxObservationOut
         * @description The discovery snapshot this range's plan compiles against, and how much it can be trusted.
         *
         *     ``freshness`` is ``absent`` when the worker has recorded no observation — which is not an error
         *     and not an empty cluster, but the reason the plan below it is ``blocked``.
         */
        ProxmoxObservationOut: {
            /** Age Seconds */
            age_seconds?: number | null;
            /** Cluster Fingerprint */
            cluster_fingerprint?: string | null;
            /** Cluster Name */
            cluster_name?: string | null;
            /** Firewall Supported */
            firewall_supported?: boolean | null;
            freshness: components["schemas"]["ObservationFreshness"];
            /** Freshness Bound Seconds */
            freshness_bound_seconds: number;
            /** Management Bridges */
            management_bridges?: string[] | null;
            /** Management Cidrs */
            management_cidrs?: string[] | null;
            /** Observed At */
            observed_at?: string | null;
            /** Online Node Count */
            online_node_count?: number | null;
            /** Sdn Supported */
            sdn_supported?: boolean | null;
            /** Snapshot Evidence Hash */
            snapshot_evidence_hash?: string | null;
            /** Snapshot Id */
            snapshot_id?: string | null;
            /** Target Id */
            target_id?: string | null;
            /** Unobserved Fields */
            unobserved_fields?: string[];
        };
        /**
         * ProxmoxOwnershipOut
         * @description How this range's objects are stamped and classified.
         */
        ProxmoxOwnershipOut: {
            /** Blocked Reasons */
            blocked_reasons?: components["schemas"]["BlockedReasonOut"][];
            ownership?: components["schemas"]["OwnershipClassOut"] | null;
            state: components["schemas"]["PlanState"];
        };
        /**
         * ProxmoxPlanApprovalRequest
         * @description Approve the exact compiled plan. ``plan_hash`` is required and is compared, never trusted.
         */
        ProxmoxPlanApprovalRequest: {
            /** Plan Hash */
            plan_hash: string;
        };
        /**
         * ProxmoxPlanOut
         * @description The plan document, its hash, and whether it has been approved.
         *
         *     ``document_version`` is ``secp-proxmox/desired-state-document/v1`` — the DESIRED STATE this API
         *     compiled. It is NOT the worker's OpenTofu plan document
         *     (``secp-proxmox/plan-document/v1``), which describes what ``tofu plan`` computed against real
         *     remote state and is produced only inside the privileged worker.
         */
        ProxmoxPlanOut: {
            approval?: components["schemas"]["ApprovalOut"] | null;
            /** Approved Hash Is Current */
            approved_hash_is_current?: boolean | null;
            /** Blocked Reason */
            blocked_reason?: string | null;
            /** Blocked Reasons */
            blocked_reasons?: components["schemas"]["BlockedReasonOut"][];
            /** Document */
            document?: {
                [key: string]: unknown;
            } | null;
            /** Document Version */
            document_version: string;
            /** Isolation */
            isolation?: components["schemas"]["IsolationFindingOut"][] | null;
            /** Isolation Holds */
            isolation_holds?: boolean | null;
            /** Plan Hash */
            plan_hash?: string | null;
            state: components["schemas"]["PlanState"];
            /** Unguardable Flag Values */
            unguardable_flag_values?: string[] | null;
        };
        /**
         * ProxmoxReadinessOut
         * @description Whether the PLAN would constitute a runnable two-team competition.
         *
         *     A property of a document already in hand, and never a statement about a deployed range. Passing
         *     every requirement here means the plan is worth applying and says nothing about what is running.
         */
        ProxmoxReadinessOut: {
            /** Blocked Reasons */
            blocked_reasons?: components["schemas"]["BlockedReasonOut"][];
            /** Challenge Keys */
            challenge_keys?: string[] | null;
            /** Findings */
            findings?: components["schemas"]["ReadinessFindingOut"][] | null;
            /** Plan Hash */
            plan_hash?: string | null;
            /** Satisfied */
            satisfied?: boolean | null;
            /** Scoring Endpoints */
            scoring_endpoints?: {
                [key: string]: unknown;
            }[] | null;
            state: components["schemas"]["PlanState"];
        };
        /**
         * ProxmoxReconciliationOut
         * @description Whether reconciliation was asked for, and whether anything has answered.
         *
         *     TWO independent facts, and conflating them is the failure this shape exists to prevent. A
         *     request being recorded says an operator asked; it says nothing about a worker having looked.
         *     ``state`` is the OBSERVATION and stays ``undetermined`` until a worker records one.
         */
        ProxmoxReconciliationOut: {
            /** Detail */
            detail?: string | null;
            /**
             * Enqueued
             * @default false
             */
            enqueued: boolean;
            /** Findings */
            findings?: {
                [key: string]: unknown;
            }[] | null;
            /** Not Enqueued Reason */
            not_enqueued_reason?: string | null;
            /** Observed At */
            observed_at?: string | null;
            /** Requested */
            requested: boolean;
            /** Requested At */
            requested_at?: string | null;
            /** Requested By */
            requested_by?: string | null;
            state: components["schemas"]["RecordedStageState"];
        };
        /**
         * ProxmoxReconciliationRequest
         * @description Request reconciliation of the deployed range against its desired state.
         *
         *     Carries no hash: reconciliation compares what EXISTS against what the current plan describes,
         *     so pinning it to a document the operator read would be pinning the wrong side of the comparison.
         */
        ProxmoxReconciliationRequest: {
            /** Cluster Fingerprint */
            cluster_fingerprint: string;
            /** Expected Version */
            expected_version: number;
            /** Idempotency Key */
            idempotency_key: string;
            /** Operation Generation */
            operation_generation: number;
            /** Target Id */
            target_id: string;
        };
        /**
         * ProxmoxResetAuthorizationOut
         * @description Whether a reset is authorized. Never satisfied by an apply or a destroy authorization.
         *
         *     ``reset_scope`` is published because that is what is being approved: the exact guests that will
         *     be DESTROYED and rebuilt. Approving a reset without seeing them would be approving a deletion
         *     sight unseen.
         */
        ProxmoxResetAuthorizationOut: {
            approval?: components["schemas"]["ApprovalOut"] | null;
            authorization?: components["schemas"]["ApprovalOut"] | null;
            /** Blocked Reason */
            blocked_reason?: string | null;
            /** Preserved Subjects */
            preserved_subjects?: string[];
            /** Reset Hash */
            reset_hash?: string | null;
            reset_plan_state: components["schemas"]["PlanState"];
            /** Reset Scope */
            reset_scope?: components["schemas"]["ProxmoxResetScopeEntryOut"][] | null;
            /** Reset Scope Size */
            reset_scope_size?: number | null;
            state: components["schemas"]["AuthorizationState"];
        };
        /**
         * ProxmoxResetAuthorizationRequest
         * @description Authorize a reset of an already-approved reset scope. ``reset_hash`` ONLY.
         */
        ProxmoxResetAuthorizationRequest: {
            /** Reset Hash */
            reset_hash: string;
        };
        /**
         * ProxmoxResetDispositionsOut
         * @description What a reset did to each guest, as the worker observed it.
         *
         *     ``state`` is ``undetermined`` when no reset has been recorded — distinct from a reset that ran
         *     and reported every guest as ``recovery_required``.
         */
        ProxmoxResetDispositionsOut: {
            /** Detail */
            detail?: string | null;
            /** Dispositions */
            dispositions?: {
                [key: string]: unknown;
            }[] | null;
            /** Observed At */
            observed_at?: string | null;
            state: components["schemas"]["RecordedStageState"];
        };
        /**
         * ProxmoxResetGuestOut
         * @description What a reset WOULD do to one guest.
         */
        ProxmoxResetGuestOut: {
            /** Guest Ref */
            guest_ref: string;
            /** Intended Action */
            intended_action: string;
            /** Name */
            name: string;
            /** Node Name */
            node_name?: string | null;
            /** Team Ref */
            team_ref?: string | null;
            /** Vmid */
            vmid: number;
        };
        /**
         * ProxmoxResetPlanApprovalRequest
         * @description Approve the exact reset scope. Deliberately carries ``reset_hash`` ONLY.
         *
         *     A reset DESTROYS every guest in the range and rebuilds it, so it is approved by naming the
         *     guests that will be destroyed — not by naming a creation plan. The field, the hash domain and
         *     the required permission all differ from the apply family's, so an apply body cannot be posted
         *     here and be accepted.
         */
        ProxmoxResetPlanApprovalRequest: {
            /** Reset Hash */
            reset_hash: string;
        };
        /**
         * ProxmoxResetPlanOut
         * @description What a reset would do — NOT what one did.
         *
         *     Deliberately a different endpoint and a different shape from
         *     ``/proxmox/reset-dispositions``, which reports what the worker OBSERVED a reset doing. A plan
         *     and an observation are different claims and the moment they share a surface a client starts
         *     reading one as the other.
         */
        ProxmoxResetPlanOut: {
            /** Blocked Reasons */
            blocked_reasons?: components["schemas"]["BlockedReasonOut"][];
            /** Guests */
            guests?: components["schemas"]["ProxmoxResetGuestOut"][] | null;
            last_observed: components["schemas"]["RecordedStageState"];
            /** Plan Hash */
            plan_hash?: string | null;
            state: components["schemas"]["PlanState"];
        };
        /**
         * ProxmoxResetRequest
         * @description Request a reset of the authorized reset scope. ``reset_hash`` ONLY.
         *
         *     Not ``plan_hash``. A reset DESTROYS every guest in the range and rebuilds it, so it is
         *     authorized by naming the guests that will be destroyed — a third hash domain, distinct from
         *     both the creation plan and the destroy deletion set (a reset preserves the whole network).
         */
        ProxmoxResetRequest: {
            /** Cluster Fingerprint */
            cluster_fingerprint: string;
            /** Expected Version */
            expected_version: number;
            /** Idempotency Key */
            idempotency_key: string;
            /** Operation Generation */
            operation_generation: number;
            /** Release Digest */
            release_digest: string;
            /** Reset Hash */
            reset_hash: string;
            /** Target Id */
            target_id: string;
            /** Worker Installation Id */
            worker_installation_id: string;
        };
        /**
         * ProxmoxResetScopeEntryOut
         * @description One guest a reset would DESTROY and rebuild.
         *
         *     ``template_ref`` is carried because a reset rebuilds FROM it: if the reviewed base image
         *     changed, the guest that comes back is not the guest that was approved, and an operator
         *     approving the reset should be able to see which image each guest returns from.
         */
        ProxmoxResetScopeEntryOut: {
            /** Kind */
            kind: string;
            /** Name */
            name?: string | null;
            /** Node */
            node?: string | null;
            /** Ref */
            ref?: string | null;
            /** Template Ref */
            template_ref?: string | null;
            /** Vmid */
            vmid?: number | null;
        };
        /**
         * ProxmoxResidueOut
         * @description The zero-residue proof: what a teardown actually PROVED absent.
         *
         *     ``unproven`` is a first-class verdict here and is never folded into ``clean``. A probe that
         *     could not run leaves the resource unproven, and a destroy with any unproven resource has not
         *     proved zero residue however many others it removed.
         */
        ProxmoxResidueOut: {
            /** Expected Count */
            expected_count?: number | null;
            /** Observed At */
            observed_at?: string | null;
            /** Probe Reachable */
            probe_reachable?: boolean | null;
            /** Reason */
            reason?: string | null;
            /** Removed Confirmed */
            removed_confirmed?: number | null;
            /** Resources */
            resources?: {
                [key: string]: unknown;
            }[] | null;
            state: components["schemas"]["RecordedStageState"];
            /** Still Present */
            still_present?: number | null;
            /** Uncovered Classes */
            uncovered_classes?: string[] | null;
            /** Unproven Count */
            unproven_count?: number | null;
            /** Verdict */
            verdict?: string | null;
        };
        /**
         * ProxmoxSubmitPlanRequest
         * @description Submit an exact generated plan for review. APPROVES NOTHING. ``plan_hash`` ONLY.
         */
        ProxmoxSubmitPlanRequest: {
            /** Cluster Fingerprint */
            cluster_fingerprint: string;
            /** Expected Version */
            expected_version: number;
            /** Idempotency Key */
            idempotency_key: string;
            /** Operation Generation */
            operation_generation: number;
            /** Plan Hash */
            plan_hash: string;
            /** Target Id */
            target_id: string;
        };
        /**
         * ProxmoxTopologyOut
         * @description The compiled desired state: what would exist if this plan were applied exactly.
         */
        ProxmoxTopologyOut: {
            /** Blocked Reason */
            blocked_reason?: string | null;
            /** Blocked Reasons */
            blocked_reasons?: components["schemas"]["BlockedReasonOut"][];
            /** Guest Count */
            guest_count?: number | null;
            /** Guests */
            guests?: components["schemas"]["ProxmoxGuestOut"][] | null;
            observation: components["schemas"]["ProxmoxObservationOut"];
            /** Plan Hash */
            plan_hash?: string | null;
            state: components["schemas"]["PlanState"];
            /** Team Refs */
            team_refs?: string[] | null;
            /** Topology */
            topology?: {
                [key: string]: unknown;
            } | null;
            /** Vnet Count */
            vnet_count?: number | null;
        };
        /**
         * ProxmoxVerificationOut
         * @description What was OBSERVED after an apply — infrastructure and isolation reported separately.
         *
         *     They are separate because they fail for different reasons and mean different things: every VM
         *     can exist, be running and have the right disks while the firewall lets one team reach another.
         *     Reporting a single verdict would let a passing infrastructure check mask an isolation
         *     violation, so ``infrastructure`` and ``isolation`` each carry their own outcome and neither is
         *     derived from the other.
         *
         *     ``state`` is ``undetermined`` when no verification has been recorded. That is not a pass.
         */
        ProxmoxVerificationOut: {
            /** Detail */
            detail?: string | null;
            /** Infrastructure Checks */
            infrastructure_checks?: {
                [key: string]: unknown;
            }[] | null;
            /** Infrastructure Outcome */
            infrastructure_outcome?: string | null;
            /** Isolation Checks */
            isolation_checks?: {
                [key: string]: unknown;
            }[] | null;
            /** Isolation Outcome */
            isolation_outcome?: string | null;
            /** Observed At */
            observed_at?: string | null;
            state: components["schemas"]["RecordedStageState"];
        };
        /**
         * ProxmoxWorkerOut
         * @description The enrolled worker bound to this range's organization and site, and whether it may execute.
         *
         *     ``eligible_for_execution`` is DERIVED from the fields below it, in one place, so the flag and
         *     the reasons can never disagree. It is ``false`` with named blockers rather than the endpoint
         *     404ing or omitting the worker: "no worker is enrolled" is an answer an operator needs, and it is
         *     not the same answer as "a worker is enrolled but is not healthy".
         */
        ProxmoxWorkerOut: {
            /** Blockers */
            blockers?: string[];
            /** Contract Version */
            contract_version?: string | null;
            /** Controller Installation Id */
            controller_installation_id?: string | null;
            /** Deployment Site Label */
            deployment_site_label?: string | null;
            /** Eligible For Execution */
            eligible_for_execution: boolean;
            /** Enrolled */
            enrolled: boolean;
            /** Expires At */
            expires_at?: string | null;
            /** Refusal Reason */
            refusal_reason?: string | null;
            /** Release Digest */
            release_digest?: string | null;
            /** Revision */
            revision?: number | null;
            /** State */
            state?: string | null;
            /** Worker Installation Id */
            worker_installation_id?: string | null;
            /** Worker Key Id */
            worker_key_id?: string | null;
        };
        /**
         * ProxmoxWorkloadOut
         * @description The workload and bootstrap plan, and what has been observed of it.
         */
        ProxmoxWorkloadOut: {
            /** Blocked Reasons */
            blocked_reasons?: components["schemas"]["BlockedReasonOut"][];
            /** Challenge Keys */
            challenge_keys?: string[] | null;
            /** Guests */
            guests?: components["schemas"]["ProxmoxGuestBootstrapOut"][] | null;
            /** Materials */
            materials?: components["schemas"]["MaterialRefOut"][] | null;
            /** Plan Hash */
            plan_hash?: string | null;
            state: components["schemas"]["PlanState"];
            verification: components["schemas"]["RecordedStageState"];
        };
        /** QueuePreflight */
        QueuePreflight: {
            /**
             * Live Read Authorization Id
             * Format: uuid
             */
            live_read_authorization_id: string;
        };
        /** RangeComponentOut */
        RangeComponentOut: {
            /** Container Port */
            container_port?: number | null;
            /** Image */
            image: string;
            /** Key */
            key: string;
            /** Name */
            name: string;
            /**
             * Path
             * @default /
             */
            path: string;
            /**
             * Protocol
             * @default http
             */
            protocol: string;
            /** Role */
            role: string;
        };
        /** RangeCreate */
        RangeCreate: {
            /** Name */
            name?: string | null;
            /** Template Slug */
            template_slug: string;
        };
        /**
         * RangeEventLevel
         * @enum {string}
         */
        RangeEventLevel: "info" | "warning" | "error";
        /** RangeEventOut */
        RangeEventOut: {
            /** Data */
            data: {
                [key: string]: unknown;
            };
            /**
             * Id
             * Format: uuid
             */
            id: string;
            /** Kind */
            kind: string;
            level: components["schemas"]["RangeEventLevel"];
            /** Message */
            message: string;
            /**
             * Occurred At
             * Format: date-time
             */
            occurred_at: string;
            /**
             * Range Id
             * Format: uuid
             */
            range_id: string;
            /** Sequence */
            sequence: number;
        };
        /**
         * RangeOperationAbandonIn
         * @description Body for ``POST /range-operations/{id}/abandon``.
         *
         *     ``force`` is the operator asserting they have checked that nothing is executing the operation.
         *     Without it the endpoint refuses while the lease is still live, because abandoning a running
         *     operation puts a second writer on the range.
         */
        RangeOperationAbandonIn: {
            /**
             * Force
             * @default false
             */
            force: boolean;
        };
        /**
         * RangeOperationKind
         * @enum {string}
         */
        RangeOperationKind: "deploy" | "reset" | "destroy";
        /** RangeOperationOut */
        RangeOperationOut: {
            /** Completed Steps */
            completed_steps: number;
            /** Failure Code */
            failure_code?: string | null;
            /** Failure Message */
            failure_message?: string | null;
            /** Finished At */
            finished_at?: string | null;
            /**
             * Id
             * Format: uuid
             */
            id: string;
            kind: components["schemas"]["RangeOperationKind"];
            /** Lease Expires At */
            lease_expires_at?: string | null;
            /** Percent */
            percent: number;
            /** Phase */
            phase?: string | null;
            /**
             * Range Id
             * Format: uuid
             */
            range_id: string;
            /**
             * Stale
             * @default false
             */
            stale: boolean;
            /** Stale Reason */
            stale_reason?: string | null;
            /**
             * Started At
             * Format: date-time
             */
            started_at: string;
            status: components["schemas"]["RangeOperationStatus"];
            /** Steps */
            steps: components["schemas"]["RangeOperationStepOut"][];
            /** Total Steps */
            total_steps: number;
        };
        /**
         * RangeOperationStatus
         * @enum {string}
         */
        RangeOperationStatus: "pending" | "running" | "succeeded" | "failed" | "unproven";
        /** RangeOperationStepOut */
        RangeOperationStepOut: {
            /** At */
            at?: string | null;
            /** Detail */
            detail?: string | null;
            /** Key */
            key: string;
            /** Label */
            label: string;
            /** Status */
            status: string;
        };
        /** RangeOperationSummaryOut */
        RangeOperationSummaryOut: {
            /** Completed Steps */
            completed_steps: number;
            /**
             * Id
             * Format: uuid
             */
            id: string;
            kind: components["schemas"]["RangeOperationKind"];
            /** Percent */
            percent: number;
            /** Phase */
            phase?: string | null;
            /**
             * Stale
             * @default false
             */
            stale: boolean;
            status: components["schemas"]["RangeOperationStatus"];
            /** Total Steps */
            total_steps: number;
        };
        /** RangeOut */
        RangeOut: {
            /** Access */
            access?: components["schemas"]["AccessTargetOut"][];
            /** Competition Id */
            competition_id?: string | null;
            /**
             * Created At
             * Format: date-time
             */
            created_at: string;
            current_operation?: components["schemas"]["RangeOperationSummaryOut"] | null;
            /** Deployed At */
            deployed_at?: string | null;
            /** Destroyed At */
            destroyed_at?: string | null;
            /**
             * Id
             * Format: uuid
             */
            id: string;
            /** Name */
            name: string;
            /** Provider */
            provider: string;
            residue_verdict?: components["schemas"]["ResidueVerdict"] | null;
            state: components["schemas"]["RangeState"];
            /** State Reason */
            state_reason?: string | null;
            /** Template Name */
            template_name: string;
            /** Template Slug */
            template_slug: string;
            /**
             * Updated At
             * Format: date-time
             */
            updated_at: string;
        };
        /**
         * RangeResourceKind
         * @enum {string}
         */
        RangeResourceKind: "network" | "container" | "virtual_machine" | "lxc_container" | "sdn_zone" | "vnet" | "subnet" | "firewall_group" | "ip_set" | "egress_gateway";
        /** RangeResourceOut */
        RangeResourceOut: {
            /** Component Key */
            component_key?: string | null;
            /**
             * Created At
             * Format: date-time
             */
            created_at: string;
            /** Detail */
            detail: {
                [key: string]: unknown;
            };
            /** External Id */
            external_id?: string | null;
            /** Host Port */
            host_port?: number | null;
            /**
             * Id
             * Format: uuid
             */
            id: string;
            /** Image */
            image?: string | null;
            /** Image Digest */
            image_digest?: string | null;
            kind: components["schemas"]["RangeResourceKind"];
            /** Name */
            name: string;
            /** Provider */
            provider: string;
            /** Removed At */
            removed_at?: string | null;
            state: components["schemas"]["RangeResourceState"];
        };
        /**
         * RangeResourceState
         * @enum {string}
         */
        RangeResourceState: "pending" | "creating" | "created" | "verified" | "removing" | "removed" | "unproven" | "failed";
        /**
         * RangeState
         * @description The authoritative range-instance lifecycle.
         *
         *     ``recovery_required`` is NOT ``failed``. ``failed`` means an operation was observed to go
         *     wrong; ``recovery_required`` means resources may or may not still exist and only a human
         *     looking at the provider can settle it.
         * @enum {string}
         */
        RangeState: "draft" | "deploying" | "ready" | "active" | "resetting" | "recovery_required" | "failed" | "destroying" | "destroyed";
        /** RangeTemplateOut */
        RangeTemplateOut: {
            /** Challenge Count */
            challenge_count: number;
            /** Components */
            components: components["schemas"]["RangeComponentOut"][];
            /** Description */
            description: string;
            /** Difficulty */
            difficulty: string;
            /** Estimated Deploy Seconds */
            estimated_deploy_seconds: number;
            /** Name */
            name: string;
            /** Provider */
            provider: string;
            /** Slug */
            slug: string;
            /** Summary */
            summary: string;
            /** Total Points */
            total_points: number;
            /** Warning */
            warning: string;
        };
        /** ReadinessFacetOut */
        ReadinessFacetOut: {
            /** Facet */
            facet: string;
            /** Status */
            status: string;
        };
        /**
         * ReadinessFindingOut
         * @description One competition-readiness requirement, met or not, checked against the plan.
         */
        ReadinessFindingOut: {
            /** Detail */
            detail: string;
            /** Met */
            met: boolean;
            /** Requirement */
            requirement: string;
        };
        /**
         * ReadinessRequestAccepted
         * @description The API durably ENQUEUED the operation. It executed nothing and contacted nothing.
         */
        ReadinessRequestAccepted: {
            /** Operation Kind */
            operation_kind: string;
            /** Provisioning Manifest Id */
            provisioning_manifest_id: string;
            /**
             * Status
             * @default queued
             */
            status: string;
        };
        /** ReadonlyPreflightOut */
        ReadonlyPreflightOut: {
            /** Authorization Version */
            authorization_version: number;
            /** Completed At */
            completed_at: string | null;
            /**
             * Created At
             * Format: date-time
             */
            created_at: string;
            /**
             * Execution Target Id
             * Format: uuid
             */
            execution_target_id: string;
            /**
             * Id
             * Format: uuid
             */
            id: string;
            /**
             * Live Read Authorization Id
             * Format: uuid
             */
            live_read_authorization_id: string;
            /**
             * Onboarding Id
             * Format: uuid
             */
            onboarding_id: string;
            /**
             * Organization Id
             * Format: uuid
             */
            organization_id: string;
            /** Outcome Code */
            outcome_code: string | null;
            /** Readiness Facts */
            readiness_facts: {
                [key: string]: unknown;
            } | null;
            /** Revision */
            revision: number;
            /** Status */
            status: string;
        };
        /** RecordDossierEvidenceIn */
        RecordDossierEvidenceIn: {
            /** Issuer */
            issuer: string;
            kind: components["schemas"]["ActivationDossierEvidenceKind"];
            /** Proof Id */
            proof_id: string;
            status: components["schemas"]["ActivationDossierEvidenceStatus"];
        };
        /**
         * RecordedStageState
         * @description Whether a worker-recorded stage (verification, reset, residue) has an answer yet.
         * @enum {string}
         */
        RecordedStageState: "recorded" | "undetermined";
        /** RecordPlanSecretEvidenceIn */
        RecordPlanSecretEvidenceIn: {
            /** Issuer */
            issuer: string;
            kind: components["schemas"]["PlanSecretEvidenceKind"];
            /** Proof Id */
            proof_id: string;
            status: components["schemas"]["PlanSecretEvidenceStatus"];
        };
        /** RecordResolverActivationEvidence */
        RecordResolverActivationEvidence: {
            /** Issuer */
            issuer: string;
            kind: components["schemas"]["ResolverActivationEvidenceKind"];
            /** Proof Id */
            proof_id: string;
            status: components["schemas"]["ResolverActivationEvidenceStatus"];
        };
        /**
         * RefusalCode
         * @description Stable, machine-readable reasons a command is refused.
         *
         *     A client branches on these; the message beside them is for a human and may change. Every member
         *     must have a test that provokes exactly it —
         *     ``test_proxmox_operator_commands.py::test_every_refusal_code_has_a_test_that_provokes_it``
         *     enumerates this enum FROM THE LIVE MODULE and fails on any member no test covers. It is
         *     enumerated rather than listed because a hand-maintained list written by the same author cannot
         *     notice a code that author forgot.
         * @enum {string}
         */
        RefusalCode: "range_not_proxmox" | "target_mismatch" | "cluster_fingerprint_mismatch" | "ownership_scope_mismatch" | "plan_blocked" | "observation_absent" | "observation_stale" | "plan_not_generated" | "plan_not_submitted" | "plan_not_approved" | "apply_not_authorized" | "reset_plan_not_approved" | "reset_not_authorized" | "destroy_plan_not_generated" | "destroy_plan_not_approved" | "destroy_not_authorized" | "plan_identity_mismatch" | "destroy_plan_identity_mismatch" | "reset_plan_identity_mismatch" | "desired_state_changed" | "allocation_changed" | "version_conflict" | "operation_generation_mismatch" | "idempotency_key_reused" | "operation_in_flight" | "lifecycle_state_invalid" | "worker_mismatch" | "release_mismatch" | "worker_not_healthy" | "reconciliation_consumer_unavailable";
        /** RemoteStateReadinessOut */
        RemoteStateReadinessOut: {
            /** Adapter Contract Version */
            adapter_contract_version: string;
            /** Adapter Registration Id */
            adapter_registration_id: string;
            /** Backup Proof Id */
            backup_proof_id: string;
            /** Capability Class */
            capability_class: string;
            /** Collected At */
            collected_at: string;
            /** Current */
            current: boolean;
            /** Eligibility Evidence Hash */
            eligibility_evidence_hash: string;
            /** Encryption Proof Id */
            encryption_proof_id: string;
            /** Evidence Hash */
            evidence_hash: string;
            /** Execution Target Id */
            execution_target_id: string;
            /** Expired */
            expired: boolean;
            /** Expires At */
            expires_at: string;
            /** Facets */
            facets?: components["schemas"]["ReadinessFacetOut"][];
            /** Lock Proof Id */
            lock_proof_id: string;
            /** Operation Fingerprint */
            operation_fingerprint: string;
            /** Operation Kind */
            operation_kind: string;
            /** Outcome */
            outcome: string;
            /** Provisioning Manifest Id */
            provisioning_manifest_id: string;
            /** Readiness Policy Version */
            readiness_policy_version: string;
            /** Reason Codes */
            reason_codes?: string[];
            /** Record Id */
            record_id: string;
            /** Restore Proof Id */
            restore_proof_id: string;
            /** State Backend Class */
            state_backend_class: string;
            /** State Namespace Hash */
            state_namespace_hash: string;
            /** Target Onboarding Id */
            target_onboarding_id: string;
            /** Toolchain Attestation Hash */
            toolchain_attestation_hash: string;
            /** Toolchain Attestation Id */
            toolchain_attestation_id: string;
            /** Toolchain Profile Hash */
            toolchain_profile_hash: string;
        };
        /**
         * RequirementFindingOut
         * @description One requirement for one scenario on one provider.
         */
        RequirementFindingOut: {
            /** Detail */
            detail: string;
            kind: components["schemas"]["RequirementKind"];
            /** Reason Id */
            reason_id?: string | null;
            status: components["schemas"]["RequirementStatus"];
        };
        /**
         * RequirementKind
         * @description The requirement classes the catalog reports for every scenario/provider pair.
         *
         *     Every member is reported for every pair — a requirement that does not apply to a provider is
         *     reported ``satisfied`` with a detail saying why it does not apply, rather than being omitted.
         *     An omitted requirement is indistinguishable from a requirement nobody thought about.
         * @enum {string}
         */
        RequirementKind: "source_template" | "network" | "storage" | "team_count" | "scoring" | "telemetry" | "controlled_egress";
        /**
         * RequirementStatus
         * @description Whether one requirement is met. FOUR values, and the last two are the load-bearing ones.
         *
         *     Two of these mean "not satisfied" and they are deliberately not one member, because they lead
         *     an operator to opposite actions. ``unsatisfied``/``undetermined`` mean *go and fix or check
         *     something, then this scenario can run here*. ``not_provided`` means *this substrate will never
         *     do that; deploy anyway if you do not need it*. Folding them together would either mark a
         *     perfectly deployable laptop lab as blocked, or — far worse in the other direction — mark a
         *     missing capability as an acceptable gap on a substrate where it is a hard requirement.
         * @enum {string}
         */
        RequirementStatus: "satisfied" | "unsatisfied" | "undetermined" | "not_provided";
        /** ReservationOut */
        ReservationOut: {
            /** Cidr */
            cidr: string;
            /**
             * Execution Target Id
             * Format: uuid
             */
            execution_target_id: string;
            /**
             * Id
             * Format: uuid
             */
            id: string;
            /** Status */
            status: string;
            /** Team Ref */
            team_ref: string;
        };
        /**
         * ResidueVerdict
         * @description The answer to "did we leave anything behind?".
         * @enum {string}
         */
        ResidueVerdict: "clean" | "residue" | "unproven";
        /**
         * ResolverActivationEvidenceKind
         * @description Closed set of provider-neutral, secret-free activation-evidence items (B2-4.1 / B2-2).
         *
         *     Each item is proof METADATA only — never an endpoint, backend config, vault path, reference,
         *     worker credential, token, policy, or secret. Approval requires every kind present + verified.
         * @enum {string}
         */
        ResolverActivationEvidenceKind: "isolated_staging_identity" | "worker_only_network_path" | "backend_access_policy_review" | "reference_grammar_review" | "redaction_log_audit_verification" | "transport_get_only_canonical" | "no_production_or_shared_target" | "rollback_kill_switch_drill" | "independent_adversarial_review";
        /** ResolverActivationEvidenceOut */
        ResolverActivationEvidenceOut: {
            /** Issuer */
            issuer: string;
            kind: components["schemas"]["ResolverActivationEvidenceKind"];
            /** Proof Id */
            proof_id: string;
            status: components["schemas"]["ResolverActivationEvidenceStatus"];
            /** Verified At */
            verified_at: string | null;
        };
        /**
         * ResolverActivationEvidenceStatus
         * @description Closed status of one evidence item. Only ``verified`` counts toward approval completeness.
         * @enum {string}
         */
        ResolverActivationEvidenceStatus: "pending" | "verified" | "failed";
        /** ResolverActivationOut */
        ResolverActivationOut: {
            /** Approved At */
            approved_at: string | null;
            /**
             * Authorization Expiry
             * Format: date-time
             */
            authorization_expiry: string;
            /** Authorization Version */
            authorization_version: number;
            /**
             * Created At
             * Format: date-time
             */
            created_at: string;
            /**
             * Evidence
             * @default []
             */
            evidence: components["schemas"]["ResolverActivationEvidenceOut"][];
            /** Evidence Fingerprint */
            evidence_fingerprint: string;
            /**
             * Execution Target Id
             * Format: uuid
             */
            execution_target_id: string;
            /**
             * Id
             * Format: uuid
             */
            id: string;
            /**
             * Live Read Authorization Id
             * Format: uuid
             */
            live_read_authorization_id: string;
            /** Live Read Authorization Version */
            live_read_authorization_version: number;
            /**
             * Onboarding Id
             * Format: uuid
             */
            onboarding_id: string;
            /** Operation Fingerprint */
            operation_fingerprint: string;
            /**
             * Organization Id
             * Format: uuid
             */
            organization_id: string;
            /**
             * Preflight Id
             * Format: uuid
             */
            preflight_id: string;
            /** Purpose */
            purpose: string;
            /** Resolver Adapter Contract Version */
            resolver_adapter_contract_version: string;
            /** Revision */
            revision: number;
            /** Revoked At */
            revoked_at: string | null;
            /** Status */
            status: string;
        };
        /** ResourceOut */
        ResourceOut: {
            /** Attributes */
            attributes: {
                [key: string]: unknown;
            };
            /** Display Name */
            display_name: string;
            /**
             * Id
             * Format: uuid
             */
            id: string;
            /** Parent Ref */
            parent_ref: string | null;
            /** Provider External Id */
            provider_external_id: string;
            /** Resource Type */
            resource_type: string;
            /** Status */
            status: string;
        };
        /**
         * ResultExchangeOut
         * @description The result-exchange response: the final bounded enrollment status (verified/healthy).
         */
        ResultExchangeOut: {
            enrollment: components["schemas"]["EnrollmentStatusOut"];
        };
        /**
         * ResultExchangeRequest
         * @description The worker-initiated result exchange. Carries the worker's presented public key, the bounded
         *     outcome token, the detached worker-result attestation, the bounded health-evidence structure the
         *     controller recomputes the digest from (CHECKED FACTS, never a caller boolean), and the
         *     last-observed revision. The controller rebuilds the signed claim from AUTHORITATIVE state (the
         *     result claim is never accepted from the wire); only an authenticated, fully-passing,
         *     successful-outcome result advances the enrollment to verified then healthy.
         */
        ResultExchangeRequest: {
            attestation: components["schemas"]["DetachedAttestationIn"];
            /** Expected Revision */
            expected_revision: number;
            /** Health Evidence */
            health_evidence: {
                [key: string]: boolean;
            };
            /** Outcome */
            outcome: string;
            /** Worker Public Key Hex */
            worker_public_key_hex: string;
        };
        /** RevokeDossierIn */
        RevokeDossierIn: {
            /**
             * Reason Code
             * @default operator
             */
            reason_code: string;
        };
        /**
         * RevokeEnrollment
         * @description Operator revocation. ``expected_revision`` is the revision the client last observed (from the
         *     status projection); a stale value on a live enrollment refuses a bounded conflict.
         */
        RevokeEnrollment: {
            /** Expected Revision */
            expected_revision: number;
        };
        /** RevokePlanGenerationAuthorizationIn */
        RevokePlanGenerationAuthorizationIn: {
            /**
             * Reason Code
             * @default operator
             */
            reason_code: string;
        };
        /** RevokePlanSecretAuthorizationIn */
        RevokePlanSecretAuthorizationIn: {
            /**
             * Reason Code
             * @default operator
             */
            reason_code: string;
        };
        /**
         * ScenarioOut
         * @description One lab, listed ONCE, with every provider it can run on.
         *
         *     The Web Breach Lab appears here a single time carrying two provider variants, not twice as two
         *     templates. The components and challenges are the shared catalog definitions both variants are
         *     built from, so the substrate changes and the content does not.
         */
        ScenarioOut: {
            /** Blocked Everywhere */
            blocked_everywhere: boolean;
            /** Challenge Keys */
            challenge_keys?: string[];
            /** Component Keys */
            component_keys?: string[];
            /** Key */
            key: string;
            /** Name */
            name: string;
            /** Providers */
            providers: components["schemas"]["ProviderCompatibilityOut"][];
            /** Summary */
            summary: string;
            /** Total Points */
            total_points: number;
        };
        /** ScoreboardEntryOut */
        ScoreboardEntryOut: {
            /** Last Solve At */
            last_solve_at?: string | null;
            /** Rank */
            rank: number;
            /** Score */
            score: number;
            /** Solved Challenge Ids */
            solved_challenge_ids: string[];
            /** Solved Count */
            solved_count: number;
            /**
             * Team Id
             * Format: uuid
             */
            team_id: string;
            /** Team Name */
            team_name: string;
        };
        /** ScoreboardOut */
        ScoreboardOut: {
            /**
             * Competition Id
             * Format: uuid
             */
            competition_id: string;
            /** Entries */
            entries: components["schemas"]["ScoreboardEntryOut"][];
            /**
             * Generated At
             * Format: date-time
             */
            generated_at: string;
            state: components["schemas"]["CompetitionState"];
            /** Total Points */
            total_points: number;
        };
        /**
         * SealedApplyNoticeOut
         * @description Reminds callers that live deployment apply remains sealed after read-only discovery.
         */
        SealedApplyNoticeOut: {
            /**
             * Live Apply Sealed
             * @default true
             */
            live_apply_sealed: boolean;
            /**
             * Message
             * @default Read-only discovery complete. Live deployment remains sealed until controlled integration enablement.
             */
            message: string;
        };
        /**
         * SignedControllerOfferOut
         * @description The internally-signed controller offer: the canonical claim + its detached attestation. The
         *     worker re-verifies it against the invitation-pinned controller key.
         */
        SignedControllerOfferOut: {
            attestation: components["schemas"]["DetachedAttestationOut"];
            /** Claim */
            claim: {
                [key: string]: string;
            };
        };
        /** SnapshotOut */
        SnapshotOut: {
            /** Completed At */
            completed_at: string | null;
            /** Error */
            error: string | null;
            /**
             * Execution Target Id
             * Format: uuid
             */
            execution_target_id: string;
            /**
             * Id
             * Format: uuid
             */
            id: string;
            /** Plugin Name */
            plugin_name: string;
            /** Plugin Version */
            plugin_version: string;
            /**
             * Requested At
             * Format: date-time
             */
            requested_at: string;
            /** Status */
            status: string;
            /** Summary */
            summary: {
                [key: string]: unknown;
            };
            /** Target Config Hash */
            target_config_hash: string;
            /** Workflow Run Id */
            workflow_run_id: string | null;
        };
        /**
         * StagingBootstrapArtifactProfile
         * @description Backend catalog of approved offline bootstrap-artifact profiles (SECP-002B-1B-9).
         *
         *     A closed server-owned enum — never a caller-supplied artifact id, path, URL, or checksum.
         *     Each value names an operator-approved, pre-staged offline artifact set resolved out of band.
         * @enum {string}
         */
        StagingBootstrapArtifactProfile: "nested_proxmox_offline_base";
        /** StagingLabApprove */
        StagingLabApprove: {
            /** Expected Plan Hash */
            expected_plan_hash: string;
        };
        /**
         * StagingLabCreate
         * @description All persisted labels are server-owned. Only a substrate UUID, controlled enums, and one
         *     optional strict-slug logical name are accepted.
         */
        StagingLabCreate: {
            /** @default nested_proxmox_offline_base */
            bootstrap_artifact_profile: components["schemas"]["StagingBootstrapArtifactProfile"];
            /**
             * Execution Target Id
             * Format: uuid
             */
            execution_target_id: string;
            /** Logical Name */
            logical_name?: string | null;
            /** @default small_lab */
            resource_class: components["schemas"]["StagingResourceClass"];
            /** @default revert_to_known_clean_checkpoint */
            rollback_policy: components["schemas"]["StagingRollbackPolicy"];
        };
        /** StagingLabOut */
        StagingLabOut: {
            /** Approved At */
            approved_at: string | null;
            /** Approved Plan Hash */
            approved_plan_hash: string;
            /** Approved Plan Version */
            approved_plan_version: number;
            /** Bootstrap Artifact Profile */
            bootstrap_artifact_profile: string;
            /**
             * Created At
             * Format: date-time
             */
            created_at: string;
            /** Decision Code */
            decision_code: string;
            /** Desired State */
            desired_state: {
                [key: string]: unknown;
            } | null;
            /** Display Name */
            display_name: string;
            /**
             * Execution Target Id
             * Format: uuid
             */
            execution_target_id: string;
            /**
             * Id
             * Format: uuid
             */
            id: string;
            /** Network Intent */
            network_intent: string;
            /**
             * Organization Id
             * Format: uuid
             */
            organization_id: string;
            /** Ownership Label */
            ownership_label: string;
            /** Plan Hash */
            plan_hash: string;
            /** Plan Version */
            plan_version: number;
            /** Profile */
            profile: string;
            /** Purpose */
            purpose: string;
            /** Resource Class */
            resource_class: string;
            /** Revision */
            revision: number;
            /** Rollback Policy */
            rollback_policy: string;
            /** Simulated Observed State */
            simulated_observed_state: {
                [key: string]: unknown;
            } | null;
            /** Status */
            status: string;
        };
        /** StagingLabWorkItemOut */
        StagingLabWorkItemOut: {
            /**
             * Created At
             * Format: date-time
             */
            created_at: string;
            /** Failure Code */
            failure_code: string | null;
            /**
             * Id
             * Format: uuid
             */
            id: string;
            /** Operation Kind */
            operation_kind: string;
            /**
             * Organization Id
             * Format: uuid
             */
            organization_id: string;
            /** Plan Hash */
            plan_hash: string;
            /** Plan Version */
            plan_version: number;
            /** Revision */
            revision: number;
            /**
             * Staging Lab Id
             * Format: uuid
             */
            staging_lab_id: string;
            /** Status */
            status: string;
        };
        /**
         * StagingResourceClass
         * @description Bounded logical resource class for a staging lab (SECP-002B-1B-9).
         *
         *     Safe, coarse logical sizes only — never raw host CPU/RAM/disk values. Real sizing against
         *     verified host headroom happens out of band; SECP stores only the chosen logical class.
         * @enum {string}
         */
        StagingResourceClass: "small_lab" | "medium_lab";
        /**
         * StagingRollbackPolicy
         * @description How a staging lab is returned to a known-clean state (SECP-002B-1B-9).
         * @enum {string}
         */
        StagingRollbackPolicy: "revert_to_known_clean_checkpoint" | "destroy_and_rebuild";
        /** SubmissionCreate */
        SubmissionCreate: {
            /**
             * Challenge Id
             * Format: uuid
             */
            challenge_id: string;
            /**
             * Team Id
             * Format: uuid
             */
            team_id: string;
            /** Value */
            value: string;
        };
        /** SubmissionOut */
        SubmissionOut: {
            /** Attempts Remaining */
            attempts_remaining: number;
            /**
             * Challenge Id
             * Format: uuid
             */
            challenge_id: string;
            /** Challenge Title */
            challenge_title: string;
            /**
             * Competition Id
             * Format: uuid
             */
            competition_id: string;
            /**
             * Id
             * Format: uuid
             */
            id: string;
            /** Points Awarded */
            points_awarded: number;
            /**
             * Submitted At
             * Format: date-time
             */
            submitted_at: string;
            /**
             * Team Id
             * Format: uuid
             */
            team_id: string;
            /** Team Name */
            team_name: string;
            verdict: components["schemas"]["SubmissionVerdict"];
        };
        /**
         * SubmissionVerdict
         * @enum {string}
         */
        SubmissionVerdict: "accepted" | "incorrect" | "duplicate" | "already_solved" | "not_open" | "attempts_exhausted";
        /**
         * SubstrateEligibilityGrantOut
         * @description SECP-B8: the result of granting a target staging-substrate eligibility (a target-admin action
         *     gated by ``staging_substrate:manage``). Non-secret; grants nothing beyond eligibility.
         */
        SubstrateEligibilityGrantOut: {
            /**
             * Execution Target Id
             * Format: uuid
             */
            execution_target_id: string;
            /**
             * Id
             * Format: uuid
             */
            id: string;
            /**
             * Organization Id
             * Format: uuid
             */
            organization_id: string;
            /** Status */
            status: string;
        };
        /** TargetCreate */
        TargetCreate: {
            /**
             * Address Spaces
             * @default []
             */
            address_spaces: components["schemas"]["AddressSpaceIn"][];
            /** Config */
            config: {
                [key: string]: unknown;
            };
            /** Display Name */
            display_name: string;
            /** Plugin Name */
            plugin_name: string;
            /** Provider Plan Secret Ref */
            provider_plan_secret_ref?: string | null;
            /**
             * Scope Policy
             * @default {}
             */
            scope_policy: {
                [key: string]: unknown;
            };
            /** Secret Ref */
            secret_ref?: string | null;
            /** State Backend Secret Ref */
            state_backend_secret_ref?: string | null;
        };
        /**
         * TargetCredentialRotate
         * @description Replace a target's GENERIC opaque credential reference through the supported rotation path.
         *
         *     ``secret_ref`` remains an opaque ``<scheme>:<locator>`` pointer — never a secret. Applying it
         *     rotates the target's ``provider_plan_read`` opaque credential binding (B1B-PR4 §2).
         */
        TargetCredentialRotate: {
            /** Secret Ref */
            secret_ref?: string | null;
        };
        /** TargetEvidenceOut */
        TargetEvidenceOut: {
            /**
             * Collected At
             * Format: date-time
             */
            collected_at: string;
            /**
             * Created At
             * Format: date-time
             */
            created_at: string;
            /** Evidence Hash */
            evidence_hash: string;
            /** Evidence Source */
            evidence_source: string;
            /**
             * Execution Target Id
             * Format: uuid
             */
            execution_target_id: string;
            /** Findings */
            findings: unknown[];
            /**
             * Id
             * Format: uuid
             */
            id: string;
            /**
             * Onboarding Id
             * Format: uuid
             */
            onboarding_id: string;
            /**
             * Organization Id
             * Format: uuid
             */
            organization_id: string;
            /** Status */
            status: string;
            /** Verification Level */
            verification_level: string;
        };
        /**
         * TargetOperationCredentialRotate
         * @description Replace one OPERATION-SPECIFIC opaque credential reference (B1B-PR5A, ADR-022).
         *
         *     ``purpose_class`` is a closed enum whose only members are ``provider_plan_read`` and
         *     ``state_backend_plan`` — apply/destroy purposes are unrepresentable. The reference remains an
         *     opaque pointer; rotating it invalidates every prior dossier/readiness/authorization that folded
         *     the old binding version.
         */
        TargetOperationCredentialRotate: {
            purpose_class: components["schemas"]["CredentialPurposeClass"];
            /** Secret Ref */
            secret_ref?: string | null;
        };
        /** TargetOut */
        TargetOut: {
            /** Config */
            config: {
                [key: string]: unknown;
            };
            /** Config Hash */
            config_hash: string;
            /**
             * Created At
             * Format: date-time
             */
            created_at: string;
            /** Display Name */
            display_name: string;
            /**
             * Id
             * Format: uuid
             */
            id: string;
            /**
             * Organization Id
             * Format: uuid
             */
            organization_id: string;
            /** Plugin Name */
            plugin_name: string;
            /** Scope Policy */
            scope_policy: {
                [key: string]: unknown;
            };
            /** Secret Ref */
            secret_ref: string | null;
            /** Status */
            status: string;
        };
        /** TeamCreate */
        TeamCreate: {
            /** Name */
            name: string;
        };
        /** TeamMemberCreate */
        TeamMemberCreate: {
            /** Display Name */
            display_name: string;
            /** User Id */
            user_id?: string | null;
        };
        /**
         * TeamMemberOut
         * @description A roster entry. Carries no permission and never affects scoring or authorization.
         */
        TeamMemberOut: {
            /**
             * Competition Id
             * Format: uuid
             */
            competition_id: string;
            /**
             * Created At
             * Format: date-time
             */
            created_at: string;
            /** Display Name */
            display_name: string;
            /**
             * Id
             * Format: uuid
             */
            id: string;
            /**
             * Team Id
             * Format: uuid
             */
            team_id: string;
            /** User Id */
            user_id?: string | null;
        };
        /** TeamOut */
        TeamOut: {
            /**
             * Competition Id
             * Format: uuid
             */
            competition_id: string;
            /**
             * Created At
             * Format: date-time
             */
            created_at: string;
            /**
             * Id
             * Format: uuid
             */
            id: string;
            /** Join Code */
            join_code: string;
            /** Name */
            name: string;
            /** Score */
            score: number;
            /** Slug */
            slug: string;
            /** Solved Count */
            solved_count: number;
        };
        /** TeardownEvidenceOut */
        TeardownEvidenceOut: {
            /** Expected Count */
            expected_count: number;
            /**
             * Id
             * Format: uuid
             */
            id: string;
            /**
             * Observed At
             * Format: date-time
             */
            observed_at: string;
            /** Operation Id */
            operation_id?: string | null;
            /** Probe Reachable */
            probe_reachable: boolean;
            /**
             * Range Id
             * Format: uuid
             */
            range_id: string;
            /** Reason */
            reason?: string | null;
            /** Removed Confirmed */
            removed_confirmed: number;
            /** Resources */
            resources: components["schemas"]["TeardownResourceOut"][];
            /** Still Present */
            still_present: number;
            /** Unproven Count */
            unproven_count: number;
            verdict: components["schemas"]["ResidueVerdict"];
        };
        /** TeardownResourceOut */
        TeardownResourceOut: {
            /** Detail */
            detail?: string | null;
            /** External Id */
            external_id?: string | null;
            /** Kind */
            kind: string;
            /** Name */
            name: string;
            /** Verdict */
            verdict: string;
        };
        /** TemplateCreate */
        TemplateCreate: {
            /**
             * Description
             * @default
             */
            description: string;
            /**
             * Display Name
             * @default
             */
            display_name: string;
            /** Name */
            name: string;
            /** Slug */
            slug: string;
        };
        /** TemplateOut */
        TemplateOut: {
            /**
             * Created At
             * Format: date-time
             */
            created_at: string;
            /** Description */
            description: string;
            /** Display Name */
            display_name: string;
            /**
             * Id
             * Format: uuid
             */
            id: string;
            /** Name */
            name: string;
            /**
             * Organization Id
             * Format: uuid
             */
            organization_id: string;
            /** Slug */
            slug: string;
        };
        /**
         * ToolchainAttestationOut
         * @description The durable PR2 worker-local toolchain attestation record (B1B-PR4 §1).
         *
         *     It carries NO worker-local path, filename, executable content, provider content, CLI content, or
         *     expected/observed raw digest — only ids, bounded facet names, bounded reason codes, versions and
         *     content hashes.
         */
        ToolchainAttestationOut: {
            /** Collected At */
            collected_at: string;
            /** Evidence Hash */
            evidence_hash: string;
            /** Execution Target Id */
            execution_target_id: string;
            /** Expired */
            expired: boolean;
            /** Expires At */
            expires_at: string;
            /** Operation Fingerprint */
            operation_fingerprint: string;
            /** Outcome */
            outcome: string;
            /** Reason Codes */
            reason_codes?: string[];
            /** Record Id */
            record_id: string;
            /** Toolchain Profile Hash */
            toolchain_profile_hash: string;
            /** Toolchain Profile Id */
            toolchain_profile_id: string;
            /** Verified Facets */
            verified_facets?: string[];
            /** Verifier Policy Version */
            verifier_policy_version: string;
            /** Worker Identity Registration Id */
            worker_identity_registration_id: string;
            /** Worker Identity Version */
            worker_identity_version: number;
        };
        /**
         * ToolchainProfileCreate
         * @description Register an immutable toolchain profile for a target (SECP-002B-1A).
         */
        ToolchainProfileCreate: {
            /** Name */
            name: string;
            /** Profile */
            profile: {
                [key: string]: unknown;
            };
        };
        /** ToolchainProfileOut */
        ToolchainProfileOut: {
            /** Activation Class */
            activation_class: string;
            /** Content */
            content: {
                [key: string]: unknown;
            };
            /** Content Hash */
            content_hash: string;
            /**
             * Created At
             * Format: date-time
             */
            created_at: string;
            /**
             * Execution Target Id
             * Format: uuid
             */
            execution_target_id: string;
            /**
             * Id
             * Format: uuid
             */
            id: string;
            /** Name */
            name: string;
            /**
             * Organization Id
             * Format: uuid
             */
            organization_id: string;
            /** Renderer Version */
            renderer_version: string;
            /** Runner Kind */
            runner_kind: string;
            /** Status */
            status: string;
            /** Version */
            version: number;
        };
        /**
         * TopologyAuthoringStatus
         * @description Lifecycle of a topology-authoring aggregate (SECP-B9).
         *
         *     The aggregate advances only through explicit, separately-permissioned
         *     actions. ``approved`` records a decision — it never generates a plan or
         *     contacts infrastructure. A new revision after approval reopens drafting.
         * @enum {string}
         */
        TopologyAuthoringStatus: "draft" | "validated" | "submitted" | "approved" | "rejected";
        /** TopologyDecision */
        TopologyDecision: {
            /** Content Hash */
            content_hash: string;
            /** Reason */
            reason?: string | null;
        };
        /**
         * TopologyDocumentDetailOut
         * @description Aggregate + its current revision + the current revision's validation
         *     posture, so the workspace can detect a stale local draft in one call.
         */
        TopologyDocumentDetailOut: {
            /** Approved Revision Id */
            approved_revision_id: string | null;
            /**
             * Created At
             * Format: date-time
             */
            created_at: string;
            current_revision: components["schemas"]["TopologyRevisionDetailOut"] | null;
            /** Current Revision Id */
            current_revision_id: string | null;
            current_validation_status: components["schemas"]["TopologyValidationStatus"];
            /** Display Name */
            display_name: string;
            /** Exercise Id */
            exercise_id: string | null;
            /**
             * Id
             * Format: uuid
             */
            id: string;
            /**
             * Organization Id
             * Format: uuid
             */
            organization_id: string;
            /** Revision Count */
            revision_count: number;
            /** Source Environment Version Id */
            source_environment_version_id: string | null;
            status: components["schemas"]["TopologyAuthoringStatus"];
            /** Submitted Revision Id */
            submitted_revision_id: string | null;
            /**
             * Updated At
             * Format: date-time
             */
            updated_at: string;
            /** Validated Revision Id */
            validated_revision_id: string | null;
        };
        /** TopologyDraftCreate */
        TopologyDraftCreate: {
            /** Display Name */
            display_name: string;
            /** Document */
            document?: {
                [key: string]: unknown;
            } | null;
            /** Exercise Id */
            exercise_id?: string | null;
            /** Source Environment Version Id */
            source_environment_version_id?: string | null;
        };
        /**
         * TopologyHashPin
         * @description Shared body for validate/submit/approve/reject — pins the exact hash.
         */
        TopologyHashPin: {
            /** Content Hash */
            content_hash: string;
        };
        /** TopologyRevisionCreate */
        TopologyRevisionCreate: {
            /** Base Content Hash */
            base_content_hash: string;
            /** Base Revision Number */
            base_revision_number: number;
            /** Change Note */
            change_note?: string | null;
            /** Document */
            document: {
                [key: string]: unknown;
            };
        };
        /** TopologyRevisionDetailOut */
        TopologyRevisionDetailOut: {
            /** Change Note */
            change_note: string | null;
            /** Content Hash */
            content_hash: string;
            /**
             * Created At
             * Format: date-time
             */
            created_at: string;
            /** Created By */
            created_by: string | null;
            /** Decided At */
            decided_at: string | null;
            /** Decided By */
            decided_by: string | null;
            /** Document Content */
            document_content: {
                [key: string]: unknown;
            };
            /**
             * Document Id
             * Format: uuid
             */
            document_id: string;
            /**
             * Id
             * Format: uuid
             */
            id: string;
            /** Parent Revision Id */
            parent_revision_id: string | null;
            /** Revision Number */
            revision_number: number;
            /** Schema Version */
            schema_version: string;
            /** Source Environment Version Id */
            source_environment_version_id: string | null;
            status: components["schemas"]["TopologyRevisionStatus"];
        };
        /** TopologyRevisionOut */
        TopologyRevisionOut: {
            /** Change Note */
            change_note: string | null;
            /** Content Hash */
            content_hash: string;
            /**
             * Created At
             * Format: date-time
             */
            created_at: string;
            /** Created By */
            created_by: string | null;
            /** Decided At */
            decided_at: string | null;
            /** Decided By */
            decided_by: string | null;
            /**
             * Document Id
             * Format: uuid
             */
            document_id: string;
            /**
             * Id
             * Format: uuid
             */
            id: string;
            /** Parent Revision Id */
            parent_revision_id: string | null;
            /** Revision Number */
            revision_number: number;
            /** Schema Version */
            schema_version: string;
            /** Source Environment Version Id */
            source_environment_version_id: string | null;
            status: components["schemas"]["TopologyRevisionStatus"];
        };
        /**
         * TopologyRevisionStatus
         * @description Per-revision lifecycle. Content + hash are immutable once created; only
         *     this status advances (draft → validated → submitted → approved/rejected).
         *     A submitted/approved revision is frozen — edits create a NEW draft revision.
         *     ``superseded`` marks a former current revision replaced by a newer one.
         * @enum {string}
         */
        TopologyRevisionStatus: "draft" | "validated" | "submitted" | "approved" | "rejected" | "superseded";
        /** TopologyValidationOut */
        TopologyValidationOut: {
            /** Content Hash */
            content_hash: string;
            /** Error Count */
            error_count: number;
            /** Findings */
            findings: {
                [key: string]: unknown;
            }[];
            /**
             * Id
             * Format: uuid
             */
            id: string;
            /** Result Hash */
            result_hash: string;
            /**
             * Revision Id
             * Format: uuid
             */
            revision_id: string;
            status: components["schemas"]["TopologyValidationStatus"];
            /**
             * Validated At
             * Format: date-time
             */
            validated_at: string;
            /** Validated By */
            validated_by: string | null;
            /** Warning Count */
            warning_count: number;
        };
        /**
         * TopologyValidationStatus
         * @description Outcome of a validation action, pinned to an exact revision + hash.
         *
         *     Never implies approval or deployability. ``unverifiable`` is neither pass
         *     nor fail. ``stale`` is used by the read model when a recorded result no
         *     longer matches the aggregate's current revision hash.
         * @enum {string}
         */
        TopologyValidationStatus: "valid" | "valid_with_warnings" | "invalid" | "unverifiable" | "stale";
        /** ValidationError */
        ValidationError: {
            /** Context */
            ctx?: Record<string, never>;
            /** Input */
            input?: unknown;
            /** Location */
            loc: (string | number)[];
            /** Message */
            msg: string;
            /** Error Type */
            type: string;
        };
        /** ValidationOut */
        ValidationOut: {
            /**
             * Errors
             * @default []
             */
            errors: string[];
            /** Ok */
            ok: boolean;
            /**
             * Warnings
             * @default []
             */
            warnings: string[];
        };
        /** VersionCreate */
        VersionCreate: {
            /** Definition */
            definition: {
                [key: string]: unknown;
            };
        };
        /** VersionOut */
        VersionOut: {
            /** Api Version */
            api_version: string;
            /** Content Hash */
            content_hash: string;
            /**
             * Created At
             * Format: date-time
             */
            created_at: string;
            /**
             * Id
             * Format: uuid
             */
            id: string;
            publication_provenance?: components["schemas"]["VersionPublicationProvenanceOut"] | null;
            /** Spec */
            spec: {
                [key: string]: unknown;
            };
            /**
             * Template Id
             * Format: uuid
             */
            template_id: string;
            /** Version Number */
            version_number: number;
        };
        /**
         * VersionPublicationProvenanceOut
         * @description Typed, server-owned publication provenance for a published v1alpha2 EnvironmentVersion
         *     (ADR-016 PR C). Populated ONLY from the immutable mirrored database columns; every value
         *     equals the embedded ``spec.publicationProvenance`` (the DB enforces that coherence), and
         *     ``publication_fingerprint`` is the server-derived column — never client-supplied.
         */
        VersionPublicationProvenanceOut: {
            /** Base Environment Version Id */
            base_environment_version_id: string | null;
            /** Publication Contract Version */
            publication_contract_version: string;
            /** Publication Fingerprint */
            publication_fingerprint: string;
            /** Topology Content Hash */
            topology_content_hash: string;
            /**
             * Topology Document Id
             * Format: uuid
             */
            topology_document_id: string;
            /**
             * Topology Revision Id
             * Format: uuid
             */
            topology_revision_id: string;
            /** Topology Validation Result Hash */
            topology_validation_result_hash: string;
            /**
             * Topology Validation Result Id
             * Format: uuid
             */
            topology_validation_result_id: string;
        };
        /**
         * WorkerEnrollmentStateName
         * @description The closed set of enrollment state names, as a REQUEST-side filter vocabulary.
         *
         *     These are exactly the eight states of the pure transition contract
         *     (``worker_enrollment_contract.ALL_STATES``): the five active ones, the terminal-success state,
         *     and the two terminals. The enum exists so a query filter is a closed, self-documenting,
         *     automatically-422-on-anything-else vocabulary rather than a free-form string reaching the
         *     repository.
         *
         *     It is deliberately declared with literal values instead of imported from the contract: the
         *     contract is the pure, boundary-mirrored authority and must not acquire an ``enums`` dependency.
         *     ``apps/api/tests/test_enrollment_list_api.py`` pins this enum against ``ALL_STATES`` (values AND
         *     order), so adding a state to one side without the other fails closed in CI.
         * @enum {string}
         */
        WorkerEnrollmentStateName: "invited" | "worker_bound" | "offer_transported" | "result_transported" | "verified" | "healthy" | "refused" | "recovery_required";
        /**
         * WorkerNodeIdentityApprovalLinkRequest
         * @description Explicit, secret-free operator review that creates/approves/links one node identity.
         */
        WorkerNodeIdentityApprovalLinkRequest: {
            /** Deployment Binding */
            deployment_binding: string;
            /** Deployment Binding Review Confirmed */
            deployment_binding_review_confirmed: boolean;
            /** Expected Admission Anchor Fingerprint */
            expected_admission_anchor_fingerprint: string;
            /** Expected Node Revision */
            expected_node_revision: number;
            /** Expected Ssh Public Key Fingerprint */
            expected_ssh_public_key_fingerprint: string;
            /** Issuer */
            issuer: string;
            /** Proof Id */
            proof_id: string;
            /** Rotation Revocation Review Confirmed */
            rotation_revocation_review_confirmed: boolean;
            /** Verification Anchor Review Confirmed */
            verification_anchor_review_confirmed: boolean;
        };
        /** WorkerNodeOut */
        WorkerNodeOut: {
            /** Admission Anchor Fingerprint */
            admission_anchor_fingerprint: string;
            /** Admission Anchor Hex */
            admission_anchor_hex: string;
            /**
             * Created At
             * Format: date-time
             */
            created_at: string;
            /**
             * Id
             * Format: uuid
             */
            id: string;
            /** Node Label */
            node_label: string;
            /**
             * Organization Id
             * Format: uuid
             */
            organization_id: string;
            /** Revision */
            revision: number;
            /** Ssh Public Key */
            ssh_public_key: string;
            /** Ssh Public Key Fingerprint */
            ssh_public_key_fingerprint: string;
            /**
             * Updated At
             * Format: date-time
             */
            updated_at: string;
            /** Worker Identity Registration Id */
            worker_identity_registration_id?: string | null;
        };
        /** WorkerNodeRegisterRequest */
        WorkerNodeRegisterRequest: {
            /** Admission Anchor Hex */
            admission_anchor_hex: string;
            /** Node Label */
            node_label: string;
            /** Ssh Public Key */
            ssh_public_key: string;
        };
        /** WorkflowRunOut */
        WorkflowRunOut: {
            /** Correlation Id */
            correlation_id: string;
            /**
             * Created At
             * Format: date-time
             */
            created_at: string;
            /** Detail */
            detail: {
                [key: string]: unknown;
            };
            /** Dispatch Mode */
            dispatch_mode: string;
            /**
             * Exercise Id
             * Format: uuid
             */
            exercise_id: string;
            /** Finished At */
            finished_at: string | null;
            /**
             * Id
             * Format: uuid
             */
            id: string;
            /** Kind */
            kind: string;
            /** Status */
            status: string;
            /** Target Instance Id */
            target_instance_id: string | null;
        };
    };
    responses: never;
    parameters: never;
    requestBodies: never;
    headers: never;
    pathItems: never;
}
export type AccessTargetOut = components['schemas']['AccessTargetOut'];
export type ActivationDossierEvidenceKind = components['schemas']['ActivationDossierEvidenceKind'];
export type ActivationDossierEvidenceStatus = components['schemas']['ActivationDossierEvidenceStatus'];
export type ActivationDossierOut = components['schemas']['ActivationDossierOut'];
export type AddressSpaceIn = components['schemas']['AddressSpaceIn'];
export type AddressSpaceOut = components['schemas']['AddressSpaceOut'];
export type ApprovalDecision = components['schemas']['ApprovalDecision'];
export type ApprovalKind = components['schemas']['ApprovalKind'];
export type ApprovalOut = components['schemas']['ApprovalOut'];
export type AuditEventOut = components['schemas']['AuditEventOut'];
export type AuthConfigOut = components['schemas']['AuthConfigOut'];
export type AuthorizationState = components['schemas']['AuthorizationState'];
export type BindExchangeOut = components['schemas']['BindExchangeOut'];
export type BindExchangeRequest = components['schemas']['BindExchangeRequest'];
export type BindingDescriptorOut = components['schemas']['BindingDescriptorOut'];
export type BlockedReasonOut = components['schemas']['BlockedReasonOut'];
export type BootstrapAvailabilityOut = components['schemas']['BootstrapAvailabilityOut'];
export type BootstrapCompleteRequest = components['schemas']['BootstrapCompleteRequest'];
export type BootstrapOperationOut = components['schemas']['BootstrapOperationOut'];
export type BootstrapScriptOut = components['schemas']['BootstrapScriptOut'];
export type BootstrapSessionCreate = components['schemas']['BootstrapSessionCreate'];
export type BootstrapSessionOut = components['schemas']['BootstrapSessionOut'];
export type BundleDescriptorOut = components['schemas']['BundleDescriptorOut'];
export type CandidatePlanOut = components['schemas']['CandidatePlanOut'];
export type CandidatePlanResourceOut = components['schemas']['CandidatePlanResourceOut'];
export type CapabilityState = components['schemas']['CapabilityState'];
export type ChallengeOut = components['schemas']['ChallengeOut'];
export type ChangeSetApprovalOut = components['schemas']['ChangeSetApprovalOut'];
export type CommandKind = components['schemas']['CommandKind'];
export type CompetitionCreate = components['schemas']['CompetitionCreate'];
export type CompetitionOut = components['schemas']['CompetitionOut'];
export type CompetitionState = components['schemas']['CompetitionState'];
export type CreateActivationDossierIn = components['schemas']['CreateActivationDossierIn'];
export type CreateEnrollmentInvitation = components['schemas']['CreateEnrollmentInvitation'];
export type CreatePlanGenerationAuthorizationIn = components['schemas']['CreatePlanGenerationAuthorizationIn'];
export type CreatePlanSecretAuthorizationIn = components['schemas']['CreatePlanSecretAuthorizationIn'];
export type CreatePreflightAuthorization = components['schemas']['CreatePreflightAuthorization'];
export type CreateResolverActivation = components['schemas']['CreateResolverActivation'];
export type CredentialPurposeClass = components['schemas']['CredentialPurposeClass'];
export type DecisionBody = components['schemas']['DecisionBody'];
export type DeploymentApprove = components['schemas']['DeploymentApprove'];
export type DeploymentCreate = components['schemas']['DeploymentCreate'];
export type DeploymentOut = components['schemas']['DeploymentOut'];
export type DeploymentPlanOut = components['schemas']['DeploymentPlanOut'];
export type DeploymentResourceOut = components['schemas']['DeploymentResourceOut'];
export type DeploymentVerificationOut = components['schemas']['DeploymentVerificationOut'];
export type DetachedAttestationIn = components['schemas']['DetachedAttestationIn'];
export type DetachedAttestationOut = components['schemas']['DetachedAttestationOut'];
export type DiscoveryApprove = components['schemas']['DiscoveryApprove'];
export type DiscoveryBootstrapAvailabilityOut = components['schemas']['DiscoveryBootstrapAvailabilityOut'];
export type DiscoveryEvidenceOut = components['schemas']['DiscoveryEvidenceOut'];
export type DiscoveryReadinessOut = components['schemas']['DiscoveryReadinessOut'];
export type DiscoveryRequest = components['schemas']['DiscoveryRequest'];
export type DossierEvidenceOut = components['schemas']['DossierEvidenceOut'];
export type EligibleSubstrateOut = components['schemas']['EligibleSubstrateOut'];
export type EnrollmentInvitationOut = components['schemas']['EnrollmentInvitationOut'];
export type EnrollmentListOut = components['schemas']['EnrollmentListOut'];
export type EnrollmentOut = components['schemas']['EnrollmentOut'];
export type EnrollmentStatusOut = components['schemas']['EnrollmentStatusOut'];
export type EnvironmentPublicationRequest = components['schemas']['EnvironmentPublicationRequest'];
export type EvidenceReferenceOut = components['schemas']['EvidenceReferenceOut'];
export type ExerciseCreate = components['schemas']['ExerciseCreate'];
export type ExerciseOut = components['schemas']['ExerciseOut'];
export type HttpValidationError = components['schemas']['HTTPValidationError'];
export type InstanceOut = components['schemas']['InstanceOut'];
export type IsolationFindingOut = components['schemas']['IsolationFindingOut'];
export type IsolationModel = components['schemas']['IsolationModel'];
export type ManifestOut = components['schemas']['ManifestOut'];
export type MarkRecoveryRequired = components['schemas']['MarkRecoveryRequired'];
export type MaterialRefOut = components['schemas']['MaterialRefOut'];
export type ObservationFreshness = components['schemas']['ObservationFreshness'];
export type OnboardingCreate = components['schemas']['OnboardingCreate'];
export type OnboardingDecision = components['schemas']['OnboardingDecision'];
export type OnboardingMode = components['schemas']['OnboardingMode'];
export type OnboardingOut = components['schemas']['OnboardingOut'];
export type OperationCapabilityOut = components['schemas']['OperationCapabilityOut'];
export type OperationOut = components['schemas']['OperationOut'];
export type OwnershipClassOut = components['schemas']['OwnershipClassOut'];
export type PlanEnvironmentVersionBindingOut = components['schemas']['PlanEnvironmentVersionBindingOut'];
export type PlanGenerationAuthorizationOut = components['schemas']['PlanGenerationAuthorizationOut'];
export type PlanGenerationPurpose = components['schemas']['PlanGenerationPurpose'];
export type PlanGenerationReadinessOut = components['schemas']['PlanGenerationReadinessOut'];
export type PlanGenerationRequestAccepted = components['schemas']['PlanGenerationRequestAccepted'];
export type PlannedResourceOut = components['schemas']['PlannedResourceOut'];
export type PlanOut = components['schemas']['PlanOut'];
export type PlanSecretAuthorizationOut = components['schemas']['PlanSecretAuthorizationOut'];
export type PlanSecretEvidenceKind = components['schemas']['PlanSecretEvidenceKind'];
export type PlanSecretEvidenceOut = components['schemas']['PlanSecretEvidenceOut'];
export type PlanSecretEvidenceStatus = components['schemas']['PlanSecretEvidenceStatus'];
export type PlanSecretPurpose = components['schemas']['PlanSecretPurpose'];
export type PlanSecretReadinessOut = components['schemas']['PlanSecretReadinessOut'];
export type PlanState = components['schemas']['PlanState'];
export type PluginOut = components['schemas']['PluginOut'];
export type PreflightAuthorizationOut = components['schemas']['PreflightAuthorizationOut'];
export type PreflightOut = components['schemas']['PreflightOut'];
export type PreflightSubstrateOut = components['schemas']['PreflightSubstrateOut'];
export type PrincipalOut = components['schemas']['PrincipalOut'];
export type ProviderCapabilitiesOut = components['schemas']['ProviderCapabilitiesOut'];
export type ProviderCapabilityOut = components['schemas']['ProviderCapabilityOut'];
export type ProviderCompatibilityOut = components['schemas']['ProviderCompatibilityOut'];
export type ProviderSupport = components['schemas']['ProviderSupport'];
export type ProvisioningReadinessOut = components['schemas']['ProvisioningReadinessOut'];
export type ProxmoxAllocationOut = components['schemas']['ProxmoxAllocationOut'];
export type ProxmoxAllocationsOut = components['schemas']['ProxmoxAllocationsOut'];
export type ProxmoxApplyAuthorizationOut = components['schemas']['ProxmoxApplyAuthorizationOut'];
export type ProxmoxApplyAuthorizationRequest = components['schemas']['ProxmoxApplyAuthorizationRequest'];
export type ProxmoxCommandOut = components['schemas']['ProxmoxCommandOut'];
export type ProxmoxCompileTopologyRequest = components['schemas']['ProxmoxCompileTopologyRequest'];
export type ProxmoxDestroyAuthorizationOut = components['schemas']['ProxmoxDestroyAuthorizationOut'];
export type ProxmoxDestroyAuthorizationRequest = components['schemas']['ProxmoxDestroyAuthorizationRequest'];
export type ProxmoxDestroyExecutionRequest = components['schemas']['ProxmoxDestroyExecutionRequest'];
export type ProxmoxDestroyPlanApprovalRequest = components['schemas']['ProxmoxDestroyPlanApprovalRequest'];
export type ProxmoxDestroyPlanGenerateRequest = components['schemas']['ProxmoxDestroyPlanGenerateRequest'];
export type ProxmoxDestroyPlanOut = components['schemas']['ProxmoxDestroyPlanOut'];
export type ProxmoxEvidenceOut = components['schemas']['ProxmoxEvidenceOut'];
export type ProxmoxExecutionRequest = components['schemas']['ProxmoxExecutionRequest'];
export type ProxmoxGeneratePlanRequest = components['schemas']['ProxmoxGeneratePlanRequest'];
export type ProxmoxGuestAddressOut = components['schemas']['ProxmoxGuestAddressOut'];
export type ProxmoxGuestBootstrapOut = components['schemas']['ProxmoxGuestBootstrapOut'];
export type ProxmoxGuestOut = components['schemas']['ProxmoxGuestOut'];
export type ProxmoxLifecycleOut = components['schemas']['ProxmoxLifecycleOut'];
export type ProxmoxObservationOut = components['schemas']['ProxmoxObservationOut'];
export type ProxmoxOwnershipOut = components['schemas']['ProxmoxOwnershipOut'];
export type ProxmoxPlanApprovalRequest = components['schemas']['ProxmoxPlanApprovalRequest'];
export type ProxmoxPlanOut = components['schemas']['ProxmoxPlanOut'];
export type ProxmoxReadinessOut = components['schemas']['ProxmoxReadinessOut'];
export type ProxmoxReconciliationOut = components['schemas']['ProxmoxReconciliationOut'];
export type ProxmoxReconciliationRequest = components['schemas']['ProxmoxReconciliationRequest'];
export type ProxmoxResetAuthorizationOut = components['schemas']['ProxmoxResetAuthorizationOut'];
export type ProxmoxResetAuthorizationRequest = components['schemas']['ProxmoxResetAuthorizationRequest'];
export type ProxmoxResetDispositionsOut = components['schemas']['ProxmoxResetDispositionsOut'];
export type ProxmoxResetGuestOut = components['schemas']['ProxmoxResetGuestOut'];
export type ProxmoxResetPlanApprovalRequest = components['schemas']['ProxmoxResetPlanApprovalRequest'];
export type ProxmoxResetPlanOut = components['schemas']['ProxmoxResetPlanOut'];
export type ProxmoxResetRequest = components['schemas']['ProxmoxResetRequest'];
export type ProxmoxResetScopeEntryOut = components['schemas']['ProxmoxResetScopeEntryOut'];
export type ProxmoxResidueOut = components['schemas']['ProxmoxResidueOut'];
export type ProxmoxSubmitPlanRequest = components['schemas']['ProxmoxSubmitPlanRequest'];
export type ProxmoxTopologyOut = components['schemas']['ProxmoxTopologyOut'];
export type ProxmoxVerificationOut = components['schemas']['ProxmoxVerificationOut'];
export type ProxmoxWorkerOut = components['schemas']['ProxmoxWorkerOut'];
export type ProxmoxWorkloadOut = components['schemas']['ProxmoxWorkloadOut'];
export type QueuePreflight = components['schemas']['QueuePreflight'];
export type RangeComponentOut = components['schemas']['RangeComponentOut'];
export type RangeCreate = components['schemas']['RangeCreate'];
export type RangeEventLevel = components['schemas']['RangeEventLevel'];
export type RangeEventOut = components['schemas']['RangeEventOut'];
export type RangeOperationAbandonIn = components['schemas']['RangeOperationAbandonIn'];
export type RangeOperationKind = components['schemas']['RangeOperationKind'];
export type RangeOperationOut = components['schemas']['RangeOperationOut'];
export type RangeOperationStatus = components['schemas']['RangeOperationStatus'];
export type RangeOperationStepOut = components['schemas']['RangeOperationStepOut'];
export type RangeOperationSummaryOut = components['schemas']['RangeOperationSummaryOut'];
export type RangeOut = components['schemas']['RangeOut'];
export type RangeResourceKind = components['schemas']['RangeResourceKind'];
export type RangeResourceOut = components['schemas']['RangeResourceOut'];
export type RangeResourceState = components['schemas']['RangeResourceState'];
export type RangeState = components['schemas']['RangeState'];
export type RangeTemplateOut = components['schemas']['RangeTemplateOut'];
export type ReadinessFacetOut = components['schemas']['ReadinessFacetOut'];
export type ReadinessFindingOut = components['schemas']['ReadinessFindingOut'];
export type ReadinessRequestAccepted = components['schemas']['ReadinessRequestAccepted'];
export type ReadonlyPreflightOut = components['schemas']['ReadonlyPreflightOut'];
export type RecordDossierEvidenceIn = components['schemas']['RecordDossierEvidenceIn'];
export type RecordedStageState = components['schemas']['RecordedStageState'];
export type RecordPlanSecretEvidenceIn = components['schemas']['RecordPlanSecretEvidenceIn'];
export type RecordResolverActivationEvidence = components['schemas']['RecordResolverActivationEvidence'];
export type RefusalCode = components['schemas']['RefusalCode'];
export type RemoteStateReadinessOut = components['schemas']['RemoteStateReadinessOut'];
export type RequirementFindingOut = components['schemas']['RequirementFindingOut'];
export type RequirementKind = components['schemas']['RequirementKind'];
export type RequirementStatus = components['schemas']['RequirementStatus'];
export type ReservationOut = components['schemas']['ReservationOut'];
export type ResidueVerdict = components['schemas']['ResidueVerdict'];
export type ResolverActivationEvidenceKind = components['schemas']['ResolverActivationEvidenceKind'];
export type ResolverActivationEvidenceOut = components['schemas']['ResolverActivationEvidenceOut'];
export type ResolverActivationEvidenceStatus = components['schemas']['ResolverActivationEvidenceStatus'];
export type ResolverActivationOut = components['schemas']['ResolverActivationOut'];
export type ResourceOut = components['schemas']['ResourceOut'];
export type ResultExchangeOut = components['schemas']['ResultExchangeOut'];
export type ResultExchangeRequest = components['schemas']['ResultExchangeRequest'];
export type RevokeDossierIn = components['schemas']['RevokeDossierIn'];
export type RevokeEnrollment = components['schemas']['RevokeEnrollment'];
export type RevokePlanGenerationAuthorizationIn = components['schemas']['RevokePlanGenerationAuthorizationIn'];
export type RevokePlanSecretAuthorizationIn = components['schemas']['RevokePlanSecretAuthorizationIn'];
export type ScenarioOut = components['schemas']['ScenarioOut'];
export type ScoreboardEntryOut = components['schemas']['ScoreboardEntryOut'];
export type ScoreboardOut = components['schemas']['ScoreboardOut'];
export type SealedApplyNoticeOut = components['schemas']['SealedApplyNoticeOut'];
export type SignedControllerOfferOut = components['schemas']['SignedControllerOfferOut'];
export type SnapshotOut = components['schemas']['SnapshotOut'];
export type StagingBootstrapArtifactProfile = components['schemas']['StagingBootstrapArtifactProfile'];
export type StagingLabApprove = components['schemas']['StagingLabApprove'];
export type StagingLabCreate = components['schemas']['StagingLabCreate'];
export type StagingLabOut = components['schemas']['StagingLabOut'];
export type StagingLabWorkItemOut = components['schemas']['StagingLabWorkItemOut'];
export type StagingResourceClass = components['schemas']['StagingResourceClass'];
export type StagingRollbackPolicy = components['schemas']['StagingRollbackPolicy'];
export type SubmissionCreate = components['schemas']['SubmissionCreate'];
export type SubmissionOut = components['schemas']['SubmissionOut'];
export type SubmissionVerdict = components['schemas']['SubmissionVerdict'];
export type SubstrateEligibilityGrantOut = components['schemas']['SubstrateEligibilityGrantOut'];
export type TargetCreate = components['schemas']['TargetCreate'];
export type TargetCredentialRotate = components['schemas']['TargetCredentialRotate'];
export type TargetEvidenceOut = components['schemas']['TargetEvidenceOut'];
export type TargetOperationCredentialRotate = components['schemas']['TargetOperationCredentialRotate'];
export type TargetOut = components['schemas']['TargetOut'];
export type TeamCreate = components['schemas']['TeamCreate'];
export type TeamMemberCreate = components['schemas']['TeamMemberCreate'];
export type TeamMemberOut = components['schemas']['TeamMemberOut'];
export type TeamOut = components['schemas']['TeamOut'];
export type TeardownEvidenceOut = components['schemas']['TeardownEvidenceOut'];
export type TeardownResourceOut = components['schemas']['TeardownResourceOut'];
export type TemplateCreate = components['schemas']['TemplateCreate'];
export type TemplateOut = components['schemas']['TemplateOut'];
export type ToolchainAttestationOut = components['schemas']['ToolchainAttestationOut'];
export type ToolchainProfileCreate = components['schemas']['ToolchainProfileCreate'];
export type ToolchainProfileOut = components['schemas']['ToolchainProfileOut'];
export type TopologyAuthoringStatus = components['schemas']['TopologyAuthoringStatus'];
export type TopologyDecision = components['schemas']['TopologyDecision'];
export type TopologyDocumentDetailOut = components['schemas']['TopologyDocumentDetailOut'];
export type TopologyDraftCreate = components['schemas']['TopologyDraftCreate'];
export type TopologyHashPin = components['schemas']['TopologyHashPin'];
export type TopologyRevisionCreate = components['schemas']['TopologyRevisionCreate'];
export type TopologyRevisionDetailOut = components['schemas']['TopologyRevisionDetailOut'];
export type TopologyRevisionOut = components['schemas']['TopologyRevisionOut'];
export type TopologyRevisionStatus = components['schemas']['TopologyRevisionStatus'];
export type TopologyValidationOut = components['schemas']['TopologyValidationOut'];
export type TopologyValidationStatus = components['schemas']['TopologyValidationStatus'];
export type ValidationError = components['schemas']['ValidationError'];
export type ValidationOut = components['schemas']['ValidationOut'];
export type VersionCreate = components['schemas']['VersionCreate'];
export type VersionOut = components['schemas']['VersionOut'];
export type VersionPublicationProvenanceOut = components['schemas']['VersionPublicationProvenanceOut'];
export type WorkerEnrollmentStateName = components['schemas']['WorkerEnrollmentStateName'];
export type WorkerNodeIdentityApprovalLinkRequest = components['schemas']['WorkerNodeIdentityApprovalLinkRequest'];
export type WorkerNodeOut = components['schemas']['WorkerNodeOut'];
export type WorkerNodeRegisterRequest = components['schemas']['WorkerNodeRegisterRequest'];
export type WorkflowRunOut = components['schemas']['WorkflowRunOut'];
export type $defs = Record<string, never>;
export interface operations {
    get_activation_dossier_api_v1_activation_dossiers__dossier_id__get: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                dossier_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ActivationDossierOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    approve_activation_dossier_api_v1_activation_dossiers__dossier_id__approve_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                dossier_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ActivationDossierOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    record_dossier_evidence_api_v1_activation_dossiers__dossier_id__evidence_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                dossier_id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["RecordDossierEvidenceIn"];
            };
        };
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ActivationDossierOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    revoke_activation_dossier_api_v1_activation_dossiers__dossier_id__revoke_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                dossier_id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["RevokeDossierIn"];
            };
        };
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ActivationDossierOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    list_audit_api_v1_audit_get: {
        parameters: {
            query?: {
                exercise_id?: string | null;
            };
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["AuditEventOut"][];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    auth_config_api_v1_auth_config_get: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["AuthConfigOut"];
                };
            };
        };
    };
    get_change_set_api_v1_change_sets__approval_id__get: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                approval_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ChangeSetApprovalOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    approve_change_set_api_v1_change_sets__approval_id__approve_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                approval_id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["ApprovalDecision"];
            };
        };
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ChangeSetApprovalOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    reject_change_set_api_v1_change_sets__approval_id__reject_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                approval_id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["ApprovalDecision"];
            };
        };
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ChangeSetApprovalOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    get_competition_api_v1_competitions__competition_id__get: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                competition_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["CompetitionOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    list_challenges_api_v1_competitions__competition_id__challenges_get: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                competition_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ChallengeOut"][];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    reset_scores_api_v1_competitions__competition_id__reset_scores_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                competition_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["CompetitionOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    get_scoreboard_api_v1_competitions__competition_id__scoreboard_get: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                competition_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ScoreboardOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    start_competition_api_v1_competitions__competition_id__start_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                competition_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["CompetitionOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    stop_competition_api_v1_competitions__competition_id__stop_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                competition_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["CompetitionOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    list_submissions_api_v1_competitions__competition_id__submissions_get: {
        parameters: {
            query?: {
                challenge_id?: string | null;
                limit?: number;
                team_id?: string | null;
            };
            header?: never;
            path: {
                competition_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["SubmissionOut"][];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    submit_flag_api_v1_competitions__competition_id__submissions_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                competition_id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["SubmissionCreate"];
            };
        };
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["SubmissionOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    list_teams_api_v1_competitions__competition_id__teams_get: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                competition_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["TeamOut"][];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    create_team_api_v1_competitions__competition_id__teams_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                competition_id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["TeamCreate"];
            };
        };
        responses: {
            /** @description Successful Response */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["TeamOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    delete_team_api_v1_competitions__competition_id__teams__team_id__delete: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                competition_id: string;
                team_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            204: {
                headers: {
                    [name: string]: unknown;
                };
                content?: never;
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    list_team_members_api_v1_competitions__competition_id__teams__team_id__members_get: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                competition_id: string;
                team_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["TeamMemberOut"][];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    add_team_member_api_v1_competitions__competition_id__teams__team_id__members_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                competition_id: string;
                team_id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["TeamMemberCreate"];
            };
        };
        responses: {
            /** @description Successful Response */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["TeamMemberOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    remove_team_member_api_v1_competitions__competition_id__teams__team_id__members__member_id__delete: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                competition_id: string;
                member_id: string;
                team_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            204: {
                headers: {
                    [name: string]: unknown;
                };
                content?: never;
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    validate_definition_endpoint_api_v1_definitions_validate_post: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["VersionCreate"];
            };
        };
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ValidationOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    list_enrollments_api_v1_enrollment_get: {
        parameters: {
            query?: {
                after?: string | null;
                limit?: number;
                state?: components["schemas"]["WorkerEnrollmentStateName"][] | null;
            };
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["EnrollmentListOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    get_enrollment_status_api_v1_enrollment__enrollment_id__get: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                enrollment_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["EnrollmentStatusOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    bind_worker_exchange_api_v1_enrollment__enrollment_id__exchange_bind_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                enrollment_id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["BindExchangeRequest"];
            };
        };
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["BindExchangeOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    record_worker_result_exchange_api_v1_enrollment__enrollment_id__exchange_result_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                enrollment_id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["ResultExchangeRequest"];
            };
        };
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ResultExchangeOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    mark_enrollment_recovery_required_api_v1_enrollment__enrollment_id__recover_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                enrollment_id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["MarkRecoveryRequired"];
            };
        };
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["EnrollmentStatusOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    revoke_enrollment_api_v1_enrollment__enrollment_id__revoke_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                enrollment_id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["RevokeEnrollment"];
            };
        };
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["EnrollmentStatusOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    create_enrollment_invitation_api_v1_enrollment_invitations_post: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["CreateEnrollmentInvitation"];
            };
        };
        responses: {
            /** @description Successful Response */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["EnrollmentInvitationOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    get_environment_version_api_v1_environment_versions__version_id__get: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                version_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["VersionOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    publish_environment_version_api_v1_environment_versions_publish_post: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["EnvironmentPublicationRequest"];
            };
        };
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["VersionOut"];
                };
            };
            /** @description Created */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["VersionOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    list_exercises_api_v1_exercises_get: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ExerciseOut"][];
                };
            };
        };
    };
    create_exercise_api_v1_exercises_post: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["ExerciseCreate"];
            };
        };
        responses: {
            /** @description Successful Response */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ExerciseOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    get_exercise_api_v1_exercises__exercise_id__get: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                exercise_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ExerciseOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    deploy_exercise_api_v1_exercises__exercise_id__deploy_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                exercise_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["WorkflowRunOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    destroy_exercise_api_v1_exercises__exercise_id__destroy_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                exercise_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["WorkflowRunOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    list_instances_api_v1_exercises__exercise_id__instances_get: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                exercise_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["InstanceOut"][];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    reset_instance_api_v1_exercises__exercise_id__instances__instance_id__reset_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                exercise_id: string;
                instance_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["WorkflowRunOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    latest_plan_api_v1_exercises__exercise_id__plan_get: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                exercise_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["PlanOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    generate_plan_api_v1_exercises__exercise_id__plan_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                exercise_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["PlanOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    exercise_topology_api_v1_exercises__exercise_id__topology_get: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                exercise_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": {
                        [key: string]: unknown;
                    }[];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    validate_exercise_api_v1_exercises__exercise_id__validate_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                exercise_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ExerciseOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    instance_topology_api_v1_instances__instance_id__topology_get: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                instance_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": {
                        [key: string]: unknown;
                    };
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    get_manifest_api_v1_manifests__manifest_id__get: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                manifest_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ManifestOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    list_change_sets_api_v1_manifests__manifest_id__change_sets_get: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                manifest_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ChangeSetApprovalOut"][];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    list_operations_api_v1_manifests__manifest_id__operations_get: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                manifest_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["OperationOut"][];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    me_api_v1_me_get: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["PrincipalOut"];
                };
            };
        };
    };
    get_onboarding_api_v1_onboarding__onboarding_id__get: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                onboarding_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["OnboardingOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    activate_onboarding_api_v1_onboarding__onboarding_id__activate_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                onboarding_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["OnboardingOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    approve_onboarding_api_v1_onboarding__onboarding_id__approve_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                onboarding_id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["OnboardingDecision"];
            };
        };
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["OnboardingOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    list_target_evidence_api_v1_onboarding__onboarding_id__evidence_get: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                onboarding_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["TargetEvidenceOut"][];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    list_preflights_api_v1_onboarding__onboarding_id__preflight_get: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                onboarding_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["PreflightOut"][];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    request_preflight_api_v1_onboarding__onboarding_id__preflight_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                onboarding_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["PreflightOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    reject_onboarding_api_v1_onboarding__onboarding_id__reject_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                onboarding_id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["OnboardingDecision"];
            };
        };
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["OnboardingOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    retire_onboarding_api_v1_onboarding__onboarding_id__retire_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                onboarding_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["OnboardingOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    submit_for_review_api_v1_onboarding__onboarding_id__submit_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                onboarding_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["OnboardingOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    get_plan_generation_authorization_api_v1_plan_generation_authorizations__authorization_id__get: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                authorization_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["PlanGenerationAuthorizationOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    approve_plan_generation_authorization_api_v1_plan_generation_authorizations__authorization_id__approve_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                authorization_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["PlanGenerationAuthorizationOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    revoke_plan_generation_authorization_api_v1_plan_generation_authorizations__authorization_id__revoke_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                authorization_id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["RevokePlanGenerationAuthorizationIn"];
            };
        };
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["PlanGenerationAuthorizationOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    get_plan_secret_authorization_api_v1_plan_secret_authorizations__authorization_id__get: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                authorization_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["PlanSecretAuthorizationOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    approve_plan_secret_authorization_api_v1_plan_secret_authorizations__authorization_id__approve_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                authorization_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["PlanSecretAuthorizationOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    record_plan_secret_evidence_api_v1_plan_secret_authorizations__authorization_id__evidence_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                authorization_id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["RecordPlanSecretEvidenceIn"];
            };
        };
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["PlanSecretAuthorizationOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    revoke_plan_secret_authorization_api_v1_plan_secret_authorizations__authorization_id__revoke_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                authorization_id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["RevokePlanSecretAuthorizationIn"];
            };
        };
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["PlanSecretAuthorizationOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    approve_plan_api_v1_plans__plan_id__approve_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                plan_id: string;
            };
            cookie?: never;
        };
        requestBody?: {
            content: {
                "application/json": components["schemas"]["DecisionBody"] | null;
            };
        };
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["PlanOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    generate_manifest_api_v1_plans__plan_id__manifest_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                plan_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ManifestOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    reject_plan_api_v1_plans__plan_id__reject_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                plan_id: string;
            };
            cookie?: never;
        };
        requestBody?: {
            content: {
                "application/json": components["schemas"]["DecisionBody"] | null;
            };
        };
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["PlanOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    submit_plan_api_v1_plans__plan_id__submit_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                plan_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["PlanOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    plugins_api_v1_plugins_get: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["PluginOut"][];
                };
            };
        };
    };
    provider_capabilities_api_v1_providers_capabilities_get: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ProviderCapabilitiesOut"];
                };
            };
        };
    };
    create_activation_dossier_api_v1_provisioning_manifests__manifest_id__activation_dossiers_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                manifest_id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["CreateActivationDossierIn"];
            };
        };
        responses: {
            /** @description Successful Response */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ActivationDossierOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    request_plan_generation_api_v1_provisioning_manifests__manifest_id__plan_generation_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                manifest_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            202: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["PlanGenerationRequestAccepted"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    create_plan_generation_authorization_api_v1_provisioning_manifests__manifest_id__plan_generation_authorizations_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                manifest_id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["CreatePlanGenerationAuthorizationIn"];
            };
        };
        responses: {
            /** @description Successful Response */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["PlanGenerationAuthorizationOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    get_plan_generation_readiness_api_v1_provisioning_manifests__manifest_id__plan_generation_readiness_get: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                manifest_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["PlanGenerationReadinessOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    create_plan_secret_authorization_api_v1_provisioning_manifests__manifest_id__plan_secret_authorizations_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                manifest_id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["CreatePlanSecretAuthorizationIn"];
            };
        };
        responses: {
            /** @description Successful Response */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["PlanSecretAuthorizationOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    get_plan_secret_readiness_api_v1_provisioning_manifests__manifest_id__plan_secret_readiness_get: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                manifest_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["PlanSecretReadinessOut"] | null;
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    request_plan_secret_readiness_api_v1_provisioning_manifests__manifest_id__plan_secret_readiness_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                manifest_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            202: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ReadinessRequestAccepted"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    get_provisioning_readiness_api_v1_provisioning_manifests__manifest_id__provisioning_readiness_get: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                manifest_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ProvisioningReadinessOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    get_remote_state_readiness_api_v1_provisioning_manifests__manifest_id__remote_state_readiness_get: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                manifest_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["RemoteStateReadinessOut"] | null;
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    request_remote_state_readiness_api_v1_provisioning_manifests__manifest_id__remote_state_readiness_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                manifest_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            202: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ReadinessRequestAccepted"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    get_toolchain_attestation_api_v1_provisioning_manifests__manifest_id__toolchain_attestation_get: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                manifest_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ToolchainAttestationOut"] | null;
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    request_toolchain_attestation_api_v1_provisioning_manifests__manifest_id__toolchain_attestation_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                manifest_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            202: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ReadinessRequestAccepted"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    get_operation_api_v1_provisioning_operations__operation_id__get: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                operation_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["OperationOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    get_range_operation_api_v1_range_operations__operation_id__get: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                operation_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["RangeOperationOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    abandon_range_operation_api_v1_range_operations__operation_id__abandon_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                operation_id: string;
            };
            cookie?: never;
        };
        requestBody?: {
            content: {
                "application/json": components["schemas"]["RangeOperationAbandonIn"] | null;
            };
        };
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["RangeOperationOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    list_range_scenarios_api_v1_range_scenarios_get: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ScenarioOut"][];
                };
            };
        };
    };
    get_range_scenario_api_v1_range_scenarios__key__get: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                key: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ScenarioOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    list_range_templates_api_v1_range_templates_get: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["RangeTemplateOut"][];
                };
            };
        };
    };
    get_range_template_api_v1_range_templates__slug__get: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                slug: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["RangeTemplateOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    list_ranges_api_v1_ranges_get: {
        parameters: {
            query?: {
                include_destroyed?: boolean;
                state?: components["schemas"]["RangeState"][] | null;
            };
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["RangeOut"][];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    create_range_api_v1_ranges_post: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["RangeCreate"];
            };
        };
        responses: {
            /** @description Successful Response */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["RangeOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    get_range_api_v1_ranges__range_id__get: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                range_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["RangeOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    list_range_challenges_api_v1_ranges__range_id__challenges_get: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                range_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ChallengeOut"][];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    get_competition_for_range_api_v1_ranges__range_id__competition_get: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                range_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["CompetitionOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    create_competition_api_v1_ranges__range_id__competition_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                range_id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["CompetitionCreate"];
            };
        };
        responses: {
            /** @description Successful Response */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["CompetitionOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    deploy_range_api_v1_ranges__range_id__deploy_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                range_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            202: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["RangeOperationOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    destroy_range_api_v1_ranges__range_id__destroy_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                range_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            202: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["RangeOperationOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    list_range_events_api_v1_ranges__range_id__events_get: {
        parameters: {
            query?: {
                after_sequence?: number;
            };
            header?: never;
            path: {
                range_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["RangeEventOut"][];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    list_range_operations_api_v1_ranges__range_id__operations_get: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                range_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["RangeOperationOut"][];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    get_proxmox_lifecycle_api_v1_ranges__range_id__proxmox_get: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                range_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ProxmoxLifecycleOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    get_proxmox_allocations_api_v1_ranges__range_id__proxmox_allocations_get: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                range_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ProxmoxAllocationsOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    get_proxmox_apply_authorization_api_v1_ranges__range_id__proxmox_apply_authorization_get: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                range_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ProxmoxApplyAuthorizationOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    authorize_proxmox_apply_api_v1_ranges__range_id__proxmox_apply_authorization_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                range_id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["ProxmoxApplyAuthorizationRequest"];
            };
        };
        responses: {
            /** @description Successful Response */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ProxmoxApplyAuthorizationOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    list_proxmox_commands_api_v1_ranges__range_id__proxmox_commands_get: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                range_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ProxmoxCommandOut"][];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    get_proxmox_destroy_authorization_api_v1_ranges__range_id__proxmox_destroy_authorization_get: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                range_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ProxmoxDestroyAuthorizationOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    authorize_proxmox_destroy_api_v1_ranges__range_id__proxmox_destroy_authorization_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                range_id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["ProxmoxDestroyAuthorizationRequest"];
            };
        };
        responses: {
            /** @description Successful Response */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ProxmoxDestroyAuthorizationOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    request_proxmox_destroy_execution_api_v1_ranges__range_id__proxmox_destroy_execution_request_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                range_id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["ProxmoxDestroyExecutionRequest"];
            };
        };
        responses: {
            /** @description Successful Response */
            202: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ProxmoxCommandOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    get_proxmox_destroy_plan_api_v1_ranges__range_id__proxmox_destroy_plan_get: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                range_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ProxmoxDestroyPlanOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    approve_proxmox_destroy_plan_api_v1_ranges__range_id__proxmox_destroy_plan_approval_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                range_id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["ProxmoxDestroyPlanApprovalRequest"];
            };
        };
        responses: {
            /** @description Successful Response */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ProxmoxDestroyPlanOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    generate_proxmox_destroy_plan_api_v1_ranges__range_id__proxmox_destroy_plan_generation_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                range_id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["ProxmoxDestroyPlanGenerateRequest"];
            };
        };
        responses: {
            /** @description Successful Response */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ProxmoxCommandOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    get_proxmox_evidence_api_v1_ranges__range_id__proxmox_evidence_get: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                range_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ProxmoxEvidenceOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    request_proxmox_execution_api_v1_ranges__range_id__proxmox_execution_request_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                range_id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["ProxmoxExecutionRequest"];
            };
        };
        responses: {
            /** @description Successful Response */
            202: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ProxmoxCommandOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    get_proxmox_observation_api_v1_ranges__range_id__proxmox_observation_get: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                range_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ProxmoxObservationOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    get_proxmox_ownership_api_v1_ranges__range_id__proxmox_ownership_get: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                range_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ProxmoxOwnershipOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    get_proxmox_plan_api_v1_ranges__range_id__proxmox_plan_get: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                range_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ProxmoxPlanOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    approve_proxmox_plan_api_v1_ranges__range_id__proxmox_plan_approval_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                range_id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["ProxmoxPlanApprovalRequest"];
            };
        };
        responses: {
            /** @description Successful Response */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ProxmoxPlanOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    generate_proxmox_plan_api_v1_ranges__range_id__proxmox_plan_generation_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                range_id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["ProxmoxGeneratePlanRequest"];
            };
        };
        responses: {
            /** @description Successful Response */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ProxmoxCommandOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    submit_proxmox_plan_for_review_api_v1_ranges__range_id__proxmox_plan_review_submission_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                range_id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["ProxmoxSubmitPlanRequest"];
            };
        };
        responses: {
            /** @description Successful Response */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ProxmoxCommandOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    get_proxmox_readiness_api_v1_ranges__range_id__proxmox_readiness_get: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                range_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ProxmoxReadinessOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    get_proxmox_reconciliation_api_v1_ranges__range_id__proxmox_reconciliation_get: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                range_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ProxmoxReconciliationOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    request_proxmox_reconciliation_api_v1_ranges__range_id__proxmox_reconciliation_request_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                range_id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["ProxmoxReconciliationRequest"];
            };
        };
        responses: {
            /** @description Successful Response */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ProxmoxCommandOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    get_proxmox_reset_authorization_api_v1_ranges__range_id__proxmox_reset_authorization_get: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                range_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ProxmoxResetAuthorizationOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    authorize_proxmox_reset_api_v1_ranges__range_id__proxmox_reset_authorization_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                range_id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["ProxmoxResetAuthorizationRequest"];
            };
        };
        responses: {
            /** @description Successful Response */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ProxmoxResetAuthorizationOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    get_proxmox_reset_dispositions_api_v1_ranges__range_id__proxmox_reset_dispositions_get: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                range_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ProxmoxResetDispositionsOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    get_proxmox_reset_plan_api_v1_ranges__range_id__proxmox_reset_plan_get: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                range_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ProxmoxResetPlanOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    approve_proxmox_reset_plan_api_v1_ranges__range_id__proxmox_reset_plan_approval_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                range_id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["ProxmoxResetPlanApprovalRequest"];
            };
        };
        responses: {
            /** @description Successful Response */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ProxmoxResetAuthorizationOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    request_proxmox_reset_api_v1_ranges__range_id__proxmox_reset_request_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                range_id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["ProxmoxResetRequest"];
            };
        };
        responses: {
            /** @description Successful Response */
            202: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ProxmoxCommandOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    get_proxmox_residue_api_v1_ranges__range_id__proxmox_residue_get: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                range_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ProxmoxResidueOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    get_proxmox_topology_api_v1_ranges__range_id__proxmox_topology_get: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                range_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ProxmoxTopologyOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    compile_proxmox_topology_api_v1_ranges__range_id__proxmox_topology_compilation_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                range_id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["ProxmoxCompileTopologyRequest"];
            };
        };
        responses: {
            /** @description Successful Response */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ProxmoxCommandOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    get_proxmox_verification_api_v1_ranges__range_id__proxmox_verification_get: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                range_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ProxmoxVerificationOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    get_proxmox_worker_api_v1_ranges__range_id__proxmox_worker_get: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                range_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ProxmoxWorkerOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    get_proxmox_workload_api_v1_ranges__range_id__proxmox_workload_get: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                range_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ProxmoxWorkloadOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    reset_range_api_v1_ranges__range_id__reset_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                range_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            202: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["RangeOperationOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    list_range_resources_api_v1_ranges__range_id__resources_get: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                range_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["RangeResourceOut"][];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    get_range_scenario_for_range_api_v1_ranges__range_id__scenario_get: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                range_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ScenarioOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    get_range_scoreboard_api_v1_ranges__range_id__scoreboard_get: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                range_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ScoreboardOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    list_range_teams_api_v1_ranges__range_id__teams_get: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                range_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["TeamOut"][];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    create_range_team_api_v1_ranges__range_id__teams_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                range_id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["TeamCreate"];
            };
        };
        responses: {
            /** @description Successful Response */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["TeamOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    list_range_team_members_api_v1_ranges__range_id__teams__team_id__members_get: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                range_id: string;
                team_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["TeamMemberOut"][];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    add_range_team_member_api_v1_ranges__range_id__teams__team_id__members_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                range_id: string;
                team_id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["TeamMemberCreate"];
            };
        };
        responses: {
            /** @description Successful Response */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["TeamMemberOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    remove_range_team_member_api_v1_ranges__range_id__teams__team_id__members__member_id__delete: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                member_id: string;
                range_id: string;
                team_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            204: {
                headers: {
                    [name: string]: unknown;
                };
                content?: never;
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    list_range_teardown_evidence_api_v1_ranges__range_id__teardown_evidence_get: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                range_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["TeardownEvidenceOut"][];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    list_preflights_api_v1_readonly_preflight_get: {
        parameters: {
            query: {
                execution_target_id: string;
            };
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ReadonlyPreflightOut"][];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    queue_preflight_api_v1_readonly_preflight_post: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["QueuePreflight"];
            };
        };
        responses: {
            /** @description Successful Response */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ReadonlyPreflightOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    get_preflight_api_v1_readonly_preflight__preflight_id__get: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                preflight_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ReadonlyPreflightOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    list_authorizations_api_v1_readonly_preflight_authorizations_get: {
        parameters: {
            query: {
                execution_target_id: string;
            };
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["PreflightAuthorizationOut"][];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    create_authorization_api_v1_readonly_preflight_authorizations_post: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["CreatePreflightAuthorization"];
            };
        };
        responses: {
            /** @description Successful Response */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["PreflightAuthorizationOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    approve_authorization_api_v1_readonly_preflight_authorizations__authorization_id__approve_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                authorization_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["PreflightAuthorizationOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    revoke_authorization_api_v1_readonly_preflight_authorizations__authorization_id__revoke_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                authorization_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["PreflightAuthorizationOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    list_substrates_api_v1_readonly_preflight_substrates_get: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["PreflightSubstrateOut"][];
                };
            };
        };
    };
    list_authorizations_api_v1_resolver_activation_authorizations_get: {
        parameters: {
            query: {
                execution_target_id: string;
            };
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ResolverActivationOut"][];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    create_authorization_api_v1_resolver_activation_authorizations_post: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["CreateResolverActivation"];
            };
        };
        responses: {
            /** @description Successful Response */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ResolverActivationOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    get_authorization_api_v1_resolver_activation_authorizations__authorization_id__get: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                authorization_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ResolverActivationOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    approve_authorization_api_v1_resolver_activation_authorizations__authorization_id__approve_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                authorization_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ResolverActivationOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    record_evidence_api_v1_resolver_activation_authorizations__authorization_id__evidence_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                authorization_id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["RecordResolverActivationEvidence"];
            };
        };
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ResolverActivationOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    revoke_authorization_api_v1_resolver_activation_authorizations__authorization_id__revoke_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                authorization_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ResolverActivationOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    get_snapshot_api_v1_snapshots__snapshot_id__get: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                snapshot_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["SnapshotOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    list_snapshot_resources_api_v1_snapshots__snapshot_id__resources_get: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                snapshot_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ResourceOut"][];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    list_deployments_api_v1_staging_deployments_get: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["DeploymentOut"][];
                };
            };
        };
    };
    create_deployment_api_v1_staging_deployments_post: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["DeploymentCreate"];
            };
        };
        responses: {
            /** @description Successful Response */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["DeploymentOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    get_deployment_api_v1_staging_deployments__deployment_id__get: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                deployment_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["DeploymentOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    approve_deployment_api_v1_staging_deployments__deployment_id__approve_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                deployment_id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["DeploymentApprove"];
            };
        };
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["DeploymentOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    get_bootstrap_availability_api_v1_staging_deployments__deployment_id__bootstrap_availability_get: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                deployment_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["BootstrapAvailabilityOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    deploy_api_v1_staging_deployments__deployment_id__deploy_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                deployment_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["DeploymentOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    get_plan_api_v1_staging_deployments__deployment_id__plan_get: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                deployment_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["DeploymentPlanOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    generate_plan_api_v1_staging_deployments__deployment_id__plan_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                deployment_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["DeploymentOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    reject_deployment_api_v1_staging_deployments__deployment_id__reject_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                deployment_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["DeploymentOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    list_resources_api_v1_staging_deployments__deployment_id__resources_get: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                deployment_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["DeploymentResourceOut"][];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    submit_for_approval_api_v1_staging_deployments__deployment_id__submit_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                deployment_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["DeploymentOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    request_teardown_api_v1_staging_deployments__deployment_id__teardown_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                deployment_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["DeploymentOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    list_verifications_api_v1_staging_deployments__deployment_id__verifications_get: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                deployment_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["DeploymentVerificationOut"][];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    list_staging_labs_api_v1_staging_labs_get: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["StagingLabOut"][];
                };
            };
        };
    };
    create_staging_lab_api_v1_staging_labs_post: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["StagingLabCreate"];
            };
        };
        responses: {
            /** @description Successful Response */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["StagingLabOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    get_staging_lab_api_v1_staging_labs__lab_id__get: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                lab_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["StagingLabOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    approve_staging_lab_api_v1_staging_labs__lab_id__approve_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                lab_id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["StagingLabApprove"];
            };
        };
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["StagingLabOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    generate_plan_api_v1_staging_labs__lab_id__plan_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                lab_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["StagingLabOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    reject_staging_lab_api_v1_staging_labs__lab_id__reject_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                lab_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["StagingLabOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    queue_simulation_api_v1_staging_labs__lab_id__simulate_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                lab_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["StagingLabOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    submit_for_approval_api_v1_staging_labs__lab_id__submit_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                lab_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["StagingLabOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    queue_teardown_api_v1_staging_labs__lab_id__teardown_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                lab_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["StagingLabOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    list_work_items_api_v1_staging_labs__lab_id__work_items_get: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                lab_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["StagingLabWorkItemOut"][];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    list_eligible_substrates_api_v1_staging_labs_eligible_substrates_get: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["EligibleSubstrateOut"][];
                };
            };
        };
    };
    list_enrollments_api_v1_target_discovery_get: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["EnrollmentOut"][];
                };
            };
        };
    };
    request_discovery_api_v1_target_discovery_post: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["DiscoveryRequest"];
            };
        };
        responses: {
            /** @description Successful Response */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["EnrollmentOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    get_enrollment_api_v1_target_discovery__enrollment_id__get: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                enrollment_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["EnrollmentOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    get_apply_status_api_v1_target_discovery__enrollment_id__apply_status_get: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                enrollment_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["SealedApplyNoticeOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    approve_candidate_plan_api_v1_target_discovery__enrollment_id__approve_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                enrollment_id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["DiscoveryApprove"];
            };
        };
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["EnrollmentOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    get_bootstrap_availability_api_v1_target_discovery__enrollment_id__bootstrap_availability_get: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                enrollment_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["DiscoveryBootstrapAvailabilityOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    get_candidate_plan_api_v1_target_discovery__enrollment_id__candidate_plan_get: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                enrollment_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["CandidatePlanOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    get_evidence_api_v1_target_discovery__enrollment_id__evidence_get: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                enrollment_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["DiscoveryEvidenceOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    reject_candidate_plan_api_v1_target_discovery__enrollment_id__reject_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                enrollment_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["EnrollmentOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    rerun_discovery_api_v1_target_discovery__enrollment_id__rerun_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                enrollment_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["EnrollmentOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    get_binding_descriptor_api_v1_target_discovery_read_only_bootstrap_enrollments__enrollment_id__binding_descriptor_get: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                enrollment_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["BindingDescriptorOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    get_bundle_descriptor_api_v1_target_discovery_read_only_bootstrap_enrollments__enrollment_id__bundle_descriptor_get: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                enrollment_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["BundleDescriptorOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    get_discovery_readiness_api_v1_target_discovery_read_only_bootstrap_enrollments__enrollment_id__readiness_get: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                enrollment_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["DiscoveryReadinessOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    list_sessions_api_v1_target_discovery_read_only_bootstrap_sessions_get: {
        parameters: {
            query?: {
                execution_target_id?: string | null;
            };
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["BootstrapSessionOut"][];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    create_session_api_v1_target_discovery_read_only_bootstrap_sessions_post: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["BootstrapSessionCreate"];
            };
        };
        responses: {
            /** @description Successful Response */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["BootstrapSessionOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    get_session_api_v1_target_discovery_read_only_bootstrap_sessions__session_id__get: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                session_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["BootstrapSessionOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    bind_session_api_v1_target_discovery_read_only_bootstrap_sessions__session_id__bind_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                session_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["BootstrapSessionOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    complete_session_api_v1_target_discovery_read_only_bootstrap_sessions__session_id__complete_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                session_id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["BootstrapCompleteRequest"];
            };
        };
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["BootstrapSessionOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    get_script_api_v1_target_discovery_read_only_bootstrap_sessions__session_id__script_get: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                session_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["BootstrapScriptOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    grant_substrate_eligibility_api_v1_target_discovery_read_only_bootstrap_targets__execution_target_id__substrate_eligibility_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                execution_target_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["SubstrateEligibilityGrantOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    list_worker_nodes_api_v1_target_discovery_read_only_bootstrap_worker_nodes_get: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["WorkerNodeOut"][];
                };
            };
        };
    };
    register_worker_node_api_v1_target_discovery_read_only_bootstrap_worker_nodes_post: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["WorkerNodeRegisterRequest"];
            };
        };
        responses: {
            /** @description Successful Response */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["WorkerNodeOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    get_worker_node_api_v1_target_discovery_read_only_bootstrap_worker_nodes__node_id__get: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                node_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["WorkerNodeOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    approve_and_link_worker_identity_api_v1_target_discovery_read_only_bootstrap_worker_nodes__node_id__identity_approval_link_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                node_id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["WorkerNodeIdentityApprovalLinkRequest"];
            };
        };
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["WorkerNodeOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    list_targets_api_v1_targets_get: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["TargetOut"][];
                };
            };
        };
    };
    register_target_api_v1_targets_post: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["TargetCreate"];
            };
        };
        responses: {
            /** @description Successful Response */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["TargetOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    get_target_api_v1_targets__target_id__get: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                target_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["TargetOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    list_address_spaces_api_v1_targets__target_id__address_spaces_get: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                target_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["AddressSpaceOut"][];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    disable_target_api_v1_targets__target_id__disable_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                target_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["TargetOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    request_discovery_api_v1_targets__target_id__discover_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                target_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            202: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["SnapshotOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    list_onboardings_api_v1_targets__target_id__onboarding_get: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                target_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["OnboardingOut"][];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    create_onboarding_api_v1_targets__target_id__onboarding_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                target_id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["OnboardingCreate"];
            };
        };
        responses: {
            /** @description Successful Response */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["OnboardingOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    list_reservations_api_v1_targets__target_id__reservations_get: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                target_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ReservationOut"][];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    rotate_target_credential_api_v1_targets__target_id__rotate_credential_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                target_id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["TargetCredentialRotate"];
            };
        };
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["TargetOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    rotate_target_operation_credential_api_v1_targets__target_id__rotate_operation_credential_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                target_id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["TargetOperationCredentialRotate"];
            };
        };
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["TargetOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    list_snapshots_api_v1_targets__target_id__snapshots_get: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                target_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["SnapshotOut"][];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    list_toolchain_profiles_api_v1_targets__target_id__toolchain_profiles_get: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                target_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ToolchainProfileOut"][];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    register_toolchain_profile_api_v1_targets__target_id__toolchain_profiles_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                target_id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["ToolchainProfileCreate"];
            };
        };
        responses: {
            /** @description Successful Response */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ToolchainProfileOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    list_templates_api_v1_templates_get: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["TemplateOut"][];
                };
            };
        };
    };
    create_template_api_v1_templates_post: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["TemplateCreate"];
            };
        };
        responses: {
            /** @description Successful Response */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["TemplateOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    list_versions_api_v1_templates__template_id__versions_get: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                template_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["VersionOut"][];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    create_version_api_v1_templates__template_id__versions_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                template_id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["VersionCreate"];
            };
        };
        responses: {
            /** @description Successful Response */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["VersionOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    get_toolchain_profile_api_v1_toolchain_profiles__profile_id__get: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                profile_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ToolchainProfileOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    disable_toolchain_profile_api_v1_toolchain_profiles__profile_id__disable_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                profile_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ToolchainProfileOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    create_draft_api_v1_topology_authoring_documents_post: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["TopologyDraftCreate"];
            };
        };
        responses: {
            /** @description Successful Response */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["TopologyDocumentDetailOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    get_document_api_v1_topology_authoring_documents__document_id__get: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                document_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["TopologyDocumentDetailOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    list_revisions_api_v1_topology_authoring_documents__document_id__revisions_get: {
        parameters: {
            query?: {
                limit?: number;
                offset?: number;
            };
            header?: never;
            path: {
                document_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["TopologyRevisionOut"][];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    create_revision_api_v1_topology_authoring_documents__document_id__revisions_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                document_id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["TopologyRevisionCreate"];
            };
        };
        responses: {
            /** @description Successful Response */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["TopologyRevisionDetailOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    get_revision_api_v1_topology_authoring_documents__document_id__revisions__revision_id__get: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                document_id: string;
                revision_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["TopologyRevisionDetailOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    approve_revision_api_v1_topology_authoring_documents__document_id__revisions__revision_id__approve_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                document_id: string;
                revision_id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["TopologyDecision"];
            };
        };
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["TopologyRevisionOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    reject_revision_api_v1_topology_authoring_documents__document_id__revisions__revision_id__reject_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                document_id: string;
                revision_id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["TopologyDecision"];
            };
        };
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["TopologyRevisionOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    submit_revision_api_v1_topology_authoring_documents__document_id__revisions__revision_id__submit_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                document_id: string;
                revision_id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["TopologyHashPin"];
            };
        };
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["TopologyRevisionOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    validate_revision_api_v1_topology_authoring_documents__document_id__revisions__revision_id__validate_post: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                document_id: string;
                revision_id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["TopologyHashPin"];
            };
        };
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["TopologyValidationOut"];
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    get_validation_api_v1_topology_authoring_documents__document_id__revisions__revision_id__validation_get: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                document_id: string;
                revision_id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["TopologyValidationOut"] | null;
                };
            };
            /** @description Validation Error */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HTTPValidationError"];
                };
            };
        };
    };
    health_health_get: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Successful Response */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": {
                        [key: string]: unknown;
                    };
                };
            };
        };
    };
}
