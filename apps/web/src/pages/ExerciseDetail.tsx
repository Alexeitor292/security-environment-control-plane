import "./environments.css";

import { Link, useNavigate, useParams } from "react-router-dom";

import { api } from "../api/client";
import { CyberGridBackground } from "../components/backgrounds";
import {
  CyberButton,
  CyberCard,
  CyberTable,
  EmptyState,
  HashChip,
  KeyValueList,
  SafetyNotice,
  Skeleton,
  StatusBadge,
  StepRail,
  shortId,
  useAction,
} from "../components/ui";
import { useAsync } from "../hooks";
import {
  DEPLOY_DISPATCH_NOTE,
  DESTROY_DISPATCH_NOTE,
  ENVIRONMENTS_ERROR_TEXT,
  SIMULATED_POSTURE_NOTE,
  canDeployExercise,
  canDestroyExercise,
  canGeneratePlan,
  canResetInstance,
  canValidateExercise,
  exerciseRailItems,
  exerciseStatusLabel,
  isExerciseOffRail,
  onlyNotFoundAsNull,
} from "./environments-view";

export function ExerciseDetail() {
  const { exerciseId = "" } = useParams();
  const navigate = useNavigate();
  const exercise = useAsync(() => api.getExercise(exerciseId), [exerciseId]);
  const instances = useAsync(() => api.listInstances(exerciseId), [exerciseId]);
  // Only a not_found means "no plan generated"; other failures render as
  // unavailable, never as absence.
  const plan = useAsync(
    () => api.latestPlan(exerciseId).catch(onlyNotFoundAsNull),
    [exerciseId],
  );
  const action = useAction({ codeText: ENVIRONMENTS_ERROR_TEXT });

  function reloadAll() {
    exercise.reload();
    instances.reload();
    plan.reload();
  }

  if (exercise.error !== null && exercise.error !== undefined)
    return (
      <div className="error-box" role="alert">
        Exercise unavailable.
      </div>
    );
  if (!exercise.data)
    return (
      <CyberCard>
        <Skeleton lines={5} />
      </CyberCard>
    );

  const ex = exercise.data;
  const state = ex.lifecycle_state;
  const planData = plan.data ?? null;
  const planUnavailable = plan.error !== null && plan.error !== undefined;
  const offRail = isExerciseOffRail(state);

  return (
    <div className="env">
      <CyberGridBackground intensity="subtle" className="env-bg" />
      <div className="env-head">
        <div>
          <h1>{ex.name}</h1>
          <p className="env-sub mono">
            version {shortId(ex.environment_version_id)} · {ex.team_count} teams ·
            created {ex.created_at.slice(0, 10)}
          </p>
        </div>
        <span className="env-hashline">
          <StatusBadge state={state} domain="lifecycle" />
          <span className="muted">{exerciseStatusLabel(state)}</span>
        </span>
      </div>

      <SafetyNotice role="note" tone="warn">
        {SIMULATED_POSTURE_NOTE} Lifecycle reflects recorded state only — the API
        dispatches work; it never contacts infrastructure.
      </SafetyNotice>

      {action.error && (
        <div className="error-box" role="alert">
          {action.error.text} <code className="mono">{action.error.code}</code>
        </div>
      )}

      <div className="env-grid">
        <CyberCard heading="Lifecycle">
          <StepRail items={exerciseRailItems(state)} aria-label="Exercise lifecycle" />
          {offRail && (
            <SafetyNotice
              role="status"
              // failed is danger; in-progress dispatched work (resetting/
              // destroying) is warn; destroyed is a terminal recorded fact.
              tone={
                state === "failed" ? "danger" : state === "destroyed" ? "info" : "warn"
              }
            >
              Current state: {exerciseStatusLabel(state)}
            </SafetyNotice>
          )}
          <div className="env-actions" style={{ marginTop: 10 }}>
            <CyberButton
              variant="secondary"
              size="sm"
              disabled={action.busy || !canValidateExercise(state)}
              title={
                canValidateExercise(state)
                  ? "Validates the exercise definition. Validation is not approval."
                  : `Available while draft — current: ${exerciseStatusLabel(state)}`
              }
              onClick={() => action.run(() => api.validateExercise(ex.id), reloadAll)}
            >
              Validate
            </CyberButton>
            <CyberButton
              variant="secondary"
              size="sm"
              disabled={action.busy || !canGeneratePlan(state)}
              title={
                canGeneratePlan(state)
                  ? "Generates a deterministic plan pinned to the version hash. Generation is not approval."
                  : `Available when validated — current: ${exerciseStatusLabel(state)}`
              }
              onClick={() => action.run(() => api.generatePlan(ex.id), reloadAll)}
            >
              Generate plan
            </CyberButton>
            <CyberButton
              variant="secondary"
              size="sm"
              disabled={!planData}
              onClick={() => navigate(`/exercises/${ex.id}/plan`)}
            >
              Plan review & decision →
            </CyberButton>
            <CyberButton
              size="sm"
              disabled={action.busy || !canDeployExercise(state)}
              title={
                canDeployExercise(state)
                  ? DEPLOY_DISPATCH_NOTE
                  : `Available when a plan is approved — current: ${exerciseStatusLabel(state)}`
              }
              onClick={() => action.run(() => api.deployExercise(ex.id), reloadAll)}
            >
              Dispatch simulated deploy
            </CyberButton>
          </div>
          <p className="env-note">
            Deploy is refused until a plan is explicitly approved (approval gate).{" "}
            {DEPLOY_DISPATCH_NOTE}
          </p>
        </CyberCard>

        <CyberCard heading="Deployment plan (immutable)">
          {planUnavailable ? (
            <p className="muted">Plan status unavailable.</p>
          ) : !planData ? (
            <EmptyState title="No plan generated yet">
              Generate a plan after validation. Plans are deterministic and
              pinned to the immutable version hash.
            </EmptyState>
          ) : (
            <>
              <div className="env-hashline">
                <StatusBadge state={planData.status} domain="plan" />
                <span>
                  pinned to <HashChip value={planData.version_content_hash} digits={12} />
                </span>
              </div>
              <KeyValueList
                items={[
                  {
                    key: "Shape",
                    value: `${planData.summary.total_nodes} nodes · ${planData.summary.total_networks} networks · ${planData.summary.isolation} isolation`,
                  },
                  { key: "Plugin", value: planData.summary.plugin || "—", mono: true },
                  {
                    key: "Approved hash",
                    value: planData.approved_content_hash ? (
                      <HashChip value={planData.approved_content_hash} digits={12} />
                    ) : (
                      "— (no decision recorded)"
                    ),
                  },
                ]}
              />
              <p className="env-note">
                <Link to={`/exercises/${ex.id}/plan`}>Open plan review →</Link>
              </p>
            </>
          )}
        </CyberCard>
      </div>

      <CyberCard heading="Team instances (simulated)">
        <div className="env-actions" style={{ marginBottom: 8 }}>
          <CyberButton
            variant="secondary"
            size="sm"
            disabled={!instances.data?.length}
            onClick={() => navigate(`/exercises/${ex.id}/topology`)}
          >
            Topology preview →
          </CyberButton>
          <CyberButton
            variant="danger"
            size="sm"
            disabled={action.busy || !canDestroyExercise(state)}
            title={
              canDestroyExercise(state)
                ? DESTROY_DISPATCH_NOTE
                : `Available while running or failed — current: ${exerciseStatusLabel(state)}`
            }
            onClick={() => action.run(() => api.destroyExercise(ex.id), reloadAll)}
          >
            Dispatch destroy
          </CyberButton>
        </div>
        {instances.loading && !instances.data ? (
          <Skeleton lines={3} />
        ) : instances.data && instances.data.length === 0 ? (
          <EmptyState title="No instances yet">
            Instances appear per team after deployment work runs. Dispatching a
            deploy does not create them by itself.
          </EmptyState>
        ) : instances.data ? (
          <CyberTable
            label="Team instances"
            head={["Team", "Instance", "Lifecycle", "Provider", "Actions"]}
            caption={`${instances.data.length} team instance${instances.data.length === 1 ? "" : "s"} · simulated execution only`}
          >
            {instances.data.map((inst) => (
              <tr key={inst.id}>
                <td>{inst.team_ref}</td>
                <td className="mono muted" title={inst.instance_ref}>
                  {shortId(inst.instance_ref)}
                </td>
                <td>
                  <StatusBadge state={inst.lifecycle_state} domain="lifecycle" />
                </td>
                <td className="mono muted">{inst.provider} · simulated</td>
                <td>
                  <CyberButton
                    variant="secondary"
                    size="sm"
                    disabled={action.busy || !canResetInstance(inst)}
                    title={
                      canResetInstance(inst)
                        ? "Dispatches reset work for this instance."
                        : "Available while the instance is running."
                    }
                    onClick={() =>
                      action.run(() => api.resetInstance(ex.id, inst.id), reloadAll)
                    }
                  >
                    Reset
                  </CyberButton>
                </td>
              </tr>
            ))}
          </CyberTable>
        ) : (
          <p className="muted">Instances unavailable.</p>
        )}
        <p className="env-note">{DESTROY_DISPATCH_NOTE}</p>
      </CyberCard>

      <p className="env-note">
        <Link to="/audit">Full audit ledger →</Link>
      </p>
    </div>
  );
}
