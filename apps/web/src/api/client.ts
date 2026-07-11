// Thin typed API client over the control-plane REST API.

import type {
  AuditEvent,
  BindingDescriptor,
  BootstrapCompleteRequest,
  BootstrapScript,
  BootstrapSession,
  BootstrapSessionCreate,
  DeploymentPlan,
  ExecutionTarget,
  Exercise,
  Instance,
  InventoryResource,
  InventorySnapshot,
  Onboarding,
  OnboardingCreate,
  PluginInfo,
  EligibleSubstrate,
  Preflight,
  PreflightAuthorization,
  PreflightSubstrate,
  Principal,
  ReadonlyPreflight,
  ResolverActivation,
  TopologyDocumentDetail,
  TopologyRevisionDetail,
  TopologyRevisionSummary,
  TopologyValidationResult,
  ProviderCapabilities,
  StagingLab,
  StagingLabCreate,
  StagingDeployment,
  StagingDeploymentCreate,
  StagingDeploymentPlan,
  StagingDeploymentResourceRecord,
  StagingDeploymentVerificationRecord,
  BootstrapAvailability,
  DiscoveryEnrollment,
  DiscoveryRequest,
  DiscoveryEvidence,
  DiscoveryCandidatePlan,
  DiscoveryApplyNotice,
  TargetCreate,
  TargetEvidence,
  TeamTopology,
  Template,
  Version,
  WorkflowRun,
  WorkerDiscoveryNode,
  DiscoveryReadiness,
  SubstrateEligibilityGrant,
} from "./types";

export const API_BASE =
  (import.meta.env && import.meta.env.VITE_API_BASE_URL) || "http://localhost:8080";

export class ApiClientError extends Error {
  code: string;
  details?: string[];
  status: number;
  constructor(status: number, code: string, message: string, details?: string[]) {
    super(message);
    this.status = status;
    this.code = code;
    this.details = details;
  }
}

export function buildUrl(path: string, params?: Record<string, string>): string {
  const url = new URL(path.replace(/^\//, ""), API_BASE.replace(/\/?$/, "/"));
  if (params) {
    for (const [k, v] of Object.entries(params)) url.searchParams.set(k, v);
  }
  return url.toString();
}

async function request<T>(
  method: string,
  path: string,
  body?: unknown,
  params?: Record<string, string>,
): Promise<T> {
  let res: Response;
  try {
    res = await fetch(buildUrl(path, params), {
      method,
      headers: body ? { "Content-Type": "application/json" } : {},
      body: body ? JSON.stringify(body) : undefined,
    });
  } catch {
    // A network-level failure (server unreachable, offline, CORS) — surface a clear, safe message
    // instead of leaking the browser's raw "Failed to fetch" TypeError to the UI.
    throw new ApiClientError(
      0,
      "api_unreachable",
      `Cannot reach the API at ${API_BASE}. Check that the backend is running and reachable.`,
    );
  }
  const text = await res.text();
  let payload: { error?: { code?: string; message?: string; details?: string[] } } | null = null;
  try {
    payload = text ? JSON.parse(text) : null;
  } catch {
    // A non-JSON body (e.g. a proxy error page) must not crash the client with a parse error.
    if (!res.ok) {
      throw new ApiClientError(res.status, "error", res.statusText || "request failed");
    }
  }
  if (!res.ok) {
    const err = payload?.error ?? {};
    throw new ApiClientError(
      res.status,
      err.code ?? "error",
      err.message ?? res.statusText,
      err.details,
    );
  }
  return payload as T;
}

export const api = {
  me: () => request<Principal>("GET", "/api/v1/me"),
  plugins: () => request<PluginInfo[]>("GET", "/api/v1/plugins"),

  listTemplates: () => request<Template[]>("GET", "/api/v1/templates"),
  createTemplate: (body: { name: string; slug: string; display_name?: string; description?: string }) =>
    request<Template>("POST", "/api/v1/templates", body),
  listVersions: (templateId: string) =>
    request<Version[]>("GET", `/api/v1/templates/${templateId}/versions`),
  createVersion: (templateId: string, definition: unknown) =>
    request<Version>("POST", `/api/v1/templates/${templateId}/versions`, { definition }),
  validateDefinition: (definition: unknown) =>
    request<{ ok: boolean; errors: string[]; warnings: string[] }>(
      "POST",
      "/api/v1/definitions/validate",
      { definition },
    ),

  listExercises: () => request<Exercise[]>("GET", "/api/v1/exercises"),
  createExercise: (body: { template_id: string; version_id: string; name: string }) =>
    request<Exercise>("POST", "/api/v1/exercises", body),
  getExercise: (id: string) => request<Exercise>("GET", `/api/v1/exercises/${id}`),
  listInstances: (id: string) =>
    request<Instance[]>("GET", `/api/v1/exercises/${id}/instances`),
  validateExercise: (id: string) =>
    request<Exercise>("POST", `/api/v1/exercises/${id}/validate`),
  deployExercise: (id: string) =>
    request<WorkflowRun>("POST", `/api/v1/exercises/${id}/deploy`),
  resetInstance: (exerciseId: string, instanceId: string) =>
    request<WorkflowRun>(
      "POST",
      `/api/v1/exercises/${exerciseId}/instances/${instanceId}/reset`,
    ),
  destroyExercise: (id: string) =>
    request<WorkflowRun>("POST", `/api/v1/exercises/${id}/destroy`),

  generatePlan: (exerciseId: string) =>
    request<DeploymentPlan>("POST", `/api/v1/exercises/${exerciseId}/plan`),
  latestPlan: (exerciseId: string) =>
    request<DeploymentPlan>("GET", `/api/v1/exercises/${exerciseId}/plan`),
  submitPlan: (planId: string) =>
    request<DeploymentPlan>("POST", `/api/v1/plans/${planId}/submit`),
  approvePlan: (planId: string, reason: string) =>
    request<DeploymentPlan>("POST", `/api/v1/plans/${planId}/approve`, { reason }),
  rejectPlan: (planId: string, reason: string) =>
    request<DeploymentPlan>("POST", `/api/v1/plans/${planId}/reject`, { reason }),

  exerciseTopology: (id: string) =>
    request<TeamTopology[]>("GET", `/api/v1/exercises/${id}/topology`),

  audit: (exerciseId?: string) =>
    request<AuditEvent[]>(
      "GET",
      "/api/v1/audit",
      undefined,
      exerciseId ? { exercise_id: exerciseId } : undefined,
    ),

  // --- Provider Targets (SECP-002A) ---
  providerCapabilities: () =>
    request<ProviderCapabilities>("GET", "/api/v1/providers/capabilities"),
  listTargets: () => request<ExecutionTarget[]>("GET", "/api/v1/targets"),
  registerTarget: (body: TargetCreate) =>
    request<ExecutionTarget>("POST", "/api/v1/targets", body),
  getTarget: (id: string) => request<ExecutionTarget>("GET", `/api/v1/targets/${id}`),
  disableTarget: (id: string) =>
    request<ExecutionTarget>("POST", `/api/v1/targets/${id}/disable`),
  listSnapshots: (targetId: string) =>
    request<InventorySnapshot[]>("GET", `/api/v1/targets/${targetId}/snapshots`),
  requestDiscovery: (targetId: string) =>
    request<InventorySnapshot>("POST", `/api/v1/targets/${targetId}/discover`),
  snapshotResources: (snapshotId: string) =>
    request<InventoryResource[]>("GET", `/api/v1/snapshots/${snapshotId}/resources`),

  // --- Target Onboarding (SECP-002B-1B-0 / 0.1) ---
  listOnboardings: (targetId: string) =>
    request<Onboarding[]>("GET", `/api/v1/targets/${targetId}/onboarding`),
  createOnboarding: (targetId: string, body: OnboardingCreate) =>
    request<Onboarding>("POST", `/api/v1/targets/${targetId}/onboarding`, body),
  getOnboarding: (id: string) => request<Onboarding>("GET", `/api/v1/onboarding/${id}`),
  requestPreflight: (id: string) =>
    request<Preflight>("POST", `/api/v1/onboarding/${id}/preflight`),
  listPreflights: (id: string) =>
    request<Preflight[]>("GET", `/api/v1/onboarding/${id}/preflight`),
  listTargetEvidence: (id: string) =>
    request<TargetEvidence[]>("GET", `/api/v1/onboarding/${id}/evidence`),
  submitOnboarding: (id: string) =>
    request<Onboarding>("POST", `/api/v1/onboarding/${id}/submit`),
  approveOnboarding: (id: string, reason: string) =>
    request<Onboarding>("POST", `/api/v1/onboarding/${id}/approve`, { reason }),
  rejectOnboarding: (id: string, reason: string) =>
    request<Onboarding>("POST", `/api/v1/onboarding/${id}/reject`, { reason }),
  activateOnboarding: (id: string) =>
    request<Onboarding>("POST", `/api/v1/onboarding/${id}/activate`),
  retireOnboarding: (id: string) =>
    request<Onboarding>("POST", `/api/v1/onboarding/${id}/retire`),

  // Declarative disposable staging lab (SECP-002B-1B-9, fake simulation only; queue-only).
  listEligibleSubstrates: () =>
    request<EligibleSubstrate[]>("GET", "/api/v1/staging-labs/eligible-substrates"),
  listStagingLabs: () => request<StagingLab[]>("GET", "/api/v1/staging-labs"),
  createStagingLab: (body: StagingLabCreate) =>
    request<StagingLab>("POST", "/api/v1/staging-labs", body),
  getStagingLab: (id: string) => request<StagingLab>("GET", `/api/v1/staging-labs/${id}`),
  planStagingLab: (id: string) =>
    request<StagingLab>("POST", `/api/v1/staging-labs/${id}/plan`),
  submitStagingLab: (id: string) =>
    request<StagingLab>("POST", `/api/v1/staging-labs/${id}/submit`),
  approveStagingLab: (id: string, expectedPlanHash: string) =>
    request<StagingLab>("POST", `/api/v1/staging-labs/${id}/approve`, {
      expected_plan_hash: expectedPlanHash,
    }),
  rejectStagingLab: (id: string) =>
    request<StagingLab>("POST", `/api/v1/staging-labs/${id}/reject`),
  // These QUEUE fake work only; a worker records completion later.
  queueStagingLabSimulation: (id: string) =>
    request<StagingLab>("POST", `/api/v1/staging-labs/${id}/simulate`),
  queueStagingLabTeardown: (id: string) =>
    request<StagingLab>("POST", `/api/v1/staging-labs/${id}/teardown`),

  // Real app-owned isolated staging-lab deployment (SECP-B4). The API enqueues durable work only;
  // it contacts no infrastructure. A worker executes an approved plan after re-verifying it.
  listStagingDeployments: () =>
    request<StagingDeployment[]>("GET", "/api/v1/staging-deployments"),
  createStagingDeployment: (body: StagingDeploymentCreate) =>
    request<StagingDeployment>("POST", "/api/v1/staging-deployments", body),
  getStagingDeployment: (id: string) =>
    request<StagingDeployment>("GET", `/api/v1/staging-deployments/${id}`),
  getStagingDeploymentPlan: (id: string) =>
    request<StagingDeploymentPlan>("GET", `/api/v1/staging-deployments/${id}/plan`),
  listStagingDeploymentResources: (id: string) =>
    request<StagingDeploymentResourceRecord[]>(
      "GET",
      `/api/v1/staging-deployments/${id}/resources`,
    ),
  listStagingDeploymentVerifications: (id: string) =>
    request<StagingDeploymentVerificationRecord[]>(
      "GET",
      `/api/v1/staging-deployments/${id}/verifications`,
    ),
  getStagingDeploymentBootstrapAvailability: (id: string) =>
    request<BootstrapAvailability>(
      "GET",
      `/api/v1/staging-deployments/${id}/bootstrap-availability`,
    ),
  planStagingDeployment: (id: string) =>
    request<StagingDeployment>("POST", `/api/v1/staging-deployments/${id}/plan`),
  submitStagingDeployment: (id: string) =>
    request<StagingDeployment>("POST", `/api/v1/staging-deployments/${id}/submit`),
  approveStagingDeployment: (id: string, expectedPlanHash: string) =>
    request<StagingDeployment>("POST", `/api/v1/staging-deployments/${id}/approve`, {
      expected_plan_hash: expectedPlanHash,
    }),
  rejectStagingDeployment: (id: string) =>
    request<StagingDeployment>("POST", `/api/v1/staging-deployments/${id}/reject`),
  deployStagingDeployment: (id: string) =>
    request<StagingDeployment>("POST", `/api/v1/staging-deployments/${id}/deploy`),
  teardownStagingDeployment: (id: string) =>
    request<StagingDeployment>("POST", `/api/v1/staging-deployments/${id}/teardown`),

  // Worker-owned read-only target discovery (SECP-B5). The API enqueues a durable read-only
  // discovery job; a worker runs the probes. Live deployment apply remains sealed.
  listDiscoveryEnrollments: () =>
    request<DiscoveryEnrollment[]>("GET", "/api/v1/target-discovery"),
  requestTargetDiscovery: (body: DiscoveryRequest) =>
    request<DiscoveryEnrollment>("POST", "/api/v1/target-discovery", body),
  getDiscoveryEnrollment: (id: string) =>
    request<DiscoveryEnrollment>("GET", `/api/v1/target-discovery/${id}`),
  getDiscoveryEvidence: (id: string) =>
    request<DiscoveryEvidence>("GET", `/api/v1/target-discovery/${id}/evidence`),
  getDiscoveryCandidatePlan: (id: string) =>
    request<DiscoveryCandidatePlan>("GET", `/api/v1/target-discovery/${id}/candidate-plan`),
  getDiscoveryApplyStatus: (id: string) =>
    request<DiscoveryApplyNotice>("GET", `/api/v1/target-discovery/${id}/apply-status`),
  getDiscoveryBootstrapAvailability: (id: string) =>
    request<BootstrapAvailability>(
      "GET",
      `/api/v1/target-discovery/${id}/bootstrap-availability`,
    ),
  rerunDiscovery: (id: string) =>
    request<DiscoveryEnrollment>("POST", `/api/v1/target-discovery/${id}/rerun`),
  approveDiscoveryPlan: (id: string, expectedPlanHash: string) =>
    request<DiscoveryEnrollment>("POST", `/api/v1/target-discovery/${id}/approve`, {
      expected_plan_hash: expectedPlanHash,
    }),
  rejectDiscoveryPlan: (id: string) =>
    request<DiscoveryEnrollment>("POST", `/api/v1/target-discovery/${id}/reject`),

  // Proxmox read-only discovery bootstrap automation (SECP-B7). Public key only; no private keys.
  listBootstrapSessions: (executionTargetId?: string) =>
    request<BootstrapSession[]>(
      "GET",
      "/api/v1/target-discovery/read-only-bootstrap/sessions",
      undefined,
      executionTargetId ? { execution_target_id: executionTargetId } : undefined,
    ),
  createBootstrapSession: (body: BootstrapSessionCreate) =>
    request<BootstrapSession>(
      "POST",
      "/api/v1/target-discovery/read-only-bootstrap/sessions",
      body,
    ),
  getBootstrapSession: (id: string) =>
    request<BootstrapSession>("GET", `/api/v1/target-discovery/read-only-bootstrap/sessions/${id}`),
  getBootstrapScript: (id: string) =>
    request<BootstrapScript>(
      "GET",
      `/api/v1/target-discovery/read-only-bootstrap/sessions/${id}/script`,
    ),
  completeBootstrapSession: (id: string, body: BootstrapCompleteRequest) =>
    request<BootstrapSession>(
      "POST",
      `/api/v1/target-discovery/read-only-bootstrap/sessions/${id}/complete`,
      body,
    ),
  bindBootstrapSession: (id: string) =>
    request<BootstrapSession>(
      "POST",
      `/api/v1/target-discovery/read-only-bootstrap/sessions/${id}/bind`,
    ),
  getBootstrapBindingDescriptor: (enrollmentId: string) =>
    request<BindingDescriptor>(
      "GET",
      `/api/v1/target-discovery/read-only-bootstrap/enrollments/${enrollmentId}/binding-descriptor`,
    ),
  // SECP-B8: precise discovery-readiness diagnostic (which prerequisite is missing).
  getDiscoveryReadiness: (enrollmentId: string) =>
    request<DiscoveryReadiness>(
      "GET",
      `/api/v1/target-discovery/read-only-bootstrap/enrollments/${enrollmentId}/readiness`,
    ),
  // SECP-B8: grant staging-substrate eligibility (target-admin; requires staging_substrate:manage).
  grantSubstrateEligibility: (executionTargetId: string) =>
    request<SubstrateEligibilityGrant>(
      "POST",
      `/api/v1/target-discovery/read-only-bootstrap/targets/${executionTargetId}/substrate-eligibility`,
    ),
  // SECP-B8: worker-published PUBLIC key material (the worker owns/generates its keys). No private keys.
  listWorkerNodes: () =>
    request<WorkerDiscoveryNode[]>(
      "GET",
      "/api/v1/target-discovery/read-only-bootstrap/worker-nodes",
    ),

  // App-owned read-only staging preflight (SECP-B2-0). API queues only; a worker executes.
  preflightSubstrates: () =>
    request<PreflightSubstrate[]>("GET", "/api/v1/readonly-preflight/substrates"),
  createPreflightAuthorization: (executionTargetId: string, ttlSeconds = 900) =>
    request<PreflightAuthorization>("POST", "/api/v1/readonly-preflight/authorizations", {
      execution_target_id: executionTargetId,
      ttl_seconds: ttlSeconds,
    }),
  listPreflightAuthorizations: (executionTargetId: string) =>
    request<PreflightAuthorization[]>("GET", "/api/v1/readonly-preflight/authorizations", undefined, {
      execution_target_id: executionTargetId,
    }),
  approvePreflightAuthorization: (id: string) =>
    request<PreflightAuthorization>(
      "POST",
      `/api/v1/readonly-preflight/authorizations/${id}/approve`,
    ),
  revokePreflightAuthorization: (id: string) =>
    request<PreflightAuthorization>(
      "POST",
      `/api/v1/readonly-preflight/authorizations/${id}/revoke`,
    ),
  queueReadonlyPreflight: (authorizationId: string) =>
    request<ReadonlyPreflight>("POST", "/api/v1/readonly-preflight", {
      live_read_authorization_id: authorizationId,
    }),
  listReadonlyPreflights: (executionTargetId: string) =>
    request<ReadonlyPreflight[]>("GET", "/api/v1/readonly-preflight", undefined, {
      execution_target_id: executionTargetId,
    }),
  // SECP-B2-4.1 — resolver-activation authorization admin lifecycle (no secret/backend fields).
  listResolverActivations: (executionTargetId: string) =>
    request<ResolverActivation[]>("GET", "/api/v1/resolver-activation/authorizations", undefined, {
      execution_target_id: executionTargetId,
    }),
  createResolverActivation: (preflightId: string, ttlSeconds = 3600) =>
    request<ResolverActivation>("POST", "/api/v1/resolver-activation/authorizations", {
      preflight_id: preflightId,
      ttl_seconds: ttlSeconds,
    }),
  recordResolverActivationEvidence: (
    id: string,
    kind: string,
    status: string,
    proofId: string,
    issuer: string,
  ) =>
    request<ResolverActivation>(
      "POST",
      `/api/v1/resolver-activation/authorizations/${id}/evidence`,
      { kind, status, proof_id: proofId, issuer },
    ),
  approveResolverActivation: (id: string) =>
    request<ResolverActivation>(
      "POST",
      `/api/v1/resolver-activation/authorizations/${id}/approve`,
    ),
  revokeResolverActivation: (id: string) =>
    request<ResolverActivation>(
      "POST",
      `/api/v1/resolver-activation/authorizations/${id}/revoke`,
    ),

  // SECP-B9 — durable topology draft authoring (backend contract for PR-15).
  // These are the typed, secret-free client methods a future frontend PR wires
  // the topology workspace to. The PR-13 workspace stays local-draft-only until
  // that PR ships. Save/revise/validate/submit are hash-pinned (optimistic
  // concurrency); a stale base fails closed with a topology_* closed code.
  createTopologyDraft: (body: {
    display_name: string;
    source_environment_version_id?: string | null;
    exercise_id?: string | null;
    document?: Record<string, unknown> | null;
  }) =>
    request<TopologyDocumentDetail>(
      "POST",
      "/api/v1/topology-authoring/documents",
      body,
    ),
  getTopologyDocument: (documentId: string) =>
    request<TopologyDocumentDetail>(
      "GET",
      `/api/v1/topology-authoring/documents/${documentId}`,
    ),
  listTopologyRevisions: (documentId: string, limit = 50, offset = 0) =>
    request<TopologyRevisionSummary[]>(
      "GET",
      `/api/v1/topology-authoring/documents/${documentId}/revisions`,
      undefined,
      { limit: String(limit), offset: String(offset) },
    ),
  getTopologyRevision: (documentId: string, revisionId: string) =>
    request<TopologyRevisionDetail>(
      "GET",
      `/api/v1/topology-authoring/documents/${documentId}/revisions/${revisionId}`,
    ),
  createTopologyRevision: (
    documentId: string,
    body: {
      base_revision_number: number;
      base_content_hash: string;
      document: Record<string, unknown>;
      change_note?: string | null;
    },
  ) =>
    request<TopologyRevisionDetail>(
      "POST",
      `/api/v1/topology-authoring/documents/${documentId}/revisions`,
      body,
    ),
  validateTopologyRevision: (
    documentId: string,
    revisionId: string,
    contentHash: string,
  ) =>
    request<TopologyValidationResult>(
      "POST",
      `/api/v1/topology-authoring/documents/${documentId}/revisions/${revisionId}/validate`,
      { content_hash: contentHash },
    ),
  getTopologyValidation: (documentId: string, revisionId: string) =>
    request<TopologyValidationResult | null>(
      "GET",
      `/api/v1/topology-authoring/documents/${documentId}/revisions/${revisionId}/validation`,
    ),
  submitTopologyRevision: (
    documentId: string,
    revisionId: string,
    contentHash: string,
  ) =>
    request<TopologyRevisionSummary>(
      "POST",
      `/api/v1/topology-authoring/documents/${documentId}/revisions/${revisionId}/submit`,
      { content_hash: contentHash },
    ),
  approveTopologyRevision: (
    documentId: string,
    revisionId: string,
    contentHash: string,
    reason?: string,
  ) =>
    request<TopologyRevisionSummary>(
      "POST",
      `/api/v1/topology-authoring/documents/${documentId}/revisions/${revisionId}/approve`,
      { content_hash: contentHash, reason },
    ),
  rejectTopologyRevision: (
    documentId: string,
    revisionId: string,
    contentHash: string,
    reason?: string,
  ) =>
    request<TopologyRevisionSummary>(
      "POST",
      `/api/v1/topology-authoring/documents/${documentId}/revisions/${revisionId}/reject`,
      { content_hash: contentHash, reason },
    ),
};
