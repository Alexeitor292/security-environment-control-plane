// Thin typed API client over the control-plane REST API.

import type {
  AuditEvent,
  DeploymentPlan,
  ExecutionTarget,
  Exercise,
  Instance,
  InventoryResource,
  InventorySnapshot,
  Onboarding,
  OnboardingCreate,
  PluginInfo,
  Preflight,
  Principal,
  ProviderCapabilities,
  TargetCreate,
  TargetEvidence,
  TeamTopology,
  Template,
  Version,
  WorkflowRun,
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
  const res = await fetch(buildUrl(path, params), {
    method,
    headers: body ? { "Content-Type": "application/json" } : {},
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  const payload = text ? JSON.parse(text) : null;
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
};
