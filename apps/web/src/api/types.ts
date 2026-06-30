// Types mirroring the control-plane API responses (apps/api/secp_api/schemas.py).

export type LifecycleState =
  | "draft"
  | "validated"
  | "planned"
  | "awaiting_approval"
  | "approved"
  | "deploying"
  | "running"
  | "resetting"
  | "destroying"
  | "destroyed"
  | "failed";

export type PlanStatus =
  | "generated"
  | "awaiting_approval"
  | "approved"
  | "rejected"
  | "applied";

export interface Principal {
  user_id: string;
  organization_id: string;
  email: string;
  permissions: string[];
  is_dev_fallback: boolean;
}

export interface Template {
  id: string;
  organization_id: string;
  name: string;
  slug: string;
  display_name: string;
  description: string;
  created_at: string;
}

export interface Version {
  id: string;
  template_id: string;
  version_number: number;
  api_version: string;
  content_hash: string;
  spec: Record<string, unknown>;
  created_at: string;
}

export interface Exercise {
  id: string;
  organization_id: string;
  template_id: string;
  environment_version_id: string;
  name: string;
  lifecycle_state: LifecycleState;
  team_count: number;
  created_at: string;
}

export interface Instance {
  id: string;
  exercise_id: string;
  team_index: number;
  team_ref: string;
  instance_ref: string;
  lifecycle_state: LifecycleState;
  provider: string;
}

export interface PlanSummaryTeam {
  team_ref: string;
  networks: { name: string; cidr: string }[];
  nodes: { name: string; role: string; kind: string; ip: string }[];
}

export interface PlanSummary {
  plugin: string;
  teams: number;
  isolation: string;
  total_networks: number;
  total_nodes: number;
  per_team: PlanSummaryTeam[];
}

export interface DeploymentPlan {
  id: string;
  exercise_id: string;
  environment_version_id: string;
  version_content_hash: string;
  status: PlanStatus;
  summary: PlanSummary;
  approved_content_hash: string | null;
  decided_at: string | null;
  created_at: string;
}

export interface WorkflowRun {
  id: string;
  exercise_id: string;
  kind: string;
  status: string;
  dispatch_mode: string;
  correlation_id: string;
  target_instance_id: string | null;
  detail: Record<string, unknown>;
  created_at: string;
  finished_at: string | null;
}

export interface AuditEvent {
  id: string;
  actor: string;
  action: string;
  resource_type: string;
  resource_id: string | null;
  outcome: string;
  data: Record<string, unknown>;
  created_at: string;
}

export interface PluginInfo {
  name: string;
  version: string;
  contract_version: string;
  healthy: boolean;
  simulated: boolean;
  capabilities: string[];
}

export interface TopologyNode {
  id: string;
  type: string;
  data: {
    label: string;
    kind: string;
    role?: string;
    image?: string;
    ip?: string;
    cidr?: string;
    status?: string;
    network?: string;
    isolated?: boolean;
  };
}

export interface TopologyEdge {
  id: string;
  source: string;
  target: string;
  label: string;
  data: { kind: string };
}

export interface TeamTopology {
  instance_id: string;
  team_ref: string;
  team_index: number;
  lifecycle_state: string;
  nodes: TopologyNode[];
  edges: TopologyEdge[];
}

export interface ApiError {
  error: { code: string; message: string; details?: string[] };
}
