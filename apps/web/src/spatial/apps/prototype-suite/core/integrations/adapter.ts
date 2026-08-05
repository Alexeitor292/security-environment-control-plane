import type {
  AccessProfile,
  AlertItem,
  Approval,
  AuditEvent,
  Deployment,
  EventItem,
  EvidenceRecord,
  InfraTarget,
  IntegrationInfo,
  Participant,
  ReportDef,
  Scenario,
  ScoreEntry,
  SecretRef,
  Team,
  TopologyGraph,
  UserAccount,
  WorkerNode,
  WorkflowRun,
} from '../models/types'

/**
 * Provider-independent adapter boundary.
 *
 * The prototype talks ONLY to this interface. Today it is implemented by the
 * mock adapter (fixture data); a future implementation calls the real SECP
 * control-plane API. Method names deliberately mirror the product model, not
 * the current backend routes.
 */
export interface ControlPlaneAdapter {
  listEvents(): Promise<EventItem[]>
  getEvent(id: string): Promise<EventItem | undefined>
  listScenarios(): Promise<Scenario[]>
  getScenario(id: string): Promise<Scenario | undefined>
  listDeployments(): Promise<Deployment[]>
  getDeployment(id: string): Promise<Deployment | undefined>
  listTeams(eventId?: string): Promise<Team[]>
  listParticipants(teamId?: string): Promise<Participant[]>
  listAccessProfiles(teamId?: string): Promise<AccessProfile[]>
  listTargets(): Promise<InfraTarget[]>
  listWorkers(): Promise<WorkerNode[]>
  listIntegrations(): Promise<IntegrationInfo[]>
  listWorkflowRuns(filter?: { eventId?: string; deploymentId?: string }): Promise<WorkflowRun[]>
  listApprovals(): Promise<Approval[]>
  listAlerts(): Promise<AlertItem[]>
  listAuditEvents(): Promise<AuditEvent[]>
  listEvidence(): Promise<EvidenceRecord[]>
  listScores(eventId: string): Promise<ScoreEntry[]>
  listReports(): Promise<ReportDef[]>
  listUsers(): Promise<UserAccount[]>
  listSecretRefs(): Promise<SecretRef[]>
  getTopology(subjectId: string): Promise<TopologyGraph | undefined>
}
