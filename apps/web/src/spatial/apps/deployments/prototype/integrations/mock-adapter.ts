import type { ControlPlaneAdapter } from './adapter'
import {
  accessProfiles,
  alerts,
  approvals,
  auditEvents,
  deployments,
  events,
  evidenceRecords,
  integrations,
  participants,
  reports,
  scenarios,
  scores,
  secretRefs,
  targets,
  teams,
  topologies,
  users,
  workers,
  workflowRuns,
} from '../mocks'

/** Small artificial latency so loading states are visible and realistic. */
function respond<T>(value: T, delayMs = 120): Promise<T> {
  return new Promise((resolve) => setTimeout(() => resolve(value), delayMs))
}

/** Fixture-backed adapter. All data is mock; nothing contacts infrastructure. */
export class MockControlPlaneAdapter implements ControlPlaneAdapter {
  listEvents() {
    return respond(events)
  }
  getEvent(id: string) {
    return respond(events.find((e) => e.id === id))
  }
  listScenarios() {
    return respond(scenarios)
  }
  getScenario(id: string) {
    return respond(scenarios.find((s) => s.id === id))
  }
  listDeployments() {
    return respond(deployments)
  }
  getDeployment(id: string) {
    return respond(deployments.find((d) => d.id === id))
  }
  listTeams(eventId?: string) {
    return respond(eventId ? teams.filter((t) => t.eventId === eventId) : teams)
  }
  listParticipants(teamId?: string) {
    return respond(teamId ? participants.filter((p) => p.teamId === teamId) : participants)
  }
  listAccessProfiles(teamId?: string) {
    return respond(teamId ? accessProfiles.filter((p) => p.teamId === teamId) : accessProfiles)
  }
  listTargets() {
    return respond(targets)
  }
  listWorkers() {
    return respond(workers)
  }
  listIntegrations() {
    return respond(integrations)
  }
  listWorkflowRuns(filter?: { eventId?: string; deploymentId?: string }) {
    let runs = workflowRuns
    if (filter?.eventId) runs = runs.filter((r) => r.eventId === filter.eventId)
    if (filter?.deploymentId) runs = runs.filter((r) => r.deploymentId === filter.deploymentId)
    return respond(runs)
  }
  listApprovals() {
    return respond(approvals)
  }
  listAlerts() {
    return respond(alerts)
  }
  listAuditEvents() {
    return respond(auditEvents)
  }
  listEvidence() {
    return respond(evidenceRecords)
  }
  listScores(eventId: string) {
    return respond(eventId === 'evt-aurora-cup' ? scores : [])
  }
  listReports() {
    return respond(reports)
  }
  listUsers() {
    return respond(users)
  }
  listSecretRefs() {
    return respond(secretRefs)
  }
  getTopology(subjectId: string) {
    return respond(topologies[subjectId])
  }
}

export const mockAdapter = new MockControlPlaneAdapter()
