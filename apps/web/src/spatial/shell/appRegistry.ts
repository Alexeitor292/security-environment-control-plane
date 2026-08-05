import type { SecpAppDefinition } from './shellTypes'

export const secpApps: SecpAppDefinition[] = [
  {
    id: 'infrastructure',
    name: 'Infrastructure',
    shortName: 'Infrastructure',
    description:
      'Targets, providers, workers, inventory, discovery, placement, credentials, and enrollment.',
    glyph: 'infrastructure',
    accent: '#67d8ff',
    dock: true,
  },
  {
    id: 'cyber-ranges',
    name: 'Events & Ranges',
    shortName: 'Ranges',
    description:
      'Events, live control rooms, teams, access, phases, scoring, topology, and operations.',
    glyph: 'ranges',
    accent: '#9f8cff',
    dock: true,
  },
  {
    id: 'scenarios',
    name: 'Scenarios',
    shortName: 'Scenarios',
    description: 'Scenario library, topology builder, immutable versions, and validation.',
    glyph: 'scenarios',
    accent: '#76d8ff',
    dock: true,
  },
  {
    id: 'deployments',
    name: 'Deployments',
    shortName: 'Deployments',
    description:
      'Deployment portfolio, topology, resources, operations, monitoring, activity, and advanced detail.',
    glyph: 'deployments',
    accent: '#70e6ff',
    badge: 2,
    dock: true,
  },
  {
    id: 'reports',
    name: 'Reports',
    shortName: 'Reports',
    description:
      'Operational, executive, technical, scoring, cost, audit, and evidence-backed reports.',
    glyph: 'reports',
    accent: '#7cb8ff',
  },
  {
    id: 'administration',
    name: 'Platform',
    shortName: 'Platform',
    description:
      'Organizations, identity, secrets, workflows, integrations, audit, evidence, settings, and retention.',
    glyph: 'administration',
    accent: '#95b6ff',
    dock: true,
  },
  {
    id: 'settings',
    name: 'OS Settings',
    shortName: 'Settings',
    description: 'Customize Spatial OS appearance, glass, motion, and desktop preferences.',
    glyph: 'settings',
    accent: '#9bc7e8',
  },
]

export const appById = new Map(secpApps.map((app) => [app.id, app]))
