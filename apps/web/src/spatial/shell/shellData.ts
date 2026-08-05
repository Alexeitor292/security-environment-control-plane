import type { SecpGlyphName } from './shellTypes'

export interface ShellActivity {
  id: string
  title: string
  detail: string
  value: string
  state: 'healthy' | 'running' | 'attention'
  glyph: SecpGlyphName
}

export const shellActivities: ShellActivity[] = [
  {
    id: 'infrastructure-ready',
    title: 'Infrastructure discovery',
    detail: 'Ready to enroll',
    value: 'Ready',
    state: 'healthy',
    glyph: 'infrastructure',
  },
  {
    id: 'container-discovery',
    title: 'Local containers',
    detail: '9 workloads detected',
    value: '9',
    state: 'running',
    glyph: 'environments',
  },
  {
    id: 'ai-approval',
    title: 'AI Core',
    detail: '1 approval required',
    value: '3',
    state: 'attention',
    glyph: 'ai',
  },
]

export const initialAppOrder = [
  'infrastructure',
  'cyber-ranges',
  'scenarios',
  'deployments',
  'reports',
  'administration',
  'settings',
] as const
