export type SecpAppId =
  | 'home'
  | 'infrastructure'
  | 'environments'
  | 'discovery'
  | 'cyber-ranges'
  | 'scenarios'
  | 'deployments'
  | 'network-map'
  | 'ai-operations'
  | 'evidence'
  | 'reports'
  | 'integrations'
  | 'administration'
  | 'settings'
  | 'activity'

export type SecpGlyphName =
  | 'home'
  | 'infrastructure'
  | 'environments'
  | 'discovery'
  | 'ranges'
  | 'scenarios'
  | 'deployments'
  | 'network'
  | 'ai'
  | 'evidence'
  | 'reports'
  | 'integrations'
  | 'administration'
  | 'settings'
  | 'activity'

export interface SecpAppDefinition {
  id: Exclude<SecpAppId, 'home' | 'activity'>
  name: string
  shortName: string
  description: string
  glyph: SecpGlyphName
  accent: string
  badge?: number
  dock?: boolean
}
