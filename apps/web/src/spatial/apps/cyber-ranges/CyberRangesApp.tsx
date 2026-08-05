import { PrototypeSuiteApp } from '../prototype-suite/PrototypeSuiteApp'

export function CyberRangesApp({ initialEntry = '/events' }: { initialEntry?: string }) {
  return <PrototypeSuiteApp key={initialEntry} initialEntry={initialEntry} />
}
