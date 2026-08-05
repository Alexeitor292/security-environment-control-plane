import { PrototypeSuiteApp } from '../prototype-suite/PrototypeSuiteApp'

export function ReportsApp({ initialEntry = '/reports' }: { initialEntry?: string }) {
  return <PrototypeSuiteApp key={initialEntry} initialEntry={initialEntry} />
}
