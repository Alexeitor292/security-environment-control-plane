import { PrototypeSuiteApp } from '../prototype-suite/PrototypeSuiteApp'

export function AdministrationApp({ initialEntry = '/platform' }: { initialEntry?: string }) {
  return <PrototypeSuiteApp key={initialEntry} initialEntry={initialEntry} />
}
