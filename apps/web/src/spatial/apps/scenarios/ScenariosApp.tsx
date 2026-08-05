import { PrototypeSuiteApp } from '../prototype-suite/PrototypeSuiteApp'

export function ScenariosApp({ initialEntry = '/scenarios' }: { initialEntry?: string }) {
  return <PrototypeSuiteApp key={initialEntry} initialEntry={initialEntry} />
}
