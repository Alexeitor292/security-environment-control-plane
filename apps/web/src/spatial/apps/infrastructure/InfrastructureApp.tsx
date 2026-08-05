import { useState } from 'react'
import { PrototypeSuiteApp } from '../prototype-suite/PrototypeSuiteApp'
import { SpatialInfrastructureApp } from './SpatialInfrastructureApp'

export function InfrastructureApp({
  initialEntry = '/infrastructure/targets',
}: {
  initialEntry?: string
}) {
  const [enrolling, setEnrolling] = useState(false)

  if (enrolling) {
    return (
      <SpatialInfrastructureApp
        key="active-infrastructure-enrollment"
        startAdding
        onExit={() => setEnrolling(false)}
      />
    )
  }

  return (
    <PrototypeSuiteApp
      key={initialEntry}
      initialEntry={initialEntry}
      onAddInfrastructure={() => setEnrolling(true)}
    />
  )
}
