import { ArrowLeft, Boxes, Building2, ChevronRight, Server, ShieldCheck } from 'lucide-react'
import type { LucideIcon } from 'lucide-react'
import { useCallback, useEffect, useState } from 'react'
import { LocalContainerScene } from '../../scene/containers/LocalContainerScene'
import { EnrollmentScene } from '../../scene/EnrollmentScene'
import './InfrastructureApp.css'

type InfrastructureType = 'proxmox' | 'self-hosted' | 'local-containers'

type EnrollmentPhase = 'selection' | 'loading' | 'intro' | 'wizard'

interface SpatialInfrastructureAppProps {
  startAdding?: boolean
  onExit?: () => void
}

interface EnrollmentDefinition {
  label: string
  eyebrow: string
  title: string
  description: string
  endpointLabel: string
  endpoint: string
  profile: string
  icon: LucideIcon
}

const enrollmentCopy: Record<InfrastructureType, EnrollmentDefinition> = {
  proxmox: {
    label: 'Proxmox',
    eyebrow: 'Proxmox environment',
    title: 'Enroll a Proxmox environment',
    description:
      'Connect an existing Proxmox cluster through a controlled SECP enrollment workflow.',
    endpointLabel: 'Management endpoint',
    endpoint: 'https://proxmox.example.internal:8006',
    profile: 'Controlled read-only discovery',
    icon: Server,
  },

  'self-hosted': {
    label: 'On-prem self-hosted',
    eyebrow: 'Private infrastructure',
    title: 'Enroll self-hosted infrastructure',
    description: 'Connect privately operated infrastructure located inside your organization.',
    endpointLabel: 'Management endpoint',
    endpoint: 'https://infrastructure.example.internal',
    profile: 'Controlled read-only discovery',
    icon: Building2,
  },

  'local-containers': {
    label: 'Local containers',
    eyebrow: 'Local container runtime',
    title: 'Enroll local containers',
    description:
      'Discover running containers, map their connections, and observe how data moves through your local environment.',
    endpointLabel: 'Container endpoint',
    endpoint: 'unix:///var/run/docker.sock',
    profile: 'Local container discovery',
    icon: Boxes,
  },
}

export function SpatialInfrastructureApp({
  startAdding = true,
  onExit,
}: SpatialInfrastructureAppProps) {
  const [selectedEnrollment, setSelectedEnrollment] = useState<InfrastructureType | null>(null)

  const [phase, setPhase] = useState<EnrollmentPhase>(startAdding ? 'selection' : 'selection')

  const [sceneReady, setSceneReady] = useState(false)

  const [sceneIntroComplete, setSceneIntroComplete] = useState(false)

  const selectedCopy = selectedEnrollment ? enrollmentCopy[selectedEnrollment] : null

  const SelectedIcon = selectedCopy?.icon ?? Server

  const containerSceneActive = selectedEnrollment === 'local-containers'

  const datacenterSceneActive =
    selectedEnrollment === 'proxmox' || selectedEnrollment === 'self-hosted'

  const sceneActive = phase === 'intro' || phase === 'wizard'

  const handleSceneReady = useCallback(() => {
    setSceneReady(true)
  }, [])

  const handleSceneIntroComplete = useCallback(() => {
    setSceneIntroComplete(true)
  }, [])

  useEffect(() => {
    if (phase !== 'loading' || !sceneReady) {
      return
    }

    let firstPaint = 0
    let secondPaint = 0

    firstPaint = window.requestAnimationFrame(() => {
      secondPaint = window.requestAnimationFrame(() => {
        setPhase('intro')
      })
    })

    return () => {
      window.cancelAnimationFrame(firstPaint)
      window.cancelAnimationFrame(secondPaint)
    }
  }, [phase, sceneReady])

  useEffect(() => {
    if (phase !== 'intro' || !sceneIntroComplete) {
      return
    }

    const revealFrame = window.requestAnimationFrame(() => {
      setPhase('wizard')
    })

    return () => {
      window.cancelAnimationFrame(revealFrame)
    }
  }, [phase, sceneIntroComplete])

  useEffect(() => {
    if (phase !== 'intro') {
      return
    }

    // This is only a dead-man fallback. Normal reveal is driven by the
    // scene's real completion signal.
    const safetyTimeout = window.setTimeout(() => {
      setPhase('wizard')
    }, 5000)

    return () => {
      window.clearTimeout(safetyTimeout)
    }
  }, [phase])

  function chooseEnvironment(environment: InfrastructureType) {
    setSceneReady(false)
    setSceneIntroComplete(false)
    setSelectedEnrollment(environment)
    setPhase('loading')
  }

  function changeEnvironment() {
    setSceneReady(false)
    setSceneIntroComplete(false)
    setSelectedEnrollment(null)
    setPhase('selection')
  }

  function closeAddWorkflow() {
    setSceneReady(false)
    setSceneIntroComplete(false)
    setSelectedEnrollment(null)

    if (onExit) {
      onExit()
      return
    }

    setPhase('selection')
  }

  return (
    <div
      data-enrollment-phase={phase}
      className={[
        'secp-enroll-app',
        datacenterSceneActive ? 'secp-enroll-app--datacenter' : '',
        containerSceneActive ? 'secp-enroll-app--containers' : '',
        phase === 'loading' ? 'secp-enroll-app--loading' : '',
        phase === 'intro' ? 'secp-enroll-app--intro' : '',
        phase === 'wizard' ? 'secp-enroll-app--wizard' : '',
      ]
        .filter(Boolean)
        .join(' ')}
    >
      {datacenterSceneActive ? (
        <div className="secp-enroll-scene" key={`datacenter-${selectedEnrollment}`}>
          <EnrollmentScene
            active={sceneActive}
            onReady={handleSceneReady}
            onIntroComplete={handleSceneIntroComplete}
          />
        </div>
      ) : null}

      {containerSceneActive ? (
        <div className="secp-enroll-scene" key="local-containers">
          <LocalContainerScene
            active={sceneActive}
            onReady={handleSceneReady}
            onIntroComplete={handleSceneIntroComplete}
          />
        </div>
      ) : null}

      <button className="secp-enroll-back" type="button" onClick={closeAddWorkflow}>
        <ArrowLeft size={15} aria-hidden />
        <span>Back to Infrastructure</span>
      </button>

      {phase === 'selection' ? (
        <main className="secp-enroll-stage">
          <section className="secp-enroll-card secp-enroll-card--selection">
            <header className="secp-enroll-card__header">
              <div className="secp-enroll-brand">
                <span>SECP</span>

                <div>
                  <small>Animated enrollment</small>
                  <strong>Add infrastructure</strong>
                </div>
              </div>

              <span className="secp-enroll-ready">
                <i />
                Ready
              </span>
            </header>

            <div className="secp-enroll-intro">
              <p>Infrastructure enrollment</p>

              <h1>What are you adding?</h1>

              <span>
                Choose an environment. SECP will prepare its cinematic workspace before presenting
                the enrollment controls.
              </span>
            </div>

            <div className="secp-enroll-options">
              {(Object.keys(enrollmentCopy) as InfrastructureType[]).map((environment) => {
                const copy = enrollmentCopy[environment]
                const Icon = copy.icon

                return (
                  <button
                    className="secp-enroll-option"
                    type="button"
                    key={environment}
                    onClick={() => chooseEnvironment(environment)}
                  >
                    <span className="secp-enroll-option__icon">
                      <Icon size={20} aria-hidden />
                    </span>

                    <span className="secp-enroll-option__copy">
                      <strong>{copy.label}</strong>

                      <span>{copy.description}</span>
                    </span>

                    <ChevronRight className="secp-enroll-option__arrow" size={18} aria-hidden />
                  </button>
                )
              })}
            </div>

            <footer className="secp-enroll-security">
              <ShieldCheck size={15} aria-hidden />

              <span>
                Read-only discovery is established before any provisioning capability becomes
                available.
              </span>
            </footer>
          </section>
        </main>
      ) : null}

      {phase === 'loading' ? (
        <div
          className="secp-enroll-minimal-loader"
          role="status"
          aria-label="Loading three-dimensional environment"
        >
          <div className="secp-enroll-minimal-loader__animation" aria-hidden="true">
            <span className="secp-enroll-minimal-loader__core" />
            <span className="secp-enroll-minimal-loader__orbit secp-enroll-minimal-loader__orbit--one" />
            <span className="secp-enroll-minimal-loader__orbit secp-enroll-minimal-loader__orbit--two" />
            <span className="secp-enroll-minimal-loader__orbit secp-enroll-minimal-loader__orbit--three" />
          </div>
        </div>
      ) : null}

      {phase === 'wizard' && selectedCopy ? (
        <main className="secp-enroll-stage secp-enroll-stage--wizard">
          <section className="secp-enroll-card secp-enroll-card--wizard">
            <header className="secp-enroll-card__header">
              <div className="secp-enroll-brand">
                <span>
                  <SelectedIcon size={19} aria-hidden />
                </span>

                <div>
                  <small>{selectedCopy.eyebrow}</small>
                  <strong>Enrollment ready</strong>
                </div>
              </div>

              <span className="secp-enroll-ready">
                <i />
                Scene ready
              </span>
            </header>

            <div className="secp-enroll-intro secp-enroll-intro--wizard">
              <p>Controlled enrollment</p>

              <h1>{selectedCopy.title}</h1>

              <span>{selectedCopy.description}</span>
            </div>

            {containerSceneActive ? (
              <div className="secp-enroll-runtime">
                <span>
                  <i />
                  Local runtime available
                </span>

                <strong>Ready to scan</strong>
              </div>
            ) : null}

            <div className="secp-enroll-form">
              <label>
                <span>{selectedCopy.endpointLabel}</span>

                <input type="text" defaultValue={selectedCopy.endpoint} />
              </label>

              <label>
                <span>Enrollment profile</span>

                <input type="text" defaultValue={selectedCopy.profile} />
              </label>
            </div>

            <div className="secp-enroll-actions">
              <button
                className="secp-enroll-button secp-enroll-button--secondary"
                type="button"
                onClick={changeEnvironment}
              >
                Change environment
              </button>

              <button className="secp-enroll-button secp-enroll-button--primary" type="button">
                {containerSceneActive ? 'Discover containers' : 'Continue enrollment'}
              </button>
            </div>
          </section>
        </main>
      ) : null}
    </div>
  )
}
