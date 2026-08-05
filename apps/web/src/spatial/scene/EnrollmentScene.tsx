import { Canvas } from '@react-three/fiber'
import { Bloom, EffectComposer, Vignette } from '@react-three/postprocessing'
import { Suspense } from 'react'
import { CameraRig } from './components/CameraRig'
import { DatacenterEnvironment } from './components/DatacenterEnvironment'
import { ServerLane } from './components/ServerLane'
import { sceneConfig } from './config/scene'
import { SceneIntroCompletionProbe } from './SceneIntroCompletionProbe'
import { SceneReadyProbe } from './SceneReadyProbe'

interface EnrollmentSceneProps {
  active: boolean
  onReady?: () => void
  onIntroComplete?: () => void
}

export function EnrollmentScene({ active, onReady, onIntroComplete }: EnrollmentSceneProps) {
  return (
    <div
      className={['scene-shell', active ? 'scene-shell--active' : ''].filter(Boolean).join(' ')}
      aria-hidden={!active}
    >
      <Canvas
        /*
         * Shadows remain disabled here because the downloaded
         * rack model is repeated many times. Enabling shadows on
         * every rack causes a severe performance penalty.
         */
        dpr={[1, 1.5]}
        camera={{
          position: [...sceneConfig.camera.overviewPosition],
          fov: sceneConfig.camera.overviewFov,
          near: 0.08,
          far: 120,
        }}
        gl={{
          antialias: true,
          alpha: false,
          powerPreference: 'high-performance',
        }}
      >
        <color attach="background" args={['#020713']} />

        <fog attach="fog" args={['#071528', 18, 58]} />

        <Suspense fallback={null}>
          <CameraRig active={active} />

          <DatacenterEnvironment />

          <ServerLane active={active} side={-1} />

          <ServerLane active={active} side={1} />

          <SceneReadyProbe onReady={onReady} />

          <SceneIntroCompletionProbe active={active} onComplete={onIntroComplete} />

          <EffectComposer multisampling={0}>
            <Bloom
              intensity={0.62}
              luminanceThreshold={0.56}
              luminanceSmoothing={0.78}
              mipmapBlur
            />

            <Vignette eskil={false} offset={0.08} darkness={0.42} />
          </EffectComposer>
        </Suspense>
      </Canvas>
    </div>
  )
}
