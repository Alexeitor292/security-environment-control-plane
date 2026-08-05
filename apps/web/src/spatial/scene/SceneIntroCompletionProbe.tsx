import { useFrame } from '@react-three/fiber'
import { useCallback, useEffect, useRef } from 'react'
import * as THREE from 'three'

interface SceneIntroCompletionProbeProps {
  active: boolean
  onComplete?: () => void
}

interface ObjectSample {
  position: THREE.Vector3
  quaternion: THREE.Quaternion
  scale: THREE.Vector3
}

const ignoredName =
  /(packet|particle|spark|beam|light|glow|ring|floor|fog|connection|cable|label|text)/i

const preferredName = /(server|rack|cabinet|lane|chassis|enclosure)/i

export function SceneIntroCompletionProbe({ active, onComplete }: SceneIntroCompletionProbeProps) {
  const completeRef = useRef(false)
  const startedAtRef = useRef<number | null>(null)
  const stableFramesRef = useRef(0)
  const motionSeenRef = useRef(false)

  const samplesRef = useRef(new Map<THREE.Object3D, ObjectSample>())

  const cameraPositionRef = useRef(new THREE.Vector3())

  const previousCameraPositionRef = useRef(new THREE.Vector3())

  const cameraQuaternionRef = useRef(new THREE.Quaternion())

  const previousCameraQuaternionRef = useRef(new THREE.Quaternion())

  const worldPositionRef = useRef(new THREE.Vector3())

  const worldScaleRef = useRef(new THREE.Vector3())

  const worldQuaternionRef = useRef(new THREE.Quaternion())

  const sendComplete = useCallback(() => {
    if (completeRef.current || !onComplete) {
      return
    }

    completeRef.current = true

    window.requestAnimationFrame(() => {
      window.requestAnimationFrame(() => {
        onComplete()
      })
    })
  }, [onComplete])

  useEffect(() => {
    completeRef.current = false
    startedAtRef.current = null
    stableFramesRef.current = 0
    motionSeenRef.current = false
    samplesRef.current.clear()

    previousCameraPositionRef.current.set(Number.NaN, Number.NaN, Number.NaN)

    previousCameraQuaternionRef.current.set(Number.NaN, Number.NaN, Number.NaN, Number.NaN)
  }, [active])

  useFrame(({ camera, clock, scene }) => {
    if (!active || !onComplete || completeRef.current) {
      return
    }

    if (startedAtRef.current === null) {
      startedAtRef.current = clock.elapsedTime
    }

    camera.getWorldPosition(cameraPositionRef.current)

    camera.getWorldQuaternion(cameraQuaternionRef.current)

    let cameraDelta = 0

    if (Number.isFinite(previousCameraPositionRef.current.x)) {
      cameraDelta = Math.max(
        previousCameraPositionRef.current.distanceTo(cameraPositionRef.current),
        previousCameraQuaternionRef.current.angleTo(cameraQuaternionRef.current) * 1.4,
      )
    }

    previousCameraPositionRef.current.copy(cameraPositionRef.current)

    previousCameraQuaternionRef.current.copy(cameraQuaternionRef.current)

    const preferred: THREE.Object3D[] = []

    const fallback: THREE.Object3D[] = []

    scene.traverse((object) => {
      if (
        object === scene ||
        !object.visible ||
        object instanceof THREE.Camera ||
        object instanceof THREE.Light ||
        object instanceof THREE.Points ||
        object instanceof THREE.Line ||
        object instanceof THREE.Sprite ||
        ignoredName.test(object.name)
      ) {
        return
      }

      const mesh = object as THREE.Mesh

      const geometry =
        mesh.isMesh && mesh.geometry instanceof THREE.BufferGeometry ? mesh.geometry : null

      if (geometry && geometry.boundingSphere === null) {
        geometry.computeBoundingSphere()
      }

      const radius = geometry?.boundingSphere?.radius ?? 0

      if (preferredName.test(object.name)) {
        preferred.push(object)
        return
      }

      if (object.children.length >= 3 || radius >= 0.8) {
        fallback.push(object)
      }
    })

    const candidates = (preferred.length > 0 ? preferred : fallback).slice(0, 96)

    let objectDelta = 0

    for (const object of candidates) {
      object.getWorldPosition(worldPositionRef.current)

      object.getWorldScale(worldScaleRef.current)

      object.getWorldQuaternion(worldQuaternionRef.current)

      const previous = samplesRef.current.get(object)

      if (previous) {
        objectDelta = Math.max(
          objectDelta,
          previous.position.distanceTo(worldPositionRef.current),
          previous.scale.distanceTo(worldScaleRef.current) * 1.2,
          previous.quaternion.angleTo(worldQuaternionRef.current) * 0.8,
        )

        previous.position.copy(worldPositionRef.current)

        previous.scale.copy(worldScaleRef.current)

        previous.quaternion.copy(worldQuaternionRef.current)
      } else {
        samplesRef.current.set(object, {
          position: worldPositionRef.current.clone(),
          quaternion: worldQuaternionRef.current.clone(),
          scale: worldScaleRef.current.clone(),
        })
      }
    }

    const maximumDelta = Math.max(cameraDelta, objectDelta)

    if (maximumDelta >= 0.02) {
      motionSeenRef.current = true
    }

    const sceneIsQuiet = cameraDelta <= 0.0045 && objectDelta <= 0.018

    if (sceneIsQuiet) {
      stableFramesRef.current += 1
    } else {
      stableFramesRef.current = 0
    }

    const elapsed = clock.elapsedTime - (startedAtRef.current ?? clock.elapsedTime)

    const movingIntroSettled =
      motionSeenRef.current && elapsed >= 0.75 && stableFramesRef.current >= 14

    const staticIntroPainted =
      !motionSeenRef.current && elapsed >= 2.25 && stableFramesRef.current >= 18

    const deadManReached = elapsed >= 5.2

    if (movingIntroSettled || staticIntroPainted || deadManReached) {
      sendComplete()
    }
  })

  return null
}
