import { useFrame, useThree } from '@react-three/fiber'
import gsap from 'gsap'
import { useLayoutEffect, useRef } from 'react'
import { PerspectiveCamera, Vector3 } from 'three'
import { sceneConfig } from '../config/scene'

interface CameraRigProps {
  active: boolean
}

export function CameraRig({ active }: CameraRigProps) {
  const camera = useThree((state) => state.camera) as PerspectiveCamera

  const target = useRef(new Vector3(...sceneConfig.camera.overviewTarget))

  useLayoutEffect(() => {
    const destination = active
      ? sceneConfig.camera.corridorPosition
      : sceneConfig.camera.overviewPosition

    const destinationTarget = active
      ? sceneConfig.camera.corridorTarget
      : sceneConfig.camera.overviewTarget

    const destinationFov = active ? sceneConfig.camera.corridorFov : sceneConfig.camera.overviewFov

    const timeline = gsap.timeline({
      defaults: {
        duration: 2.55,
        ease: 'power3.inOut',
      },
    })

    timeline.to(
      camera.position,
      {
        x: destination[0],
        y: destination[1],
        z: destination[2],
      },
      0,
    )

    timeline.to(
      target.current,
      {
        x: destinationTarget[0],
        y: destinationTarget[1],
        z: destinationTarget[2],
      },
      0,
    )

    timeline.to(
      camera,
      {
        fov: destinationFov,
        onUpdate: () => {
          camera.updateProjectionMatrix()
        },
      },
      0,
    )

    return () => {
      timeline.kill()
    }
  }, [active, camera])

  /*
   * Keep the camera aimed at the animated target while the transition
   * runs, but apply no walking bob, mouse parallax, or idle sway.
   */
  useFrame(() => {
    camera.lookAt(target.current)
  })

  return null
}
