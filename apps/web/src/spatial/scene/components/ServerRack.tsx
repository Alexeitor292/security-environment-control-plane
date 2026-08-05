import { Clone, useGLTF } from '@react-three/drei'
import gsap from 'gsap'
import { useLayoutEffect, useMemo, useRef } from 'react'
import { Group, Mesh, MeshStandardMaterial } from 'three'
import { sceneConfig } from '../config/scene'

interface ServerRackProps {
  active: boolean
  delay: number
  side: -1 | 1
  x: number
  z: number
  yaw: number
}

export function ServerRack({ active, delay, side, x, z, yaw }: ServerRackProps) {
  const { scene } = useGLTF(sceneConfig.model.url)
  const rackGroup = useRef<Group>(null)

  const preparedScene = useMemo(() => {
    scene.traverse((object) => {
      const mesh = object as Mesh

      if (!mesh.isMesh) {
        return
      }

      mesh.castShadow = true
      mesh.receiveShadow = true

      const materials = Array.isArray(mesh.material) ? mesh.material : [mesh.material]

      for (const material of materials) {
        if (!(material instanceof MeshStandardMaterial)) {
          continue
        }

        /*
         * Generated PBR maps produced a polished metallic finish.
         * Keep the color texture while overriding its physical
         * response with matte, powder-coated cabinet steel.
         */
        material.metalnessMap = null
        material.roughnessMap = null

        material.metalness = sceneConfig.model.material.metalness

        material.roughness = sceneConfig.model.material.roughness

        material.envMapIntensity = sceneConfig.model.material.envMapIntensity

        material.needsUpdate = true
      }
    })

    return scene
  }, [scene])

  useLayoutEffect(() => {
    const rack = rackGroup.current

    if (!rack) {
      return
    }

    gsap.killTweensOf(rack.position)
    gsap.killTweensOf(rack.rotation)
    gsap.killTweensOf(rack.scale)

    const timeline = gsap.timeline({
      delay: active ? delay : 0,
    })

    if (active) {
      timeline.set(rack.position, {
        y: sceneConfig.model.hiddenY,
      })

      timeline.set(rack.rotation, {
        y: yaw + side * 0.1,
      })

      timeline.set(rack.scale, {
        x: 0.975,
        y: 0.975,
        z: 0.975,
      })

      timeline.to(
        rack.position,
        {
          y: sceneConfig.model.restingY + 0.065,
          duration: 1.24,
          ease: 'power4.out',
        },
        0,
      )

      timeline.to(
        rack.position,
        {
          y: sceneConfig.model.restingY,
          duration: 0.28,
          ease: 'power2.inOut',
        },
        1.24,
      )

      timeline.to(
        rack.rotation,
        {
          y: yaw,
          duration: 1.15,
          ease: 'power3.out',
        },
        0.08,
      )

      timeline.to(
        rack.scale,
        {
          x: 1,
          y: 1,
          z: 1,
          duration: 1.08,
          ease: 'power2.out',
        },
        0.12,
      )
    } else {
      timeline.set(rack.position, {
        y: sceneConfig.model.hiddenY,
      })
    }

    return () => {
      timeline.kill()
    }
  }, [active, delay, side, yaw])

  return (
    <group ref={rackGroup} position={[x, sceneConfig.model.hiddenY, z]} rotation={[0, yaw, 0]}>
      <Clone object={preparedScene} scale={sceneConfig.model.scale} castShadow receiveShadow />
    </group>
  )
}

useGLTF.preload(sceneConfig.model.url)
