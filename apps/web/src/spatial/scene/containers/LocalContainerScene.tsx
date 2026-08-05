import { Suspense, useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { Line, RoundedBox, Text } from '@react-three/drei'
import { Canvas, useFrame } from '@react-three/fiber'
import { Bloom, EffectComposer, Vignette } from '@react-three/postprocessing'
import * as THREE from 'three'
import './LocalContainerScene.css'
import { SceneReadyProbe } from '../SceneReadyProbe'

interface LocalContainerSceneProps {
  active: boolean
  onReady?: () => void
  onIntroComplete?: () => void
}

type DetailLevel = 'hero' | 'medium' | 'distant'

interface PodDefinition {
  id: string
  label: string
  version: string
  icon: string
  position: [number, number, number]
  rotation: [number, number, number]
  scale: number
  phase: number
  detail: DetailLevel
}

interface ConnectionDefinition {
  from: string
  to: string
  controlA: [number, number, number]
  controlB: [number, number, number]
  speed: number
  packets: number
}

const pods: PodDefinition[] = [
  {
    id: 'api-gateway',
    label: 'api-gateway',
    version: 'v1.2.3',
    icon: '◇',
    position: [-8.8, 2.9, 1.1],
    rotation: [0.05, 0.58, -0.08],
    scale: 1.28,
    phase: 0.25,
    detail: 'hero',
  },
  {
    id: 'frontend',
    label: 'frontend',
    version: 'v1.4.2',
    icon: '▣',
    position: [-3.95, 4.05, -3.8],
    rotation: [-0.06, 0.28, 0.04],
    scale: 0.88,
    phase: 1.1,
    detail: 'medium',
  },
  {
    id: 'auth-service',
    label: 'auth-service',
    version: 'v2.1.0',
    icon: '▱',
    position: [-8.1, -0.2, -0.25],
    rotation: [0.03, 0.42, -0.05],
    scale: 1.05,
    phase: 1.95,
    detail: 'hero',
  },
  {
    id: 'user-db',
    label: 'user-db',
    version: 'PostgreSQL 15',
    icon: '◫',
    position: [-6.6, -3.3, -2.1],
    rotation: [-0.03, 0.2, 0.03],
    scale: 0.96,
    phase: 2.8,
    detail: 'medium',
  },
  {
    id: 'redis-cache',
    label: 'redis-cache',
    version: 'v7.2',
    icon: '▰',
    position: [-1.85, -4.15, -5.0],
    rotation: [0.03, 0.1, -0.02],
    scale: 0.8,
    phase: 3.35,
    detail: 'medium',
  },
  {
    id: 'worker',
    label: 'worker',
    version: 'v1.0.8',
    icon: '⚙',
    position: [8.55, 3.05, 0.9],
    rotation: [-0.05, -0.58, 0.08],
    scale: 1.26,
    phase: 1.45,
    detail: 'hero',
  },
  {
    id: 'billing-service',
    label: 'billing-service',
    version: 'v1.3.0',
    icon: '$',
    position: [8.15, -0.1, -0.35],
    rotation: [0.03, -0.4, -0.05],
    scale: 1.04,
    phase: 2.45,
    detail: 'hero',
  },
  {
    id: 'analytics',
    label: 'analytics',
    version: 'v2.0.1',
    icon: '▥',
    position: [6.15, -3.35, -2.25],
    rotation: [-0.03, -0.22, 0.02],
    scale: 0.94,
    phase: 3.15,
    detail: 'medium',
  },
  {
    id: 'message-queue',
    label: 'message-queue',
    version: 'RabbitMQ 3.13',
    icon: '⌘',
    position: [2.25, -4.0, -5.1],
    rotation: [0.03, -0.14, -0.02],
    scale: 0.84,
    phase: 4.0,
    detail: 'medium',
  },
]

const podLookup = new Map(pods.map((pod) => [pod.id, pod]))

const connections: ConnectionDefinition[] = [
  {
    from: 'frontend',
    to: 'api-gateway',
    controlA: [-5.1, 4.6, -1.9],
    controlB: [-7.3, 3.8, 0.4],
    speed: 0.08,
    packets: 3,
  },
  {
    from: 'api-gateway',
    to: 'auth-service',
    controlA: [-10.1, 2.0, 1.6],
    controlB: [-9.4, 0.8, 0.55],
    speed: 0.07,
    packets: 3,
  },
  {
    from: 'auth-service',
    to: 'user-db',
    controlA: [-9.35, -1.1, 0.4],
    controlB: [-8.1, -2.55, -0.9],
    speed: 0.07,
    packets: 2,
  },
  {
    from: 'auth-service',
    to: 'redis-cache',
    controlA: [-6.5, -1.2, 1.4],
    controlB: [-3.9, -3.3, -2.2],
    speed: 0.09,
    packets: 3,
  },
  {
    from: 'api-gateway',
    to: 'worker',
    controlA: [-4.9, 6.05, 0.55],
    controlB: [4.9, 6.1, 0.65],
    speed: 0.06,
    packets: 5,
  },
  {
    from: 'worker',
    to: 'billing-service',
    controlA: [9.8, 2.4, 1.2],
    controlB: [9.25, 0.8, 0.5],
    speed: 0.08,
    packets: 3,
  },
  {
    from: 'billing-service',
    to: 'analytics',
    controlA: [9.05, -0.8, 0.2],
    controlB: [7.45, -2.45, -0.75],
    speed: 0.07,
    packets: 2,
  },
  {
    from: 'worker',
    to: 'message-queue',
    controlA: [6.45, 1.6, 1.5],
    controlB: [4.0, -2.8, -1.6],
    speed: 0.085,
    packets: 4,
  },
  {
    from: 'message-queue',
    to: 'analytics',
    controlA: [3.95, -4.8, -2.3],
    controlB: [5.4, -4.25, -1.0],
    speed: 0.075,
    packets: 3,
  },
  {
    from: 'redis-cache',
    to: 'message-queue',
    controlA: [-0.5, -5.0, -3.0],
    controlB: [0.8, -5.1, -3.1],
    speed: 0.07,
    packets: 4,
  },
]

function MetalMaterial({
  color = '#0c1d2c',
  emissive = '#07243a',
  emissiveIntensity = 0.3,
  metalness = 0.72,
  roughness = 0.26,
}: {
  color?: string
  emissive?: string
  emissiveIntensity?: number
  metalness?: number
  roughness?: number
}) {
  return (
    <meshStandardMaterial
      color={color}
      emissive={emissive}
      emissiveIntensity={emissiveIntensity}
      metalness={metalness}
      roughness={roughness}
    />
  )
}

function EmissiveMaterial({
  color = '#63d7ff',
  opacity = 1,
}: {
  color?: string
  opacity?: number
}) {
  return (
    <meshBasicMaterial
      color={color}
      transparent={opacity < 1}
      opacity={opacity}
      toneMapped={false}
      depthWrite={opacity === 1}
    />
  )
}

function Fastener({ position }: { position: [number, number, number] }) {
  return (
    <group position={position} rotation={[Math.PI / 2, 0, 0]}>
      <mesh>
        <cylinderGeometry args={[0.04, 0.04, 0.02, 12]} />
        <meshStandardMaterial color="#8798a5" metalness={0.95} roughness={0.14} />
      </mesh>

      <mesh position={[0, 0.012, 0]}>
        <boxGeometry args={[0.038, 0.007, 0.01]} />
        <meshBasicMaterial color="#1b2a38" />
      </mesh>
    </group>
  )
}

function CornerAssembly({ x, y }: { x: number; y: number }) {
  const inwardX = x > 0 ? -1 : 1
  const inwardY = y > 0 ? -1 : 1

  return (
    <group position={[x, y, 0]}>
      <RoundedBox args={[0.38, 0.58, 1.56]} radius={0.065} smoothness={3}>
        <MetalMaterial
          color="#13293a"
          emissive="#0a2438"
          emissiveIntensity={0.42}
          metalness={0.8}
          roughness={0.2}
        />
      </RoundedBox>

      <mesh position={[inwardX * 0.12, 0, 0.84]}>
        <boxGeometry args={[0.06, 0.38, 0.03]} />
        <EmissiveMaterial color="#6ce6ff" />
      </mesh>

      <mesh position={[0, inwardY * 0.21, 0.78]}>
        <boxGeometry args={[0.22, 0.045, 0.025]} />
        <EmissiveMaterial color="#1782b6" opacity={0.82} />
      </mesh>

      <mesh position={[0, 0, -0.86]}>
        <boxGeometry args={[0.26, 0.4, 0.07]} />
        <MetalMaterial
          color="#07111a"
          emissive="#020912"
          emissiveIntensity={0.08}
          metalness={0.72}
          roughness={0.38}
        />
      </mesh>

      <Fastener position={[inwardX * 0.1, inwardY * 0.2, 0.81]} />
      <Fastener position={[inwardX * 0.1, -inwardY * 0.2, 0.81]} />
    </group>
  )
}

function StructuralRail({ y }: { y: number }) {
  return (
    <group position={[0, y, 0]}>
      <RoundedBox args={[2.84, 0.22, 1.56]} radius={0.05} smoothness={2}>
        <MetalMaterial
          color="#12283a"
          emissive="#09283f"
          emissiveIntensity={0.38}
          metalness={0.78}
          roughness={0.22}
        />
      </RoundedBox>

      <mesh position={[0, 0, 0.83]}>
        <boxGeometry args={[2.05, 0.038, 0.026]} />
        <EmissiveMaterial color={y > 0 ? '#80edff' : '#2190c7'} opacity={0.95} />
      </mesh>

      {[-0.98, -0.64, 0.64, 0.98].map((x) => (
        <mesh key={x} position={[x, 0, 0.845]}>
          <boxGeometry args={[0.15, 0.06, 0.018]} />
          <EmissiveMaterial color="#1a7eb0" opacity={0.7} />
        </mesh>
      ))}
    </group>
  )
}

function SideRail({ side }: { side: -1 | 1 }) {
  return (
    <group position={[side * 1.58, 0, 0]}>
      <RoundedBox args={[0.12, 1.42, 1.52]} radius={0.03} smoothness={2}>
        <MetalMaterial
          color="#0e2334"
          emissive="#08293f"
          emissiveIntensity={0.3}
          metalness={0.78}
          roughness={0.22}
        />
      </RoundedBox>

      <mesh position={[-side * 0.045, 0, 0.86]}>
        <boxGeometry args={[0.02, 1.04, 0.024]} />
        <EmissiveMaterial color="#71e9ff" opacity={0.86} />
      </mesh>
    </group>
  )
}

function VentPanel({ side }: { side: -1 | 1 }) {
  return (
    <group position={[side * 1.52, 0, 0]} rotation={[0, Math.PI / 2, 0]}>
      <RoundedBox args={[1.18, 1.2, 0.08]} radius={0.055} smoothness={2}>
        <MetalMaterial
          color="#08131d"
          emissive="#02101a"
          emissiveIntensity={0.1}
          metalness={0.66}
          roughness={0.44}
        />
      </RoundedBox>

      {Array.from({ length: 9 }, (_, index) => (
        <mesh key={index} position={[0, 0.47 - index * 0.12, 0.055]}>
          <boxGeometry args={[0.84, 0.022, 0.014]} />
          <meshBasicMaterial color={index % 3 === 0 ? '#2a749f' : '#173548'} />
        </mesh>
      ))}

      <mesh position={[0, 0, 0.078]}>
        <ringGeometry args={[0.27, 0.305, 32]} />
        <EmissiveMaterial color="#2e9ed6" opacity={0.55} />
      </mesh>

      <mesh position={[0, 0, 0.081]}>
        <circleGeometry args={[0.17, 24]} />
        <meshStandardMaterial color="#04090d" metalness={0.5} roughness={0.72} />
      </mesh>
    </group>
  )
}

function ComputeBlade({ y, index }: { y: number; index: number }) {
  return (
    <group position={[0, y, 0.48]}>
      <RoundedBox args={[1.92, 0.14, 0.34]} radius={0.03} smoothness={2}>
        <MetalMaterial
          color={index % 2 === 0 ? '#0f202f' : '#122537'}
          emissive="#04131d"
          emissiveIntensity={0.16}
          metalness={0.48}
          roughness={0.42}
        />
      </RoundedBox>

      <mesh position={[-0.65, 0, 0.19]}>
        <boxGeometry args={[0.34, 0.036, 0.014]} />
        <EmissiveMaterial color="#71e6ff" opacity={0.92} />
      </mesh>

      <mesh position={[-0.34, 0, 0.19]}>
        <boxGeometry args={[0.12, 0.036, 0.014]} />
        <EmissiveMaterial color="#1d6c98" opacity={0.82} />
      </mesh>

      {[0.36, 0.54, 0.72].map((x, lightIndex) => (
        <mesh key={x} position={[x, 0, 0.192]}>
          <circleGeometry args={[lightIndex === 0 ? 0.024 : 0.016, 10]} />
          <EmissiveMaterial color={lightIndex === 1 && index % 3 === 0 ? '#ff9a31' : '#8ef2ff'} />
        </mesh>
      ))}

      <mesh position={[0, -0.055, 0.19]}>
        <boxGeometry args={[1.55, 0.012, 0.008]} />
        <meshBasicMaterial color="#123042" />
      </mesh>
    </group>
  )
}

function InternalCore() {
  const rotor = useRef<THREE.Group>(null)

  useFrame(({ clock }) => {
    if (!rotor.current) {
      return
    }

    rotor.current.rotation.z = clock.elapsedTime * 0.18
  })

  return (
    <group position={[0.78, 0, 0.22]}>
      <mesh rotation={[Math.PI / 2, 0, 0]}>
        <cylinderGeometry args={[0.31, 0.31, 0.56, 24]} />
        <MetalMaterial
          color="#091722"
          emissive="#0a314b"
          emissiveIntensity={0.48}
          metalness={0.72}
          roughness={0.24}
        />
      </mesh>

      <group ref={rotor}>
        {[0, 1, 2].map((index) => (
          <mesh key={index} rotation={[0, 0, index * (Math.PI / 3)]}>
            <boxGeometry args={[0.56, 0.06, 0.06]} />
            <EmissiveMaterial color={index === 0 ? '#8df0ff' : '#2297cf'} opacity={0.9} />
          </mesh>
        ))}
      </group>

      <mesh position={[0, 0, 0.31]}>
        <ringGeometry args={[0.24, 0.27, 32]} />
        <EmissiveMaterial color="#8cf0ff" />
      </mesh>
    </group>
  )
}

function ConnectionPort({ x, y }: { x: number; y: number }) {
  return (
    <group position={[x, y, 0.85]}>
      <RoundedBox args={[0.25, 0.18, 0.08]} radius={0.025} smoothness={2}>
        <MetalMaterial
          color="#12283a"
          emissive="#0a4162"
          emissiveIntensity={0.48}
          metalness={0.58}
          roughness={0.28}
        />
      </RoundedBox>

      <mesh position={[0, 0, 0.055]}>
        <circleGeometry args={[0.04, 12]} />
        <EmissiveMaterial color="#8ef0ff" />
      </mesh>
    </group>
  )
}

function RearFins() {
  return (
    <group position={[0, 0, -0.9]}>
      {[-0.92, -0.56, -0.2, 0.16, 0.52, 0.88].map((x) => (
        <mesh key={x} position={[x, 0, 0]}>
          <boxGeometry args={[0.07, 1.12, 0.14]} />
          <meshStandardMaterial color="#060d14" metalness={0.58} roughness={0.62} />
        </mesh>
      ))}
    </group>
  )
}

function ContainerPod({ definition }: { definition: PodDefinition }) {
  const group = useRef<THREE.Group>(null)

  const hero = definition.detail === 'hero'
  const bladeCount = hero ? 8 : 6

  const blades = useMemo(
    () =>
      Array.from({ length: bladeCount }, (_, index) => ({
        y: 0.45 - index * (hero ? 0.128 : 0.148),
        index,
      })),
    [bladeCount, hero],
  )

  useFrame(({ clock }) => {
    const node = group.current
    if (!node) {
      return
    }

    const time = clock.elapsedTime

    node.position.y = definition.position[1] + Math.sin(time * 0.24 + definition.phase) * 0.12
    node.rotation.x = definition.rotation[0] + Math.sin(time * 0.12 + definition.phase) * 0.012
    node.rotation.y = definition.rotation[1] + Math.sin(time * 0.09 + definition.phase) * 0.03
    node.rotation.z = definition.rotation[2] + Math.sin(time * 0.11 + definition.phase) * 0.01
  })

  return (
    <group
      ref={group}
      position={definition.position}
      rotation={definition.rotation}
      scale={definition.scale}
    >
      <RoundedBox args={[3.28, 2.02, 1.82]} radius={0.18} smoothness={4}>
        <MetalMaterial
          color="#091623"
          emissive="#072338"
          emissiveIntensity={0.42}
          metalness={0.72}
          roughness={0.28}
        />
      </RoundedBox>

      <RoundedBox args={[2.88, 1.58, 1.66]} radius={0.15} smoothness={4}>
        <meshPhysicalMaterial
          color="#10314a"
          emissive="#0c3752"
          emissiveIntensity={0.28}
          metalness={0.08}
          roughness={0.1}
          transmission={0.28}
          thickness={0.25}
          transparent
          opacity={0.42}
          depthWrite={false}
        />
      </RoundedBox>

      <RoundedBox args={[2.52, 1.24, 0.1]} radius={0.08} smoothness={3} position={[0, 0, 0.92]}>
        <meshPhysicalMaterial
          color="#07131e"
          emissive="#0a4f79"
          emissiveIntensity={0.34}
          metalness={0.15}
          roughness={0.14}
          transmission={0.12}
          transparent
          opacity={0.92}
        />
      </RoundedBox>

      <StructuralRail y={0.92} />
      <StructuralRail y={-0.92} />

      <SideRail side={-1} />
      <SideRail side={1} />

      <CornerAssembly x={-1.49} y={0.79} />
      <CornerAssembly x={1.49} y={0.79} />
      <CornerAssembly x={-1.49} y={-0.79} />
      <CornerAssembly x={1.49} y={-0.79} />

      <VentPanel side={-1} />
      <VentPanel side={1} />

      {blades.map(({ y, index }) => (
        <ComputeBlade key={index} y={y} index={index} />
      ))}

      {hero && (
        <>
          <InternalCore />
          <ConnectionPort x={-1.02} y={0.67} />
          <ConnectionPort x={-0.72} y={0.67} />
          <ConnectionPort x={0.98} y={-0.67} />
        </>
      )}

      <mesh position={[0, 0, -0.93]}>
        <boxGeometry args={[2.6, 1.26, 0.07]} />
        <MetalMaterial
          color="#04090d"
          emissive="#010407"
          emissiveIntensity={0.06}
          metalness={0.76}
          roughness={0.54}
        />
      </mesh>

      <RearFins />

      <group position={[0, 0, 0.99]}>
        <RoundedBox args={[0.42, 0.42, 0.04]} radius={0.08} smoothness={3} position={[-1.03, 0, 0]}>
          <MetalMaterial
            color="#0d2e44"
            emissive="#0f6e9f"
            emissiveIntensity={0.75}
            metalness={0.28}
            roughness={0.24}
          />
        </RoundedBox>

        <Text
          position={[-1.03, 0, 0.035]}
          anchorX="center"
          anchorY="middle"
          fontSize={0.17}
          color="#95eeff"
        >
          {definition.icon}
        </Text>

        <Text
          position={[-0.7, 0.16, 0.034]}
          anchorX="left"
          anchorY="middle"
          fontSize={0.17}
          maxWidth={1.4}
          color="#f2fbff"
          outlineWidth={0.003}
          outlineColor="#02070a"
        >
          {definition.label}
        </Text>

        <Text
          position={[-0.7, -0.14, 0.034]}
          anchorX="left"
          anchorY="middle"
          fontSize={0.085}
          maxWidth={1.4}
          color="#7dd7ff"
        >
          {definition.version}
        </Text>

        <mesh position={[1.08, 0.04, 0.036]}>
          <circleGeometry args={[0.032, 12]} />
          <EmissiveMaterial color="#a4f3ff" />
        </mesh>
      </group>
    </group>
  )
}

function DataPacket({
  curve,
  speed,
  offset,
}: {
  curve: THREE.CatmullRomCurve3
  speed: number
  offset: number
}) {
  const packet = useRef<THREE.Group>(null)

  useFrame(({ clock }) => {
    if (!packet.current) {
      return
    }

    const progress = (clock.elapsedTime * speed + offset) % 1
    packet.current.position.copy(curve.getPointAt(progress))

    const pulse = 0.85 + Math.sin(clock.elapsedTime * 7.5 + offset * Math.PI * 2) * 0.18
    packet.current.scale.setScalar(pulse)
  })

  return (
    <group ref={packet}>
      <mesh>
        <sphereGeometry args={[0.06, 12, 12]} />
        <EmissiveMaterial color="#ecfcff" />
      </mesh>

      <mesh scale={3.3}>
        <sphereGeometry args={[0.06, 10, 10]} />
        <EmissiveMaterial color="#3ec4ff" opacity={0.16} />
      </mesh>
    </group>
  )
}

function NetworkConnection({ definition }: { definition: ConnectionDefinition }) {
  const from = podLookup.get(definition.from)
  const to = podLookup.get(definition.to)

  const curve = useMemo(() => {
    if (!from || !to) {
      return null
    }

    return new THREE.CatmullRomCurve3(
      [
        new THREE.Vector3(...from.position),
        new THREE.Vector3(...definition.controlA),
        new THREE.Vector3(...definition.controlB),
        new THREE.Vector3(...to.position),
      ],
      false,
      'catmullrom',
      0.42,
    )
  }, [definition, from, to])

  const points = useMemo(() => curve?.getPoints(140) ?? [], [curve])

  if (!curve) {
    return null
  }

  return (
    <group>
      <Line points={points} color="#0a7db9" lineWidth={2.4} transparent opacity={0.28} />
      <Line points={points} color="#63d9ff" lineWidth={0.84} transparent opacity={0.92} />
      <Line points={points} color="#f1fdff" lineWidth={0.18} transparent opacity={0.85} />

      {Array.from({ length: definition.packets }, (_, index) => (
        <DataPacket
          key={index}
          curve={curve}
          speed={definition.speed}
          offset={index / definition.packets}
        />
      ))}
    </group>
  )
}

function FloorEnvironment() {
  const group = useRef<THREE.Group>(null)

  useFrame(({ clock }) => {
    if (!group.current) {
      return
    }

    const pulse = 1 + Math.sin(clock.elapsedTime * 0.55) * 0.009
    group.current.scale.setScalar(pulse)
  })

  return (
    <group ref={group} position={[0, -4.6, -2.4]}>
      <mesh rotation={[-Math.PI / 2, 0, 0]}>
        <circleGeometry args={[7.1, 128]} />
        <meshPhysicalMaterial
          color="#020913"
          metalness={0.6}
          roughness={0.22}
          transparent
          opacity={0.88}
        />
      </mesh>

      {[2.5, 4, 5.35, 6.55].map((radius, index) => (
        <mesh key={radius} rotation={[-Math.PI / 2, 0, 0]} position={[0, 0.025 + index * 0.003, 0]}>
          <ringGeometry args={[radius, radius + (index === 2 ? 0.065 : 0.028), 128]} />
          <EmissiveMaterial
            color={index === 2 ? '#72e7ff' : '#1c6f9d'}
            opacity={index === 2 ? 0.82 : 0.48}
          />
        </mesh>
      ))}

      {Array.from({ length: 18 }, (_, index) => {
        const angle = (index / 18) * Math.PI * 2

        return (
          <mesh
            key={index}
            position={[Math.cos(angle) * 6.0, 0.035, Math.sin(angle) * 6.0]}
            rotation={[-Math.PI / 2, 0, -angle]}
          >
            <boxGeometry args={[0.025, 1.15, 0.012]} />
            <EmissiveMaterial color="#165c81" opacity={0.42} />
          </mesh>
        )
      })}
    </group>
  )
}

function CameraRig() {
  useFrame(({ camera, clock, pointer }) => {
    const time = clock.elapsedTime

    const targetX = pointer.x * 0.32 + Math.sin(time * 0.055) * 0.24
    const targetY = 0.2 + pointer.y * 0.15 + Math.sin(time * 0.08) * 0.08

    camera.position.x = THREE.MathUtils.lerp(camera.position.x, targetX, 0.025)
    camera.position.y = THREE.MathUtils.lerp(camera.position.y, targetY, 0.025)
    camera.lookAt(0, -0.08, -2.35)
  })

  return null
}

function AtmosphericDepth() {
  const particles = useRef<THREE.Points>(null)

  const geometry = useMemo(() => {
    const positions: number[] = []

    for (let index = 0; index < 110; index += 1) {
      positions.push(
        THREE.MathUtils.randFloatSpread(24),
        THREE.MathUtils.randFloat(-5, 7),
        THREE.MathUtils.randFloat(-24, -7),
      )
    }

    const buffer = new THREE.BufferGeometry()

    buffer.setAttribute('position', new THREE.Float32BufferAttribute(positions, 3))

    return buffer
  }, [])

  useFrame(({ clock }) => {
    if (!particles.current) {
      return
    }

    particles.current.rotation.y = Math.sin(clock.elapsedTime * 0.035) * 0.035
  })

  return (
    <>
      <points ref={particles} geometry={geometry}>
        <pointsMaterial
          color="#42bfff"
          size={0.035}
          transparent
          opacity={0.24}
          sizeAttenuation
          depthWrite={false}
          toneMapped={false}
        />
      </points>

      <mesh position={[-5.8, 2.4, -12]} scale={[5, 3, 1]}>
        <planeGeometry args={[1, 1]} />

        <meshBasicMaterial
          color="#0b6fa5"
          transparent
          opacity={0.035}
          depthWrite={false}
          toneMapped={false}
        />
      </mesh>

      <mesh position={[6.2, -0.8, -14]} scale={[4.5, 4, 1]}>
        <planeGeometry args={[1, 1]} />

        <meshBasicMaterial
          color="#168bc3"
          transparent
          opacity={0.025}
          depthWrite={false}
          toneMapped={false}
        />
      </mesh>
    </>
  )
}

function ContainerEnvironment() {
  return (
    <>
      <color attach="background" args={['#01050b']} />

      <fog attach="fog" args={['#01050b', 12, 40]} />

      <ambientLight intensity={0.55} />

      <directionalLight position={[5, 10, 9]} intensity={2.2} color="#e1f7ff" />

      <pointLight position={[0, 2.2, 5]} intensity={7.2} distance={22} decay={2} color="#29a8ff" />

      <pointLight
        position={[-10, 1.2, 2.4]}
        intensity={4.2}
        distance={16}
        decay={2}
        color="#1f8dd7"
      />

      <pointLight
        position={[10, -0.2, 2.5]}
        intensity={4.1}
        distance={16}
        decay={2}
        color="#1ea6e0"
      />

      <pointLight
        position={[0, -4.1, 1.0]}
        intensity={3.1}
        distance={13}
        decay={2}
        color="#1278b0"
      />

      <spotLight
        position={[-6, 5, 7]}
        angle={0.45}
        penumbra={0.6}
        intensity={2.5}
        distance={25}
        color="#74ddff"
      />

      <spotLight
        position={[6, 5, 7]}
        angle={0.45}
        penumbra={0.6}
        intensity={2.5}
        distance={25}
        color="#74ddff"
      />

      <CameraRig />

      <AtmosphericDepth />

      {connections.map((connection) => (
        <NetworkConnection key={`${connection.from}-${connection.to}`} definition={connection} />
      ))}

      {pods.map((pod) => (
        <ContainerPod key={pod.id} definition={pod} />
      ))}

      <FloorEnvironment />

      <EffectComposer multisampling={0}>
        <Bloom intensity={1.15} luminanceThreshold={0.38} luminanceSmoothing={0.78} mipmapBlur />
        <Vignette eskil={false} offset={0.08} darkness={0.42} />
      </EffectComposer>
    </>
  )
}

export function LocalContainerScene({
  active,
  onReady,
  onIntroComplete,
}: LocalContainerSceneProps) {
  const rootRef = useRef<HTMLDivElement>(null)

  const [entered, setEntered] = useState(false)

  const completionSentRef = useRef(false)

  const sendCompletion = useCallback(() => {
    if (completionSentRef.current || !onIntroComplete) {
      return
    }

    completionSentRef.current = true
    onIntroComplete()
  }, [onIntroComplete])

  useEffect(() => {
    completionSentRef.current = false
    setEntered(false)

    if (!active) {
      return
    }

    let firstFrame = 0
    let secondFrame = 0

    firstFrame = window.requestAnimationFrame(() => {
      secondFrame = window.requestAnimationFrame(() => {
        setEntered(true)
      })
    })

    return () => {
      window.cancelAnimationFrame(firstFrame)

      window.cancelAnimationFrame(secondFrame)
    }
  }, [active])

  useEffect(() => {
    if (!active || !entered || !onIntroComplete) {
      return
    }

    const node = rootRef.current

    if (!node) {
      return
    }

    let cancelled = false
    let inspectFrame = 0
    let fallbackTimer = 0

    const finishAfterPaint = () => {
      window.requestAnimationFrame(() => {
        window.requestAnimationFrame(() => {
          if (!cancelled) {
            sendCompletion()
          }
        })
      })
    }

    inspectFrame = window.requestAnimationFrame(() => {
      if (cancelled) {
        return
      }

      if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
        finishAfterPaint()
        return
      }

      const animations = node.getAnimations().filter((animation) => {
        const effect = animation.effect

        return effect instanceof KeyframeEffect && effect.target === node
      })

      if (animations.length > 0) {
        void Promise.allSettled(animations.map((animation) => animation.finished)).then(() => {
          if (!cancelled) {
            sendCompletion()
          }
        })

        return
      }

      const styles = window.getComputedStyle(node)

      const durations = styles.transitionDuration.split(',').map((value) => value.trim())

      const delays = styles.transitionDelay.split(',').map((value) => value.trim())

      const toMilliseconds = (value: string) => {
        if (value.endsWith('ms')) {
          return Number.parseFloat(value) || 0
        }

        if (value.endsWith('s')) {
          return (Number.parseFloat(value) || 0) * 1000
        }

        return 0
      }

      const transitionCount = Math.max(durations.length, delays.length)

      let longestTransition = 0

      for (let index = 0; index < transitionCount; index += 1) {
        const duration = toMilliseconds(durations[index % durations.length] ?? '0s')

        const delay = toMilliseconds(delays[index % delays.length] ?? '0s')

        longestTransition = Math.max(longestTransition, duration + delay)
      }

      if (longestTransition <= 0) {
        finishAfterPaint()
        return
      }

      fallbackTimer = window.setTimeout(sendCompletion, longestTransition + 34)
    })

    return () => {
      cancelled = true

      window.cancelAnimationFrame(inspectFrame)

      window.clearTimeout(fallbackTimer)
    }
  }, [active, entered, onIntroComplete, sendCompletion])

  return (
    <div
      ref={rootRef}
      className={['local-container-scene', active && entered ? 'local-container-scene--active' : '']
        .filter(Boolean)
        .join(' ')}
      aria-hidden={!active}
      onTransitionEnd={(event) => {
        if (
          !active ||
          !entered ||
          completionSentRef.current ||
          event.target !== event.currentTarget ||
          event.propertyName !== 'transform'
        ) {
          return
        }

        sendCompletion()
      }}
    >
      <Canvas
        dpr={[1, 2]}
        camera={{
          position: [0, 0.25, 16.4],
          fov: 42,
          near: 0.1,
          far: 60,
        }}
        gl={{
          antialias: true,
          alpha: false,
          powerPreference: 'high-performance',
        }}
      >
        <Suspense fallback={null}>
          <ContainerEnvironment />

          <SceneReadyProbe onReady={onReady} />
        </Suspense>
      </Canvas>
    </div>
  )
}

export default LocalContainerScene
