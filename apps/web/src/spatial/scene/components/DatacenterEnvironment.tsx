import { MeshReflectorMaterial, Sparkles } from '@react-three/drei'
import { sceneConfig } from '../config/scene'

const { bankCount, racksPerBank, rackPitch, serviceGap, nearestZ } = sceneConfig.lane

const bankSpan = racksPerBank * rackPitch
const bankStride = bankSpan + serviceGap

const crossAisles = Array.from({ length: bankCount - 1 }, (_, bankIndex) => {
  const lastRackOfBank = nearestZ - bankIndex * bankStride - (racksPerBank - 1) * rackPitch

  const firstRackOfNextBank = nearestZ - (bankIndex + 1) * bankStride

  return (lastRackOfBank + firstRackOfNextBank) / 2
})

const architecturalFrames = Array.from({ length: 11 }, (_, index) => 7 - index * 4.25)

const ceilingPanels = Array.from({ length: 18 }, (_, index) => 8 - index * 2.7)

const floorGuides = [-4.25, -2.15, 2.15, 4.25]

export function DatacenterEnvironment() {
  const { ceilingY, corridorCenterZ, corridorLength, corridorWidth } = sceneConfig.environment

  return (
    <group>
      {/* Grand reflective technical floor */}
      <mesh position={[0, -0.04, corridorCenterZ]} rotation={[-Math.PI / 2, 0, 0]} receiveShadow>
        <planeGeometry args={[corridorWidth + 3, corridorLength]} />

        <MeshReflectorMaterial
          blur={[500, 150]}
          resolution={512}
          mixBlur={1}
          mixStrength={4.8}
          mirror={0.2}
          roughness={0.52}
          depthScale={0.5}
          minDepthThreshold={0.22}
          maxDepthThreshold={1.55}
          color="#06101d"
          metalness={0.28}
        />
      </mesh>

      {/* Soft illuminated center promenade */}
      <mesh position={[0, -0.008, corridorCenterZ]} rotation={[-Math.PI / 2, 0, 0]}>
        <planeGeometry args={[2.6, corridorLength - 2]} />

        <meshStandardMaterial
          color="#061629"
          emissive="#082e59"
          emissiveIntensity={0.5}
          roughness={0.72}
          metalness={0.12}
          transparent
          opacity={0.9}
        />
      </mesh>

      {/* Center aisle edge lighting */}
      {[-1.34, 1.34].map((x) => (
        <mesh
          key={`center-${x}`}
          position={[x, 0.008, corridorCenterZ]}
          rotation={[-Math.PI / 2, 0, 0]}
        >
          <planeGeometry args={[0.028, corridorLength - 2]} />

          <meshBasicMaterial color="#47a9ff" transparent opacity={0.7} toneMapped={false} />
        </mesh>
      ))}

      {/* Rack lane floor guides */}
      {floorGuides.map((x) => (
        <mesh key={x} position={[x, 0.007, corridorCenterZ]} rotation={[-Math.PI / 2, 0, 0]}>
          <planeGeometry args={[0.022, corridorLength - 2]} />

          <meshBasicMaterial color="#1e79c8" transparent opacity={0.28} toneMapped={false} />
        </mesh>
      ))}

      {/* Cross-paths between five-rack banks */}
      {crossAisles.map((z) => (
        <group key={z}>
          <mesh position={[0, -0.012, z]} rotation={[-Math.PI / 2, 0, 0]}>
            <planeGeometry args={[corridorWidth - 0.4, serviceGap]} />

            <meshStandardMaterial color="#071a2c" roughness={0.68} metalness={0.14} />
          </mesh>

          {[serviceGap / 2 - 0.08, -serviceGap / 2 + 0.08].map((offset) => (
            <mesh key={offset} position={[0, 0.008, z + offset]} rotation={[-Math.PI / 2, 0, 0]}>
              <planeGeometry args={[corridorWidth - 0.65, 0.025]} />

              <meshBasicMaterial color="#3a9df1" transparent opacity={0.5} toneMapped={false} />
            </mesh>
          ))}
        </group>
      ))}

      {/* Architectural side walls */}
      {[-1, 1].map((side) => (
        <mesh
          key={`wall-${side}`}
          position={[(side * corridorWidth) / 2, ceilingY / 2, corridorCenterZ]}
          rotation={[0, side === -1 ? Math.PI / 2 : -Math.PI / 2, 0]}
        >
          <planeGeometry args={[corridorLength, ceilingY]} />

          <meshStandardMaterial color="#040a13" roughness={0.72} metalness={0.14} />
        </mesh>
      ))}

      {/* Actual ceiling surface */}
      <mesh position={[0, ceilingY + 0.04, corridorCenterZ]} rotation={[Math.PI / 2, 0, 0]}>
        <planeGeometry args={[corridorWidth, corridorLength]} />

        <meshStandardMaterial color="#07111e" roughness={0.62} metalness={0.2} />
      </mesh>

      {/* Large illuminated portal frames */}
      {architecturalFrames.map((z, index) => (
        <group key={`frame-${z}`}>
          <mesh position={[-corridorWidth / 2 + 0.16, ceilingY / 2, z]}>
            <boxGeometry args={[0.18, ceilingY, 0.18]} />

            <meshStandardMaterial color="#0d1c2b" roughness={0.54} metalness={0.28} />
          </mesh>

          <mesh position={[corridorWidth / 2 - 0.16, ceilingY / 2, z]}>
            <boxGeometry args={[0.18, ceilingY, 0.18]} />

            <meshStandardMaterial color="#0d1c2b" roughness={0.54} metalness={0.28} />
          </mesh>

          <mesh position={[0, ceilingY - 0.08, z]}>
            <boxGeometry args={[corridorWidth, 0.18, 0.18]} />

            <meshStandardMaterial color="#102234" roughness={0.48} metalness={0.3} />
          </mesh>

          {index % 2 === 0 && (
            <>
              <mesh position={[-corridorWidth / 2 + 0.12, ceilingY / 2, z + 0.11]}>
                <boxGeometry args={[0.035, ceilingY - 0.7, 0.035]} />

                <meshStandardMaterial
                  color="#5cb8ff"
                  emissive="#158cff"
                  emissiveIntensity={4.5}
                  toneMapped={false}
                />
              </mesh>

              <mesh position={[corridorWidth / 2 - 0.12, ceilingY / 2, z + 0.11]}>
                <boxGeometry args={[0.035, ceilingY - 0.7, 0.035]} />

                <meshStandardMaterial
                  color="#5cb8ff"
                  emissive="#158cff"
                  emissiveIntensity={4.5}
                  toneMapped={false}
                />
              </mesh>
            </>
          )}
        </group>
      ))}

      {/* Layered ceiling panels and light rails */}
      {ceilingPanels.map((z, index) => (
        <group key={`ceiling-${z}`}>
          <mesh position={[0, ceilingY - 0.12, z]}>
            <boxGeometry args={[corridorWidth - 0.7, 0.09, 2.35]} />

            <meshStandardMaterial
              color={index % 2 === 0 ? '#0a1828' : '#081321'}
              roughness={0.58}
              metalness={0.22}
            />
          </mesh>

          {[-2.8, 0, 2.8].map((x) => (
            <mesh key={x} position={[x, ceilingY - 0.2, z]}>
              <boxGeometry args={[0.055, 0.04, 1.85]} />

              <meshStandardMaterial
                color="#d9efff"
                emissive={x === 0 ? '#eaf7ff' : '#4ea8ff'}
                emissiveIntensity={x === 0 ? 3.7 : 5.4}
                toneMapped={false}
              />
            </mesh>
          ))}
        </group>
      ))}

      {/* Long perspective light rails */}
      {[-3.2, 3.2].map((x) => (
        <mesh key={`rail-${x}`} position={[x, ceilingY - 0.27, corridorCenterZ]}>
          <boxGeometry args={[0.04, 0.04, corridorLength - 2]} />

          <meshStandardMaterial
            color="#bfe4ff"
            emissive="#369cff"
            emissiveIntensity={4.7}
            toneMapped={false}
          />
        </mesh>
      ))}

      {/* Luminous destination portal */}
      <group position={[0, 0, -37]}>
        <mesh position={[0, ceilingY / 2, 0]}>
          <planeGeometry args={[corridorWidth - 0.7, ceilingY - 0.25]} />

          <meshStandardMaterial
            color="#071527"
            emissive="#062b54"
            emissiveIntensity={1.4}
            roughness={0.64}
            metalness={0.1}
          />
        </mesh>

        <mesh position={[0, ceilingY / 2, 0.06]}>
          <planeGeometry args={[3.6, 2.5]} />

          <meshBasicMaterial color="#0c75c9" transparent opacity={0.13} toneMapped={false} />
        </mesh>

        <pointLight
          position={[0, ceilingY / 2, 2]}
          intensity={28}
          distance={18}
          decay={2}
          color="#3d9fff"
        />
      </group>

      {/* Subtle atmospheric data particles */}
      <Sparkles
        count={110}
        scale={[corridorWidth - 1, ceilingY - 0.8, corridorLength - 8]}
        position={[0, ceilingY / 2, corridorCenterZ]}
        size={1.15}
        speed={0.08}
        opacity={0.22}
        color="#69baff"
        noise={0.7}
      />

      {/* Balanced architectural illumination */}
      <hemisphereLight args={['#bbdfff', '#010308', 0.72]} />

      <ambientLight intensity={0.28} />

      <directionalLight
        position={[0, 8, 9]}
        intensity={1.7}
        color="#e3f2ff"
        castShadow
        shadow-mapSize-width={1024}
        shadow-mapSize-height={1024}
      />

      <pointLight
        position={[-3.9, 2.3, 5]}
        intensity={16}
        distance={17}
        decay={2}
        color="#228eff"
      />

      <pointLight position={[3.9, 2.3, 5]} intensity={16} distance={17} decay={2} color="#228eff" />

      <pointLight position={[0, 2.4, -7]} intensity={19} distance={25} decay={2} color="#58aaff" />

      <pointLight position={[0, 2.7, -24]} intensity={20} distance={23} decay={2} color="#80c3ff" />
    </group>
  )
}
