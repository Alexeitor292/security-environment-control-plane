import { sceneConfig } from '../config/scene'
import { ServerRack } from './ServerRack'

interface ServerLaneProps {
  active: boolean
  side: -1 | 1
}

export function ServerLane({ active, side }: ServerLaneProps) {
  const { bankCount, racksPerBank, rackPitch, serviceGap, nearestZ, xOffset } = sceneConfig.lane

  const rackCount = bankCount * racksPerBank

  const bankSpan = racksPerBank * rackPitch
  const bankStride = bankSpan + serviceGap

  const racks = Array.from({ length: rackCount }, (_, index) => {
    const bankIndex = Math.floor(index / racksPerBank)

    const slotIndex = index % racksPerBank

    const z = nearestZ - bankIndex * bankStride - slotIndex * rackPitch

    /*
     * The far end forms first, then the emergence wave moves
     * toward the person walking into the aisle.
     */
    const reverseIndex = rackCount - 1 - index

    const delay = reverseIndex * 0.052 + (side === 1 ? 0.045 : 0)

    const yaw = side === -1 ? Math.PI / 2 : -Math.PI / 2

    return {
      bankIndex,
      delay,
      index,
      slotIndex,
      yaw,
      z,
    }
  })

  return (
    <group>
      {racks.map(({ bankIndex, delay, index, slotIndex, yaw, z }) => (
        <ServerRack
          key={`${side}-${bankIndex}-${slotIndex}-${index}`}
          active={active}
          delay={delay}
          side={side}
          x={side * xOffset}
          z={z}
          yaw={yaw}
        />
      ))}
    </group>
  )
}
