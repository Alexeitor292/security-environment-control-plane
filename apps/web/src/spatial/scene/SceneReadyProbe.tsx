import { useFrame } from '@react-three/fiber'
import { useEffect, useRef } from 'react'

interface SceneReadyProbeProps {
  onReady?: () => void
}

export function SceneReadyProbe({ onReady }: SceneReadyProbeProps) {
  const renderedFramesRef = useRef(0)
  const sentRef = useRef(false)

  useEffect(() => {
    renderedFramesRef.current = 0
    sentRef.current = false
  }, [onReady])

  useFrame(() => {
    if (!onReady || sentRef.current) {
      return
    }

    renderedFramesRef.current += 1

    if (renderedFramesRef.current < 2) {
      return
    }

    sentRef.current = true

    window.requestAnimationFrame(() => {
      onReady()
    })
  })

  return null
}
