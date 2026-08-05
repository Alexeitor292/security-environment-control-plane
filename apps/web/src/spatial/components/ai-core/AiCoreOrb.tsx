import { Canvas, useFrame, useThree } from '@react-three/fiber'
import type { ButtonHTMLAttributes, HTMLAttributes } from 'react'
import { useEffect, useMemo, useRef } from 'react'
import * as THREE from 'three'
import './AiCoreOrb.css'

export type AiCoreState = 'idle' | 'listening' | 'thinking' | 'executing' | 'approval' | 'complete'

export interface GradientOrbConfig {
  background?: string
  hue?: number
  innerRadius?: number
  noiseScale?: number
  rotationSpeed?: number
}

interface AiCoreOrbButtonProps extends Omit<ButtonHTMLAttributes<HTMLButtonElement>, 'children'> {
  active?: boolean
  label?: string
  state?: AiCoreState
}

interface AiCoreLoaderProps extends Omit<HTMLAttributes<HTMLDivElement>, 'children'> {
  label?: string
  size?: 'small' | 'medium' | 'large'
}

const defaults: Required<GradientOrbConfig> = {
  background: 'transparent',
  hue: 0,
  innerRadius: 0.1,
  noiseScale: 0.65,
  rotationSpeed: 0.3,
}

const stateConfig: Record<AiCoreState, Partial<GradientOrbConfig>> = {
  idle: {
    hue: 0,
    innerRadius: 0.1,
    noiseScale: 0.62,
    rotationSpeed: 0.22,
  },

  listening: {
    hue: 4,
    innerRadius: 0.085,
    noiseScale: 0.72,
    rotationSpeed: 0.38,
  },

  thinking: {
    hue: -8,
    innerRadius: 0.075,
    noiseScale: 0.92,
    rotationSpeed: 0.72,
  },

  executing: {
    hue: 10,
    innerRadius: 0.08,
    noiseScale: 0.8,
    rotationSpeed: 0.58,
  },

  approval: {
    hue: -18,
    innerRadius: 0.11,
    noiseScale: 0.58,
    rotationSpeed: 0.18,
  },

  complete: {
    hue: 6,
    innerRadius: 0.12,
    noiseScale: 0.54,
    rotationSpeed: 0.12,
  },
}

const vertexShader = /* glsl */ `
  varying vec2 vUv;

  void main() {
    vUv = uv;
    gl_Position = vec4(position.xy, 0.0, 1.0);
  }
`

const fragmentShader = /* glsl */ `
  precision highp float;

  uniform float iTime;
  uniform vec3 iResolution;
  uniform float hue;
  uniform float rot;
  uniform float noiseScale;
  uniform float innerRadius;

  varying vec2 vUv;

  vec3 rgb2yiq(vec3 c) {
    return vec3(
      dot(c, vec3(0.299, 0.587, 0.114)),
      dot(c, vec3(0.596, -0.274, -0.322)),
      dot(c, vec3(0.211, -0.523, 0.312))
    );
  }

  vec3 yiq2rgb(vec3 c) {
    return vec3(
      c.x + 0.956 * c.y + 0.621 * c.z,
      c.x - 0.272 * c.y - 0.647 * c.z,
      c.x - 1.106 * c.y + 1.703 * c.z
    );
  }

  vec3 adjustHue(
    vec3 color,
    float hueDeg
  ) {
    float hueRad = radians(hueDeg);
    vec3 yiq = rgb2yiq(color);
    float cosA = cos(hueRad);
    float sinA = sin(hueRad);

    yiq.yz = vec2(
      yiq.y * cosA - yiq.z * sinA,
      yiq.y * sinA + yiq.z * cosA
    );

    return yiq2rgb(yiq);
  }

  vec3 hash33(vec3 p3) {
    p3 = fract(
      p3 *
      vec3(
        0.1031,
        0.11369,
        0.13787
      )
    );

    p3 += dot(
      p3,
      p3.yxz + 19.19
    );

    return -1.0 + 2.0 * fract(
      vec3(
        p3.x + p3.y,
        p3.x + p3.z,
        p3.y + p3.z
      ) * p3.zyx
    );
  }

  float snoise3(vec3 p) {
    const float K1 = 0.333333333;
    const float K2 = 0.166666667;

    vec3 i = floor(
      p +
      (p.x + p.y + p.z) * K1
    );

    vec3 d0 = p - (
      i -
      (i.x + i.y + i.z) * K2
    );

    vec3 e = step(
      vec3(0.0),
      d0 - d0.yzx
    );

    vec3 i1 =
      e * (1.0 - e.zxy);

    vec3 i2 =
      1.0 -
      e.zxy * (1.0 - e);

    vec3 d1 =
      d0 - (i1 - K2);

    vec3 d2 =
      d0 - (i2 - K1);

    vec3 d3 =
      d0 - 0.5;

    vec4 h = max(
      0.6 -
      vec4(
        dot(d0, d0),
        dot(d1, d1),
        dot(d2, d2),
        dot(d3, d3)
      ),
      0.0
    );

    vec4 n =
      h * h * h * h *
      vec4(
        dot(
          d0,
          hash33(i)
        ),
        dot(
          d1,
          hash33(i + i1)
        ),
        dot(
          d2,
          hash33(i + i2)
        ),
        dot(
          d3,
          hash33(i + 1.0)
        )
      );

    return dot(
      vec4(31.316),
      n
    );
  }

  vec4 extractAlpha(vec3 colorIn) {
    float alpha = max(
      max(
        colorIn.r,
        colorIn.g
      ),
      colorIn.b
    );

    return vec4(
      colorIn.rgb /
      (alpha + 0.00001),
      alpha
    );
  }

  // SECP palette:
  // deep cobalt, electric cyan,
  // pale ice blue, and navy-black.
  const vec3 baseColor0 =
    vec3(0.015, 0.18, 0.58);

  const vec3 baseColor1 =
    vec3(0.0, 0.68, 1.0);

  const vec3 baseColor2 =
    vec3(0.45, 0.93, 1.0);

  const vec3 baseColor3 =
    vec3(0.0, 0.012, 0.035);

  float light1(
    float intensity,
    float attenuation,
    float distanceValue
  ) {
    return intensity /
      (
        1.0 +
        distanceValue * attenuation
      );
  }

  float light2(
    float intensity,
    float attenuation,
    float distanceValue
  ) {
    return intensity /
      (
        1.0 +
        distanceValue *
        distanceValue *
        attenuation
      );
  }

  vec4 draw(vec2 uv) {
    vec3 color0 =
      adjustHue(baseColor0, hue);

    vec3 color1 =
      adjustHue(baseColor1, hue);

    vec3 color2 =
      adjustHue(baseColor2, hue);

    vec3 color3 =
      adjustHue(baseColor3, hue);

    float len = length(uv);

    float invLen =
      len > 0.0
        ? 1.0 / len
        : 0.0;

    float pulse =
      sin(iTime * 1.5) * 0.02;

    float n0 =
      snoise3(
        vec3(
          uv * noiseScale,
          iTime * 0.5
        )
      ) * 0.5 + 0.5;

    float r0 = mix(
      mix(
        innerRadius + pulse,
        1.0,
        0.4
      ),
      mix(
        innerRadius + pulse,
        1.0,
        0.6
      ),
      n0
    );

    float d0 = distance(
      uv,
      (r0 * invLen) * uv
    );

    float v0 =
      light1(
        1.0,
        10.0,
        d0
      );

    v0 *= smoothstep(
      r0 * 1.05,
      r0,
      len
    );

    float colorLine =
      cos(
        atan(uv.y, uv.x) +
        iTime * 2.0
      ) * 0.5 + 0.5;

    float angle =
      iTime * -1.0;

    vec2 lightPosition =
      vec2(
        cos(angle),
        sin(angle)
      ) * r0;

    float distanceToLight =
      distance(
        uv,
        lightPosition
      );

    float v1 =
      light2(
        1.5,
        5.0,
        distanceToLight
      );

    v1 *= light1(
      1.0,
      50.0,
      d0
    );

    float v2 = smoothstep(
      1.0,
      mix(
        innerRadius,
        1.0,
        n0 * 0.5
      ),
      len
    );

    float v3 = smoothstep(
      innerRadius,
      mix(
        innerRadius,
        1.0,
        0.5
      ),
      len
    );

    vec3 color = mix(
      color1,
      color2,
      colorLine
    );

    color = mix(
      color,
      color0,
      n0
    );

    color = mix(
      color3,
      color,
      v0
    );

    color =
      (color + v1) *
      v2 *
      v3;

    color = clamp(
      color,
      0.0,
      1.0
    );

    return extractAlpha(color);
  }

  void main() {
    vec2 center =
      iResolution.xy * 0.5;

    float size =
      min(
        iResolution.x,
        iResolution.y
      );

    vec2 uv = (
      vUv * iResolution.xy -
      center
    ) / size * 2.0;

    float sinRotation = sin(rot);
    float cosRotation = cos(rot);

    uv = vec2(
      cosRotation * uv.x -
      sinRotation * uv.y,
      sinRotation * uv.x +
      cosRotation * uv.y
    );

    vec4 color = draw(uv);

    gl_FragColor = vec4(
      color.rgb * color.a,
      color.a
    );
  }
`

function GradientScene({ config }: { config: Required<GradientOrbConfig> }) {
  const materialRef = useRef<THREE.ShaderMaterial>(null)

  const { gl, size } = useThree()

  const rotationRef = useRef(0)
  const lastTimeRef = useRef(0)

  const geometry = useMemo(() => {
    const result = new THREE.BufferGeometry()

    result.setAttribute(
      'position',
      new THREE.Float32BufferAttribute([-1, -1, 0, 3, -1, 0, -1, 3, 0], 3),
    )

    result.setAttribute('uv', new THREE.Float32BufferAttribute([0, 0, 2, 0, 0, 2], 2))

    return result
  }, [])

  useEffect(() => {
    return () => {
      geometry.dispose()
    }
  }, [geometry])

  const uniforms = useMemo(
    () => ({
      hue: {
        value: config.hue,
      },

      innerRadius: {
        value: config.innerRadius,
      },

      iResolution: {
        value: new THREE.Vector3(size.width, size.height, 1),
      },

      iTime: {
        value: 0,
      },

      noiseScale: {
        value: config.noiseScale,
      },

      rot: {
        value: 0,
      },
    }),
    [config.hue, config.innerRadius, config.noiseScale, size.height, size.width],
  )

  useFrame((state) => {
    const material = materialRef.current

    if (!material) {
      return
    }

    const elapsed = state.clock.elapsedTime

    const delta = Math.min(0.05, Math.max(0, elapsed - lastTimeRef.current))

    lastTimeRef.current = elapsed

    rotationRef.current += delta * config.rotationSpeed

    const pixelRatio = gl.getPixelRatio()

    material.uniforms.iTime.value = elapsed

    material.uniforms.hue.value = config.hue

    material.uniforms.rot.value = rotationRef.current

    material.uniforms.noiseScale.value = config.noiseScale

    material.uniforms.innerRadius.value = config.innerRadius

    material.uniforms.iResolution.value.set(
      size.width * pixelRatio,
      size.height * pixelRatio,
      size.width / Math.max(1, size.height),
    )
  })

  return (
    <mesh frustumCulled={false} geometry={geometry}>
      <shaderMaterial
        ref={materialRef}
        depthTest={false}
        depthWrite={false}
        fragmentShader={fragmentShader}
        transparent
        uniforms={uniforms}
        vertexShader={vertexShader}
      />
    </mesh>
  )
}

export function GradientOrb({
  className = '',
  config: configOverrides,
}: {
  className?: string
  config?: GradientOrbConfig
}) {
  const configKey = JSON.stringify(configOverrides ?? {})

  const config = useMemo(
    () => ({
      ...defaults,
      ...configOverrides,
    }),
    // The serialized key keeps this stable
    // for object-literal call sites.
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [configKey],
  )

  return (
    <span
      className={['gradient-orb', className].filter(Boolean).join(' ')}
      style={{
        background: config.background,
      }}
      aria-hidden="true"
    >
      <Canvas
        dpr={[1, 2]}
        frameloop="always"
        gl={{
          alpha: true,
          antialias: true,
          powerPreference: 'high-performance',
          premultipliedAlpha: true,
        }}
        camera={{
          position: [0, 0, 1],
        }}
      >
        <GradientScene config={config} />
      </Canvas>
    </span>
  )
}

export function AiCoreOrbButton({
  active = false,
  className,
  label = 'Ask SECP',
  state = active ? 'listening' : 'idle',
  type = 'button',
  ...buttonProps
}: AiCoreOrbButtonProps) {
  const config = {
    ...stateConfig[state],
  }

  return (
    <button
      {...buttonProps}
      className={['ai-core-orb-button', active ? 'ai-core-orb-button--active' : '', className]
        .filter(Boolean)
        .join(' ')}
      type={type}
      aria-expanded={active}
      aria-label={label}
      data-state={state}
    >
      <span className="ai-core-orb-button__halo" />

      <GradientOrb className="ai-core-orb-button__shader" config={config} />

      <span className="ai-core-orb-button__focus-ring" />

      <span className="ai-core-orb-button__label">{label}</span>
    </button>
  )
}

export function AiCoreLoader({
  className,
  label = 'Loading',
  size = 'medium',
  ...containerProps
}: AiCoreLoaderProps) {
  return (
    <div
      {...containerProps}
      className={['ai-core-loader', `ai-core-loader--${size}`, className].filter(Boolean).join(' ')}
      role="status"
      aria-label={label}
    >
      <GradientOrb
        config={{
          innerRadius: 0.075,
          noiseScale: 0.9,
          rotationSpeed: 0.72,
        }}
      />
    </div>
  )
}

export default GradientOrb
