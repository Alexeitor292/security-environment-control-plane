import { useEffect, useMemo, useRef } from 'react'
import { Canvas, useFrame, useThree } from '@react-three/fiber'
import * as THREE from 'three'

export type GradientOrbConfig = {
  background?: string
  hue?: number
  noiseScale?: number
  innerRadius?: number
  energySpeed?: number
  glowStrength?: number
  edgeSoftness?: number
}

const defaults: Required<GradientOrbConfig> = {
  background: 'transparent',
  hue: 0,
  noiseScale: 0.68,
  innerRadius: 0.13,
  energySpeed: 0.3,
  glowStrength: 0.76,
  edgeSoftness: 0.04,
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

  uniform float animationTime;
  uniform vec3 iResolution;
  uniform float hue;
  uniform float noiseScale;
  uniform float innerRadius;
  uniform float glowStrength;
  uniform float edgeSoftness;

  varying vec2 vUv;

  vec3 rgb2yiq(vec3 color) {
    return vec3(
      dot(color, vec3(0.299, 0.587, 0.114)),
      dot(color, vec3(0.596, -0.274, -0.322)),
      dot(color, vec3(0.211, -0.523, 0.312))
    );
  }

  vec3 yiq2rgb(vec3 color) {
    return vec3(
      color.x + 0.956 * color.y + 0.621 * color.z,
      color.x - 0.272 * color.y - 0.647 * color.z,
      color.x - 1.106 * color.y + 1.703 * color.z
    );
  }

  vec3 adjustHue(
    vec3 color,
    float hueDegrees
  ) {
    float hueRadians =
      radians(hueDegrees);

    vec3 yiq =
      rgb2yiq(color);

    float cosine =
      cos(hueRadians);

    float sine =
      sin(hueRadians);

    yiq.yz =
      vec2(
        yiq.y * cosine -
        yiq.z * sine,

        yiq.y * sine +
        yiq.z * cosine
      );

    return yiq2rgb(yiq);
  }

  vec3 hash33(vec3 point) {
    point =
      fract(
        point *
        vec3(
          0.1031,
          0.11369,
          0.13787
        )
      );

    point +=
      dot(
        point,
        point.yxz + 19.19
      );

    return
      -1.0 +
      2.0 *
      fract(
        vec3(
          point.x + point.y,
          point.x + point.z,
          point.y + point.z
        ) *
        point.zyx
      );
  }

  float snoise3(vec3 point) {
    const float K1 =
      0.333333333;

    const float K2 =
      0.166666667;

    vec3 cell =
      floor(
        point +
        (
          point.x +
          point.y +
          point.z
        ) *
        K1
      );

    vec3 delta0 =
      point -
      (
        cell -
        (
          cell.x +
          cell.y +
          cell.z
        ) *
        K2
      );

    vec3 edge =
      step(
        vec3(0.0),
        delta0 -
        delta0.yzx
      );

    vec3 index1 =
      edge *
      (
        1.0 -
        edge.zxy
      );

    vec3 index2 =
      1.0 -
      edge.zxy *
      (
        1.0 -
        edge
      );

    vec3 delta1 =
      delta0 -
      (
        index1 -
        K2
      );

    vec3 delta2 =
      delta0 -
      (
        index2 -
        K1
      );

    vec3 delta3 =
      delta0 -
      0.5;

    vec4 falloff =
      max(
        0.6 -
        vec4(
          dot(delta0, delta0),
          dot(delta1, delta1),
          dot(delta2, delta2),
          dot(delta3, delta3)
        ),
        0.0
      );

    vec4 contribution =
      falloff *
      falloff *
      falloff *
      falloff *
      vec4(
        dot(
          delta0,
          hash33(cell)
        ),

        dot(
          delta1,
          hash33(
            cell +
            index1
          )
        ),

        dot(
          delta2,
          hash33(
            cell +
            index2
          )
        ),

        dot(
          delta3,
          hash33(
            cell +
            1.0
          )
        )
      );

    return dot(
      vec4(31.316),
      contribution
    );
  }

  float lightLinear(
    float intensity,
    float attenuation,
    float distanceValue
  ) {
    return
      intensity /
      (
        1.0 +
        distanceValue *
        attenuation
      );
  }

  float lightQuadratic(
    float intensity,
    float attenuation,
    float distanceValue
  ) {
    return
      intensity /
      (
        1.0 +
        distanceValue *
        distanceValue *
        attenuation
      );
  }

  vec4 renderOrb(vec2 uv) {
    const vec3 iceCyan =
      vec3(
        0.50,
        0.89,
        1.00
      );

    const vec3 electricBlue =
      vec3(
        0.04,
        0.51,
        1.00
      );

    const vec3 deepBlue =
      vec3(
        0.008,
        0.13,
        0.34
      );

    const vec3 blueBlack =
      vec3(
        0.001,
        0.006,
        0.018
      );

    vec3 color0 =
      adjustHue(
        iceCyan,
        hue
      );

    vec3 color1 =
      adjustHue(
        electricBlue,
        hue
      );

    vec3 color2 =
      adjustHue(
        deepBlue,
        hue
      );

    vec3 color3 =
      adjustHue(
        blueBlack,
        hue
      );

    float radialDistance =
      length(uv);

    float inverseDistance =
      radialDistance > 0.0
        ? 1.0 / radialDistance
        : 0.0;

    /*
     * animationTime is accumulated frame by frame in JavaScript.
     * It is never calculated by multiplying total elapsed time.
     */
    float animatedTime =
      animationTime;

    float pulse =
      sin(
        animatedTime *
        2.0
      ) *
      0.012;

    float noiseValue =
      snoise3(
        vec3(
          uv *
          noiseScale,

          animatedTime
        )
      ) *
      0.5 +
      0.5;

    float secondaryNoise =
      snoise3(
        vec3(
          uv.yx *
          (
            noiseScale *
            1.45
          ) +
          vec2(
            0.8,
            -0.45
          ),

          animatedTime *
          0.72 +
          5.0
        )
      ) *
      0.5 +
      0.5;

    float combinedNoise =
      mix(
        noiseValue,
        secondaryNoise,
        0.3
      );

    float orbRadius =
      mix(
        mix(
          innerRadius +
          pulse,
          1.0,
          0.39
        ),

        mix(
          innerRadius +
          pulse,
          1.0,
          0.61
        ),

        combinedNoise
      );

    float edgeDistance =
      distance(
        uv,

        (
          orbRadius *
          inverseDistance
        ) *
        uv
      );

    float bodyLight =
      lightLinear(
        1.0,
        15.0,
        edgeDistance
      );

    bodyLight *=
      smoothstep(
        orbRadius +
        edgeSoftness,

        orbRadius -
        edgeSoftness,

        radialDistance
      );

    float angularFlow =
      cos(
        atan(
          uv.y,
          uv.x
        ) +
        animatedTime *
        1.35 +
        combinedNoise *
        2.4
      ) *
      0.5 +
      0.5;

    float orbitAngle =
      animatedTime *
      -0.7;

    vec2 movingLightPosition =
      vec2(
        cos(orbitAngle),
        sin(orbitAngle)
      ) *
      orbRadius *
      0.92;

    float movingLightDistance =
      distance(
        uv,
        movingLightPosition
      );

    float movingLight =
      lightQuadratic(
        1.05,
        9.0,
        movingLightDistance
      );

    movingLight *=
      lightLinear(
        1.0,
        58.0,
        edgeDistance
      );

    float outerMask =
      1.0 -
      smoothstep(
        0.88,
        1.02,
        radialDistance
      );

    float innerMask =
      smoothstep(
        innerRadius -
        0.035,

        innerRadius +
        0.14,

        radialDistance
      );

    vec3 color =
      mix(
        color1,
        color2,
        angularFlow
      );

    color =
      mix(
        color,
        color0,
        combinedNoise
      );

    color =
      mix(
        color3,
        color,
        bodyLight
      );

    vec3 filamentColor =
      mix(
        color0,

        vec3(
          0.85,
          0.97,
          1.0
        ),

        0.4
      );

    color +=
      filamentColor *
      movingLight *
      glowStrength;

    float edgeFilament =
      pow(
        clamp(
          bodyLight,
          0.0,
          1.0
        ),
        2.2
      );

    color +=
      filamentColor *
      edgeFilament *
      glowStrength *
      0.22;

    color *=
      outerMask *
      innerMask;

    color =
      clamp(
        color,
        0.0,
        1.0
      );

    float luminanceAlpha =
      max(
        max(
          color.r,
          color.g
        ),
        color.b
      );

    float circularAlpha =
      1.0 -
      smoothstep(
        0.88,
        1.0,
        radialDistance
      );

    float alpha =
      clamp(
        luminanceAlpha *
        circularAlpha,
        0.0,
        1.0
      );

    vec3 unpremultipliedColor =
      color /
      max(
        alpha,
        0.00001
      );

    return vec4(
      unpremultipliedColor,
      alpha
    );
  }

  void main() {
    vec2 center =
      iResolution.xy *
      0.5;

    float renderSize =
      min(
        iResolution.x,
        iResolution.y
      );

    vec2 uv =
      (
        vUv *
        iResolution.xy -
        center
      ) /
      renderSize *
      2.0;

    vec4 orb =
      renderOrb(uv);

    gl_FragColor =
      vec4(
        orb.rgb *
        orb.a,

        orb.a
      );
  }
`

interface GradientSceneProps {
  targetConfig: Required<GradientOrbConfig>
}

function GradientScene({ targetConfig }: GradientSceneProps) {
  const materialRef = useRef<THREE.ShaderMaterial>(null)

  const { size, viewport } = useThree()

  /*
   * This clock is independent of the R3F elapsed-time clock.
   * It advances only by delta * current speed.
   */
  const animationTimeRef = useRef(0)

  const currentValues = useRef({
    hue: targetConfig.hue,

    noiseScale: targetConfig.noiseScale,

    innerRadius: targetConfig.innerRadius,

    energySpeed: targetConfig.energySpeed,

    glowStrength: targetConfig.glowStrength,

    edgeSoftness: targetConfig.edgeSoftness,
  })

  const geometry = useMemo(() => {
    const buffer = new THREE.BufferGeometry()

    buffer.setAttribute(
      'position',
      new THREE.Float32BufferAttribute(
        [
          -1, -1, 0,

          3, -1, 0,

          -1, 3, 0,
        ],
        3,
      ),
    )

    buffer.setAttribute(
      'uv',
      new THREE.Float32BufferAttribute(
        [
          0, 0,

          2, 0,

          0, 2,
        ],
        2,
      ),
    )

    return buffer
  }, [])

  useEffect(() => {
    return () => {
      geometry.dispose()
    }
  }, [geometry])

  const uniforms = useMemo(
    () => ({
      animationTime: {
        value: 0,
      },

      iResolution: {
        value: new THREE.Vector3(),
      },

      hue: {
        value: targetConfig.hue,
      },

      noiseScale: {
        value: targetConfig.noiseScale,
      },

      innerRadius: {
        value: targetConfig.innerRadius,
      },

      glowStrength: {
        value: targetConfig.glowStrength,
      },

      edgeSoftness: {
        value: targetConfig.edgeSoftness,
      },
    }),
    [],
  )

  useFrame((_, rawDelta) => {
    const material = materialRef.current

    if (!material) {
      return
    }

    /*
     * Prevent a tab switch, breakpoint, or lag spike from advancing
     * the animation by a huge amount in one frame.
     */
    const delta = Math.min(rawDelta, 1 / 20)

    const current = currentValues.current

    current.hue = THREE.MathUtils.damp(current.hue, targetConfig.hue, 4, delta)

    current.noiseScale = THREE.MathUtils.damp(
      current.noiseScale,
      targetConfig.noiseScale,
      3.2,
      delta,
    )

    current.innerRadius = THREE.MathUtils.damp(
      current.innerRadius,
      targetConfig.innerRadius,
      3.6,
      delta,
    )

    current.energySpeed = THREE.MathUtils.damp(
      current.energySpeed,
      targetConfig.energySpeed,
      2.8,
      delta,
    )

    current.glowStrength = THREE.MathUtils.damp(
      current.glowStrength,
      targetConfig.glowStrength,
      3.8,
      delta,
    )

    current.edgeSoftness = THREE.MathUtils.damp(
      current.edgeSoftness,
      targetConfig.edgeSoftness,
      3.8,
      delta,
    )

    /*
     * Correct integration:
     *
     * newTime = oldTime + frameDuration * currentSpeed
     *
     * Hover changes the rate of future motion, not the position
     * accumulated during the entire lifetime of the component.
     */
    animationTimeRef.current += delta * current.energySpeed

    /*
     * Keep the value numerically bounded during very long sessions.
     * The noise and trigonometric functions remain visually continuous.
     */
    if (animationTimeRef.current > 10000) {
      animationTimeRef.current %= 10000
    }

    const values = material.uniforms

    values.animationTime.value = animationTimeRef.current

    values.hue.value = current.hue

    values.noiseScale.value = current.noiseScale

    values.innerRadius.value = current.innerRadius

    values.glowStrength.value = current.glowStrength

    values.edgeSoftness.value = current.edgeSoftness

    values.iResolution.value.set(
      size.width * viewport.dpr,

      size.height * viewport.dpr,

      size.width / Math.max(size.height, 1),
    )
  })

  return (
    <mesh geometry={geometry} frustumCulled={false}>
      <shaderMaterial
        ref={materialRef}
        vertexShader={vertexShader}
        fragmentShader={fragmentShader}
        uniforms={uniforms}
        transparent
        premultipliedAlpha
        depthWrite={false}
        depthTest={false}
        toneMapped={false}
      />
    </mesh>
  )
}

interface GradientOrbProps {
  config?: GradientOrbConfig
  className?: string
}

export function GradientOrb({ config: overrides, className = '' }: GradientOrbProps) {
  const targetConfig = useMemo(
    () => ({
      ...defaults,
      ...overrides,
    }),
    [
      overrides?.background,
      overrides?.edgeSoftness,
      overrides?.energySpeed,
      overrides?.glowStrength,
      overrides?.hue,
      overrides?.innerRadius,
      overrides?.noiseScale,
    ],
  )

  return (
    <div
      className={['gradient-orb', className].filter(Boolean).join(' ')}
      style={{
        background: targetConfig.background,
      }}
    >
      <Canvas
        dpr={[1, 1.2]}
        frameloop="always"
        gl={{
          antialias: false,
          alpha: true,
          premultipliedAlpha: true,
          powerPreference: 'high-performance',
        }}
        style={{
          background: 'transparent',
        }}
      >
        <GradientScene targetConfig={targetConfig} />
      </Canvas>
    </div>
  )
}

export default GradientOrb
