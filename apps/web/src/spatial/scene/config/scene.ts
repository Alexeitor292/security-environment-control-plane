export const sceneConfig = {
  model: {
    url: '/models/server-rack.glb',

    /*
     * Slightly larger than real scale so the nearest cabinets
     * frame the camera naturally without narrowing the aisle.
     */
    scale: 1.42,
    restingY: 1.4,
    hiddenY: -4.8,

    material: {
      /*
       * Dark powder-coated cabinet steel rather than polished
       * or chrome-like metal.
       */
      metalness: 0.06,
      roughness: 0.92,
      envMapIntensity: 0.16,
    },
  },

  lane: {
    bankCount: 3,
    racksPerBank: 5,

    /*
     * Five cabinets remain almost flush within each bank.
     */
    rackPitch: 0.97,

    /*
     * Wider cross-path between each group of five.
     */
    serviceGap: 2.8,

    /*
     * A wide central promenade creates a grand scale rather
     * than a claustrophobic tunnel.
     */
    xOffset: 3.05,
    nearestZ: 5.05,
  },

  camera: {
    /*
     * The inactive camera is still inside the finished corridor.
     * The scene itself remains visually hidden until selection.
     */
    overviewPosition: [0, 1.88, 10.4] as const,
    overviewTarget: [0, 1.58, -15] as const,
    overviewFov: 48,

    /*
     * Human eye-height walking perspective.
     */
    corridorPosition: [0, 1.68, 7.55] as const,
    corridorTarget: [0, 1.58, -19] as const,
    corridorFov: 54,

    walkBob: 0.014,
    walkSway: 0.01,
    pointerParallax: 0.055,
  },

  environment: {
    ceilingY: 4.8,
    corridorCenterZ: -13,
    corridorLength: 50,
    corridorWidth: 10.5,
  },
} as const
