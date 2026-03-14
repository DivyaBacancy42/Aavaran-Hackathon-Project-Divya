import { useEffect, useRef } from "react";
import * as THREE from "three";

// ── Atmospheric scattering shaders — Mars dusty-orange tones ──────────────────
const VERT = `
  varying vec3 vNormal;
  varying vec3 vPosition;
  void main() {
    vNormal = normalize(normalMatrix * normal);
    vPosition = (modelViewMatrix * vec4(position, 1.0)).xyz;
    gl_Position = projectionMatrix * modelViewMatrix * vec4(position, 1.0);
  }
`;

// Outer glow — rendered on back-face: rusty orange dust haze
const FRAG_OUTER = `
  varying vec3 vNormal;
  void main() {
    float intensity = pow(0.58 - dot(vNormal, vec3(0.0, 0.0, 1.0)), 5.0);
    vec3 atmoColor = vec3(0.82, 0.34, 0.10);
    gl_FragColor = vec4(atmoColor, 1.0) * intensity * 2.4;
  }
`;

// Inner limb brightening — warm orange rim light
const FRAG_INNER = `
  varying vec3 vNormal;
  void main() {
    float rim = pow(1.0 - abs(dot(vNormal, vec3(0.0, 0.0, 1.0))), 5.5);
    gl_FragColor = vec4(0.92, 0.48, 0.16, rim * 0.32);
  }
`;

// Three.js bundled Mars texture (same package already installed)
const MARS_TEX =
  "https://raw.githubusercontent.com/mrdoob/three.js/r160/examples/textures/planets/mars_1k_color.jpg";

export default function MarsBackground() {
  const mountRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const mount = mountRef.current;
    if (!mount) return;

    // ── Renderer ──────────────────────────────────────────────────────────────
    const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    renderer.setSize(window.innerWidth, window.innerHeight);
    renderer.setClearColor(0x000000, 0);
    mount.appendChild(renderer.domElement);

    // ── Scene + Camera ────────────────────────────────────────────────────────
    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(
      45, window.innerWidth / window.innerHeight, 0.1, 1000
    );
    camera.position.set(0, 0.55, 3.0);
    camera.rotation.x = -0.1;

    // ── Texture loader ────────────────────────────────────────────────────────
    const loader = new THREE.TextureLoader();
    loader.crossOrigin = "anonymous";
    const marsTex = loader.load(MARS_TEX);

    // ── Mars sphere ───────────────────────────────────────────────────────────
    const marsGroup = new THREE.Group();
    marsGroup.position.set(-0.25, -1.4, 0);
    scene.add(marsGroup);

    const marsGeo = new THREE.SphereGeometry(1, 80, 80);
    const marsMat = new THREE.MeshPhongMaterial({
      map:       marsTex,
      bumpMap:   marsTex,
      bumpScale: 0.04,
      specular:  new THREE.Color(0x1a0800),
      shininess: 4,
    });
    const mars = new THREE.Mesh(marsGeo, marsMat);
    // Mars axial tilt ≈ 25°
    mars.rotation.z = (-25 * Math.PI) / 180;
    mars.rotation.y = 1.5;
    marsGroup.add(mars);

    // ── Atmosphere — outer Fresnel dust halo ─────────────────────────────────
    const atmoGeo = new THREE.SphereGeometry(1.065, 72, 72);
    const atmoMat = new THREE.ShaderMaterial({
      vertexShader: VERT, fragmentShader: FRAG_OUTER,
      blending: THREE.AdditiveBlending, side: THREE.BackSide, transparent: true,
    });
    marsGroup.add(new THREE.Mesh(atmoGeo, atmoMat));

    // ── Atmosphere — inner limb ───────────────────────────────────────────────
    const innerGeo = new THREE.SphereGeometry(1.02, 72, 72);
    const innerMat = new THREE.ShaderMaterial({
      vertexShader: VERT, fragmentShader: FRAG_INNER,
      blending: THREE.AdditiveBlending, side: THREE.FrontSide, transparent: true,
    });
    marsGroup.add(new THREE.Mesh(innerGeo, innerMat));

    // ── Starfield (5 000 points) ──────────────────────────────────────────────
    const STAR_COUNT = 5000;
    const sPos = new Float32Array(STAR_COUNT * 3);
    const sCol = new Float32Array(STAR_COUNT * 3);
    const palette: [number, number, number][] = [
      [1.0, 1.0, 1.0], [0.87, 0.93, 1.0],
      [1.0, 0.97, 0.86], [1.0, 0.88, 0.78],
    ];
    for (let i = 0; i < STAR_COUNT; i++) {
      const theta = Math.random() * Math.PI * 2;
      const phi   = Math.acos(2 * Math.random() - 1);
      const r     = 20 + Math.random() * 10;
      sPos[i*3]   = r * Math.sin(phi) * Math.cos(theta);
      sPos[i*3+1] = r * Math.sin(phi) * Math.sin(theta);
      sPos[i*3+2] = r * Math.cos(phi);
      const c = palette[Math.floor(Math.random() * palette.length)];
      sCol[i*3] = c[0]; sCol[i*3+1] = c[1]; sCol[i*3+2] = c[2];
    }
    const starsGeo = new THREE.BufferGeometry();
    starsGeo.setAttribute("position", new THREE.BufferAttribute(sPos, 3));
    starsGeo.setAttribute("color",    new THREE.BufferAttribute(sCol, 3));
    const starsMat = new THREE.PointsMaterial({
      size: 0.045, vertexColors: true,
      transparent: true, opacity: 0.88, sizeAttenuation: true,
    });
    const starField = new THREE.Points(starsGeo, starsMat);
    scene.add(starField);

    // ── Nebula sprays — warm rust/terracotta tones ────────────────────────────
    const addNebula = (
      cx: number, cy: number, cz: number,
      n: number, spread: number,
      color: THREE.Color, opacity: number, size: number
    ) => {
      const geo = new THREE.BufferGeometry();
      const pos = new Float32Array(n * 3);
      for (let i = 0; i < n; i++) {
        pos[i*3]   = cx + (Math.random()-0.5)*spread;
        pos[i*3+1] = cy + (Math.random()-0.5)*spread*0.5;
        pos[i*3+2] = cz + (Math.random()-0.5)*spread*0.3;
      }
      geo.setAttribute("position", new THREE.BufferAttribute(pos, 3));
      scene.add(new THREE.Points(geo, new THREE.PointsMaterial({
        color, size, transparent: true, opacity,
        blending: THREE.AdditiveBlending, depthWrite: false,
      })));
    };
    // Deep rust nebula
    addNebula( 8,  3, -16, 700, 14, new THREE.Color(0.30, 0.06, 0.02), 0.10, 0.16);
    // Dark crimson cloud
    addNebula(-7, -2, -19, 600, 10, new THREE.Color(0.22, 0.04, 0.06), 0.08, 0.14);
    // Faint maroon
    addNebula( 2, -5, -21, 400,  8, new THREE.Color(0.14, 0.02, 0.03), 0.06, 0.12);

    // ── Lighting ──────────────────────────────────────────────────────────────
    // Mars is 1.52× further from the Sun — dimmer, warmer light
    scene.add(new THREE.AmbientLight(0x100a08, 1.0));

    const sun = new THREE.DirectionalLight(0xffe0b0, 1.8);
    sun.position.set(-5, 3, 4);
    scene.add(sun);

    const backLight = new THREE.DirectionalLight(0x180a04, 0.18);
    backLight.position.set(5, -2, -5);
    scene.add(backLight);

    // ── Scroll-based animation ────────────────────────────────────────────────
    let targetY  = -1.4, currentY  = -1.4;
    let targetCZ = 3.0,  currentCZ = 3.0;

    const onScroll = () => {
      const p = Math.min(window.scrollY / window.innerHeight, 1);
      targetY  = -1.4 + p * 1.35;
      targetCZ = 3.0  + p * 0.4;
    };
    window.addEventListener("scroll", onScroll, { passive: true });

    const onResize = () => {
      camera.aspect = window.innerWidth / window.innerHeight;
      camera.updateProjectionMatrix();
      renderer.setSize(window.innerWidth, window.innerHeight);
    };
    window.addEventListener("resize", onResize);

    // ── Animation loop ────────────────────────────────────────────────────────
    let frameId: number;
    const animate = () => {
      frameId = requestAnimationFrame(animate);
      currentY  += (targetY  - currentY)  * 0.04;
      currentCZ += (targetCZ - currentCZ) * 0.04;
      marsGroup.position.y = currentY;
      camera.position.z    = currentCZ;

      // Mars rotates slower than Earth (24h 37m vs 24h)
      mars.rotation.y     += 0.00017;
      starField.rotation.y += 0.000022;

      renderer.render(scene, camera);
    };
    animate();

    return () => {
      cancelAnimationFrame(frameId);
      window.removeEventListener("scroll", onScroll);
      window.removeEventListener("resize", onResize);
      if (mount.contains(renderer.domElement)) mount.removeChild(renderer.domElement);
      renderer.dispose();
      [marsGeo, marsMat, atmoGeo, atmoMat, innerGeo, innerMat,
       starsGeo, starsMat].forEach((o) => o.dispose());
    };
  }, []);

  return (
    <div
      ref={mountRef}
      style={{
        position: "fixed",
        inset: 0,
        width: "100%",
        height: "100%",
        pointerEvents: "none",
        zIndex: -1,
        // Slightly warm-dark background complements Mars rust tones
        backgroundColor: "#040208",
      }}
    />
  );
}
