import { useEffect, useRef } from "react";
import * as THREE from "three";

// ── Atmospheric scattering shaders (Fresnel) ──────────────────────────────────
const VERT = `
  varying vec3 vNormal;
  varying vec3 vPosition;
  void main() {
    vNormal = normalize(normalMatrix * normal);
    vPosition = (modelViewMatrix * vec4(position, 1.0)).xyz;
    gl_Position = projectionMatrix * modelViewMatrix * vec4(position, 1.0);
  }
`;

// Outer glow — rendered on the back-face of a slightly larger sphere
const FRAG_OUTER = `
  varying vec3 vNormal;
  void main() {
    float intensity = pow(0.58 - dot(vNormal, vec3(0.0, 0.0, 1.0)), 5.0);
    vec3 atmoColor = vec3(0.18, 0.48, 1.0);
    gl_FragColor = vec4(atmoColor, 1.0) * intensity * 2.6;
  }
`;

// Inner limb brightening — rendered on the front face
const FRAG_INNER = `
  varying vec3 vNormal;
  void main() {
    float rim = pow(1.0 - abs(dot(vNormal, vec3(0.0, 0.0, 1.0))), 5.5);
    gl_FragColor = vec4(0.3, 0.6, 1.0, rim * 0.35);
  }
`;

// CDN base — three-globe ships production-ready 4K textures with CORS
const CDN = "https://unpkg.com/three-globe/example/img";

export default function SpaceBackground() {
  const mountRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const mount = mountRef.current;
    if (!mount) return;

    // ── Renderer ──────────────────────────────────────────────────────────────
    const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    renderer.setSize(window.innerWidth, window.innerHeight);
    renderer.setClearColor(0x000000, 0);
    renderer.shadowMap.enabled = true;
    renderer.shadowMap.type = THREE.PCFSoftShadowMap;
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

    // Load all 4 textures. Earth renders once first tex loads; others enhance it.
    const dayTex    = loader.load(`${CDN}/earth-blue-marble.jpg`);
    const nightTex  = loader.load(`${CDN}/earth-night.jpg`);
    const cloudsTex = loader.load(`${CDN}/earth-clouds.png`);
    // Topology/bump — converts land elevation to surface relief
    const bumpTex   = loader.load(`${CDN}/earth-topology.png`);

    // ── Earth sphere ──────────────────────────────────────────────────────────
    const earthGroup = new THREE.Group();
    earthGroup.position.set(-0.25, -1.4, 0);
    scene.add(earthGroup);

    const earthGeo = new THREE.SphereGeometry(1, 80, 80);
    const earthMat = new THREE.MeshPhongMaterial({
      map:          dayTex,
      bumpMap:      bumpTex,
      bumpScale:    0.06,          // subtle terrain relief
      specularMap:  nightTex,      // reuse night tex as a proxy — brighter where lights are
      specular:     new THREE.Color(0x2255aa),
      shininess:    20,
      emissiveMap:  nightTex,
      emissive:     new THREE.Color(0xffcc77),
      emissiveIntensity: 0.0,      // will be modulated below if desired
    });
    const earth = new THREE.Mesh(earthGeo, earthMat);
    earth.rotation.z = (-23.4 * Math.PI) / 180;
    earth.rotation.y = 2.2;
    earth.receiveShadow = true;
    earthGroup.add(earth);

    // ── Cloud layer ───────────────────────────────────────────────────────────
    // Separate sphere, slightly larger, semi-transparent cloud texture
    const cloudGeo = new THREE.SphereGeometry(1.012, 80, 80);
    const cloudMat = new THREE.MeshPhongMaterial({
      map:         cloudsTex,
      transparent: true,
      opacity:     0.42,
      depthWrite:  false,
      blending:    THREE.AdditiveBlending,
    });
    const clouds = new THREE.Mesh(cloudGeo, cloudMat);
    clouds.rotation.z = (-23.4 * Math.PI) / 180;
    clouds.rotation.y = 2.2;
    earthGroup.add(clouds);

    // ── Atmosphere — outer Fresnel glow ──────────────────────────────────────
    const atmoGeo = new THREE.SphereGeometry(1.07, 72, 72);
    const atmoMat = new THREE.ShaderMaterial({
      vertexShader: VERT, fragmentShader: FRAG_OUTER,
      blending: THREE.AdditiveBlending, side: THREE.BackSide, transparent: true,
    });
    earthGroup.add(new THREE.Mesh(atmoGeo, atmoMat));

    // ── Atmosphere — inner limb ───────────────────────────────────────────────
    const innerGeo = new THREE.SphereGeometry(1.022, 72, 72);
    const innerMat = new THREE.ShaderMaterial({
      vertexShader: VERT, fragmentShader: FRAG_INNER,
      blending: THREE.AdditiveBlending, side: THREE.FrontSide, transparent: true,
    });
    earthGroup.add(new THREE.Mesh(innerGeo, innerMat));

    // ── Starfield (5 000 points, spherically distributed) ────────────────────
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

    // ── Nebula sprays ─────────────────────────────────────────────────────────
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
    addNebula( 8,  3, -16, 700, 14, new THREE.Color(0.12, 0.04, 0.38), 0.10, 0.16);
    addNebula(-7, -2, -19, 600, 10, new THREE.Color(0.00, 0.20, 0.16), 0.08, 0.14);
    addNebula( 2, -5, -21, 400,  8, new THREE.Color(0.30, 0.04, 0.12), 0.06, 0.12);

    // ── Lighting ──────────────────────────────────────────────────────────────
    // Dim ambient (deep space — very little ambient)
    scene.add(new THREE.AmbientLight(0x080814, 1.0));

    // Primary sun — warm, from top-left
    const sun = new THREE.DirectionalLight(0xfff0e0, 2.4);
    sun.position.set(-5, 3, 4);
    sun.castShadow = true;
    scene.add(sun);

    // Subtle back-scatter (simulates Earth IR emission on dark side)
    const backLight = new THREE.DirectionalLight(0x112244, 0.22);
    backLight.position.set(5, -2, -5);
    scene.add(backLight);

    // ── Scroll-based animation ────────────────────────────────────────────────
    let targetEarthY  = -1.4;
    let currentEarthY = -1.4;
    let targetCamZ    = 3.0;
    let currentCamZ   = 3.0;

    const onScroll = () => {
      const p = Math.min(window.scrollY / window.innerHeight, 1);
      targetEarthY = -1.4 + p * 1.35;
      targetCamZ   = 3.0  + p * 0.4;
    };
    window.addEventListener("scroll", onScroll, { passive: true });

    // ── Resize ────────────────────────────────────────────────────────────────
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

      // Smooth lerp for scroll
      currentEarthY += (targetEarthY - currentEarthY) * 0.04;
      currentCamZ   += (targetCamZ   - currentCamZ)   * 0.04;
      earthGroup.position.y = currentEarthY;
      camera.position.z     = currentCamZ;

      // Gentle rotation
      earth.rotation.y  += 0.00020;
      clouds.rotation.y += 0.00025;   // clouds drift slightly faster
      starField.rotation.y += 0.000025;

      renderer.render(scene, camera);
    };
    animate();

    return () => {
      cancelAnimationFrame(frameId);
      window.removeEventListener("scroll", onScroll);
      window.removeEventListener("resize", onResize);
      if (mount.contains(renderer.domElement)) mount.removeChild(renderer.domElement);
      renderer.dispose();
      [earthGeo, earthMat, cloudGeo, cloudMat,
       atmoGeo, atmoMat, innerGeo, innerMat,
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
        backgroundColor: "#02020a",
      }}
    />
  );
}
