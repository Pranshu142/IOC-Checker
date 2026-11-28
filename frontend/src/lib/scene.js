import {
  BufferGeometry, EdgesGeometry, Float32BufferAttribute, Group, IcosahedronGeometry, LineBasicMaterial,
  LineSegments, MathUtils, PerspectiveCamera, Points, PointsMaterial, Scene, WebGLRenderer,
} from 'three';

// A slowly turning particle globe behind the chat. Monochrome, follows the light/dark theme,
// speeds up while a job runs, flares on a High or Critical result, and leans toward the pointer.
export function createScene(canvas, { reduced, getBusy }) {
  const renderer = new WebGLRenderer({ canvas, alpha: true, antialias: true, powerPreference: 'low-power' });
  renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 1.75));
  const scene = new Scene();
  const camera = new PerspectiveCamera(45, 1, 0.1, 100);
  camera.position.z = 8;
  const group = new Group();
  scene.add(group);

  // points spread evenly over a sphere (Fibonacci lattice), slightly roughened
  const R = 2.6, N = 1600, pos = new Float32Array(N * 3), golden = Math.PI * (3 - Math.sqrt(5));
  for (let i = 0; i < N; i++) {
    const y = 1 - (i / (N - 1)) * 2, r = Math.sqrt(1 - y * y), a = golden * i, j = 1 + (Math.random() - 0.5) * 0.04;
    pos[i * 3] = Math.cos(a) * r * R * j; pos[i * 3 + 1] = y * R * j; pos[i * 3 + 2] = Math.sin(a) * r * R * j;
  }
  const pointGeo = new BufferGeometry();
  pointGeo.setAttribute('position', new Float32BufferAttribute(pos, 3));
  const pointMat = new PointsMaterial({ size: 0.028, transparent: true, depthWrite: false });
  group.add(new Points(pointGeo, pointMat));

  const iso = new IcosahedronGeometry(R * 1.02, 2), edges = new EdgesGeometry(iso);
  const lineMat = new LineBasicMaterial({ transparent: true });
  group.add(new LineSegments(edges, lineMat));

  let base = 0.5, baseLine = 0.1;
  function applyTheme() {
    const dark = document.documentElement.classList.contains('dark');
    pointMat.color.setHex(dark ? 0xffffff : 0x111111); lineMat.color.setHex(dark ? 0xffffff : 0x111111);
    base = dark ? 0.55 : 0.32; baseLine = dark ? 0.1 : 0.07;
    pointMat.opacity = base; lineMat.opacity = baseLine;
  }
  applyTheme();

  let baseScale = 1;
  function resize() {
    const w = window.innerWidth, h = window.innerHeight, wide = w / h > 1.1;
    renderer.setSize(w, h, false);
    camera.aspect = w / h; camera.updateProjectionMatrix();
    group.position.set(wide ? 3.3 : 0, wide ? 0 : 0.4, 0);   // beside the chat on wide screens, behind it on narrow ones
    baseScale = wide ? 1 : 0.8;
    group.scale.setScalar(baseScale);
  }
  resize();

  let raf = 0, last = performance.now(), speed = 0.12, kick = 0, tx = 0, ty = 0;
  const draw = () => renderer.render(scene, camera);
  const onMove = (e) => { tx = e.clientX / window.innerWidth - 0.5; ty = e.clientY / window.innerHeight - 0.5; };
  const onResize = () => { resize(); if (reduced) draw(); };
  const mo = new MutationObserver(() => { applyTheme(); if (reduced) draw(); });
  mo.observe(document.documentElement, { attributes: true, attributeFilter: ['class'] });
  window.addEventListener('resize', onResize);

  function frame(now) {
    const dt = Math.min(0.05, (now - last) / 1000); last = now;
    const busy = getBusy();
    speed += ((busy ? 0.9 : 0.12) - speed) * Math.min(1, dt * 2);       // ease between idle and working
    kick *= Math.pow(0.2, dt);
    group.rotation.y += speed * dt;
    group.rotation.x = MathUtils.lerp(group.rotation.x, ty * 0.5 + 0.25, Math.min(1, dt * 2));
    group.rotation.z = MathUtils.lerp(group.rotation.z, -tx * 0.3, Math.min(1, dt * 2));
    group.scale.setScalar(baseScale * (1 + (busy ? 0.025 * Math.sin(now / 400) : 0) + kick * 0.08));
    pointMat.opacity = Math.min(1, base + (busy ? 0.15 : 0) + kick * 0.3);
    lineMat.opacity = Math.min(1, baseLine + kick * 0.2);
    draw();
    raf = requestAnimationFrame(frame);
  }
  if (reduced) { group.rotation.set(0.25, 0.6, 0); draw(); }          // reduced motion: one still frame
  else { window.addEventListener('pointermove', onMove, { passive: true }); raf = requestAnimationFrame(frame); }

  return {
    pulse() { kick = 1; if (reduced) draw(); },
    dispose() {
      cancelAnimationFrame(raf);
      window.removeEventListener('pointermove', onMove); window.removeEventListener('resize', onResize);
      mo.disconnect();
      pointGeo.dispose(); pointMat.dispose(); iso.dispose(); edges.dispose(); lineMat.dispose(); renderer.dispose();
    },
  };
}
