import { useEffect, useRef } from 'react';

// Loads Three.js only after the page is up, so it never delays the first paint.
// If WebGL is unavailable the page simply works without it.
export default function Backdrop({ busy, pulse }) {
  const canvas = useRef(null), scene = useRef(null), busyRef = useRef(busy);
  busyRef.current = busy;

  useEffect(() => {
    let dead = false;
    const reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    import('@/lib/scene').then(({ createScene }) => {
      if (dead) return;
      try { scene.current = createScene(canvas.current, { reduced, getBusy: () => busyRef.current }); }
      catch { /* no WebGL */ }
    }).catch(() => {});
    return () => { dead = true; scene.current?.dispose(); scene.current = null; };
  }, []);

  useEffect(() => { if (pulse) scene.current?.pulse(); }, [pulse]);

  return <canvas ref={canvas} aria-hidden="true" className="pointer-events-none fixed inset-0 -z-10 h-full w-full" />;
}
