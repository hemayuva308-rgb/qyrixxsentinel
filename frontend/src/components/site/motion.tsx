"use client";
import { useEffect, useRef, useState } from "react";
import { usePathname } from "next/navigation";

export const prefersReducedMotion = () =>
  typeof window !== "undefined" && window.matchMedia("(prefers-reduced-motion: reduce)").matches;

/** Opts `.reveal` elements into a one-time entrance animation when they scroll into view.
 *  Without JS or with reduced motion, content is simply visible. */
export function RevealRoot() {
  const path = usePathname();
  useEffect(() => {
    if (prefersReducedMotion() || !("IntersectionObserver" in window)) return;
    document.documentElement.classList.add("js-reveal");
    const io = new IntersectionObserver((entries) => {
      for (const e of entries) if (e.isIntersecting) { (e.target as HTMLElement).dataset.shown = "true"; io.unobserve(e.target); }
    }, { rootMargin: "0px 0px -8% 0px", threshold: 0.08 });
    const scan = () => document.querySelectorAll<HTMLElement>(".reveal:not([data-shown])").forEach((el) => io.observe(el));
    scan();
    const t = setTimeout(scan, 300);
    return () => { clearTimeout(t); io.disconnect(); };
  }, [path]);
  return null;
}

/** True while the element is on screen. Used to pause looping visuals that are not visible. */
export function useInView<T extends Element>(margin = "0px") {
  const ref = useRef<T | null>(null);
  const [inView, setInView] = useState(false);
  useEffect(() => {
    const el = ref.current;
    if (!el || !("IntersectionObserver" in window)) { setInView(true); return; }
    const io = new IntersectionObserver(([e]) => setInView(e.isIntersecting), { rootMargin: margin });
    io.observe(el);
    return () => io.disconnect();
  }, [margin]);
  return [ref, inView] as const;
}

/** Pauses SMIL animations inside an <svg> when off-screen or when the user prefers reduced motion. */
export function useSvgPlayback(inView: boolean) {
  const svg = useRef<SVGSVGElement | null>(null);
  useEffect(() => {
    const s = svg.current; if (!s || typeof s.pauseAnimations !== "function") return;
    if (prefersReducedMotion()) { s.pauseAnimations(); s.setCurrentTime?.(2.6); return; }
    if (inView) s.unpauseAnimations(); else s.pauseAnimations();
  }, [inView]);
  return svg;
}
