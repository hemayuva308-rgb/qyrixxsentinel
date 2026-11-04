import type { Config } from "tailwindcss";
const config: Config = {
  content: ["./src/**/*.{ts,tsx}"],
  theme: { extend: {
    colors: {
      // Authenticated app (dark command center) - unchanged tokens
      bg: "#070A12", bg2: "#0A0F1F", card: "#101827", neon: "#00D4FF", cyan: "#00F0FF",
      ok: "#00E676", warn: "#FFB020", crit: "#FF3B5C", ink: "#F5F7FA", mute: "#8B9BB4",
      // Homepage (premium white theme) tokens
      qx: { ink: "#101828", blue: "#2563EB", sky: "#60A5FA", mist: "#F7F9FC", ice: "#EAF3FF", mute: "#667085", body: "#475467", line: "#E5EAF2" },
      // Public website (light) - QYRIX brand tokens
      site: { ink: "#0B1630", navy: "#0A1A3F", deep: "#060E24", blue: "#1F5BFF", cyan: "#06B6D4", violet: "#6D5DF6",
        mist: "#F5F7FB", fog: "#EEF2F8", line: "#E2E8F2", mute: "#55627A", allow: "#0891B2", block: "#E11D48" },
    },
    fontFamily: {
      mono: ["ui-monospace", "SFMono-Regular", "Menlo", "Consolas", "monospace"],
      sans: ["ui-sans-serif", "-apple-system", "BlinkMacSystemFont", "\"Segoe UI\"", "Inter", "Roboto", "\"Helvetica Neue\"", "Arial", "sans-serif"],
    },
    boxShadow: {
      glow: "0 0 0 1px rgba(0,212,255,.35), 0 0 24px -8px rgba(0,212,255,.45)",
      soft: "0 1px 2px rgba(11,22,48,.04), 0 8px 24px -12px rgba(11,22,48,.12)",
      lift: "0 2px 4px rgba(11,22,48,.04), 0 24px 48px -20px rgba(31,91,255,.28)",
      ring: "0 0 0 1px rgba(31,91,255,.18), 0 12px 32px -16px rgba(31,91,255,.35)",
      "qx-card": "0 1px 2px rgba(16,24,40,.04), 0 12px 32px -20px rgba(16,24,40,.18)",
      "qx-lift": "0 2px 4px rgba(16,24,40,.04), 0 28px 56px -24px rgba(37,99,235,.35)",
    },
    maxWidth: { site: "1200px" },
    transitionTimingFunction: { out: "cubic-bezier(.16,1,.3,1)" },
  } },
  plugins: [],
};
export default config;
