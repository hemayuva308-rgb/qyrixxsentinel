import type { Config } from "tailwindcss";
const config: Config = {
  content: ["./src/**/*.{ts,tsx}"],
  theme: { extend: {
    colors: { bg: "#070A12", bg2: "#0A0F1F", card: "#101827", neon: "#00D4FF", cyan: "#00F0FF",
      ok: "#00E676", warn: "#FFB020", crit: "#FF3B5C", ink: "#F5F7FA", mute: "#8B9BB4" },
    fontFamily: { mono: ["ui-monospace", "SFMono-Regular", "Menlo", "Consolas", "monospace"] },
    boxShadow: { glow: "0 0 0 1px rgba(0,212,255,.35), 0 0 24px -8px rgba(0,212,255,.45)" },
  } },
  plugins: [],
};
export default config;
