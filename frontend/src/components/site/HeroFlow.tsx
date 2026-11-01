"use client";
import { useInView, useSvgPlayback } from "./motion";
import { GATE, RING, SHIELD, TAIL } from "@/components/brand/BrandMark";

// Concept animation (not data): an instruction travels Agent -> Instruction -> QYRIX layer -> Gate -> ALLOW | BLOCK.
// Two packets alternate every 4 s; the colour is only assigned AT the gate, which is the point of the product.
const A = "M240 64 L240 396 C240 432 126 428 126 466";
const B = "M240 64 L240 396 C240 432 354 428 354 466";
const KP = "0;0.40;0.40;0.72;0.72;1;1";
const KT = "0;0.12;0.2;0.3;0.38;0.48;1";
const OP = { values: "0;1;1;1;0;0", keyTimes: "0;0.03;0.5;0.58;0.62;1" };

function Packet({ path, begin, to }: { path: string; begin: string; to: string }) {
  return (
    <g>
      <circle r="11" fill={to} opacity="0">
        <animateMotion dur="8s" begin={begin} repeatCount="indefinite" path={path} keyPoints={KP} keyTimes={KT} calcMode="linear" />
        <animate attributeName="opacity" dur="8s" begin={begin} repeatCount="indefinite" values="0;.2;.2;.2;0;0" keyTimes={OP.keyTimes} />
        <animate attributeName="fill" dur="8s" begin={begin} repeatCount="indefinite" values={`#1F5BFF;#1F5BFF;${to};${to}`} keyTimes="0;0.33;0.36;1" />
      </circle>
      <circle r="5.5" fill="#1F5BFF" stroke="#fff" strokeWidth="2" opacity="0">
        <animateMotion dur="8s" begin={begin} repeatCount="indefinite" path={path} keyPoints={KP} keyTimes={KT} calcMode="linear" />
        <animate attributeName="opacity" dur="8s" begin={begin} repeatCount="indefinite" {...OP} />
        <animate attributeName="fill" dur="8s" begin={begin} repeatCount="indefinite" values={`#1F5BFF;#1F5BFF;${to};${to}`} keyTimes="0;0.33;0.36;1" />
      </circle>
    </g>);
}

function Flash({ begin, at = "0;0;1;0;0", times = "0;0.44;0.49;0.66;1", children }: { begin: string; at?: string; times?: string; children: React.ReactNode }) {
  return (
    <g opacity="0">
      <animate attributeName="opacity" dur="8s" begin={begin} repeatCount="indefinite" values={at} keyTimes={times} />
      {children}
    </g>);
}

export default function HeroFlow() {
  const [box, inView] = useInView<HTMLDivElement>("80px");
  const svg = useSvgPlayback(inView);
  return (
    <div ref={box} className="relative">
      <svg ref={svg} viewBox="0 0 480 560" className="h-auto w-full" role="img"
        aria-labelledby="hero-flow-title hero-flow-desc" style={{ fontFamily: "inherit" }}>
        <title id="hero-flow-title">How QYRIX SENTINEL intercepts an AI action</title>
        <desc id="hero-flow-desc">An AI agent proposes a tool call from an unverified instruction. The QYRIX SENTINEL layer inspects it and
          checks its provenance, then the deterministic gate either allows it, issuing a grant so the tool runs, or blocks it before execution
          and records proof.</desc>
        <defs>
          <linearGradient id="hf-band" x1="0" y1="0" x2="1" y2="1">
            <stop offset="0" stopColor="#0A1A3F" /><stop offset="1" stopColor="#13306F" />
          </linearGradient>
          <linearGradient id="hf-scan" x1="0" x2="1">
            <stop offset="0" stopColor="#67E8F9" stopOpacity="0" /><stop offset=".5" stopColor="#67E8F9" stopOpacity=".55" /><stop offset="1" stopColor="#67E8F9" stopOpacity="0" />
          </linearGradient>
          <linearGradient id="hf-shield" x1="10" y1="4" x2="54" y2="60" gradientUnits="userSpaceOnUse">
            <stop offset="0" stopColor="#1F5BFF" /><stop offset="1" stopColor="#06B6D4" />
          </linearGradient>
          <clipPath id="hf-clip"><rect x="24" y="196" width="432" height="108" rx="20" /></clipPath>
          <filter id="hf-soft" x="-20%" y="-20%" width="140%" height="160%"><feDropShadow dx="0" dy="8" stdDeviation="10" floodColor="#0B1630" floodOpacity=".10" /></filter>
        </defs>

        {/* spine + branches */}
        <path d="M240 64 V396" stroke="#CBD5E6" strokeWidth="1.5" />
        <path d="M240 64 V396" stroke="#1F5BFF" strokeOpacity=".5" strokeWidth="1.5" className="flow-dash" />
        <path d="M240 396 C240 432 126 428 126 466" fill="none" stroke="#06B6D4" strokeOpacity=".6" strokeWidth="1.5" className="flow-dash" />
        <path d="M240 396 C240 432 354 428 354 466" fill="none" stroke="#E11D48" strokeOpacity=".45" strokeWidth="1.5" strokeDasharray="3 6" />

        {/* 1. agent */}
        <g filter="url(#hf-soft)">
          <rect x="150" y="16" width="180" height="48" rx="14" fill="#fff" stroke="#E2E8F2" />
        </g>
        <circle cx="174" cy="40" r="9" fill="#EEF2FF" /><circle cx="174" cy="40" r="3.5" fill="#1F5BFF" />
        <text x="192" y="37" fontSize="12" fontWeight="700" fill="#0B1630" letterSpacing="1.4">AI AGENT</text>
        <text x="192" y="52" fontSize="10.5" fill="#55627A">proposes a tool call</text>

        {/* 2. instruction */}
        <g filter="url(#hf-soft)"><rect x="112" y="104" width="256" height="52" rx="14" fill="#fff" stroke="#E2E8F2" /></g>
        <text x="130" y="126" fontSize="11.5" fontWeight="700" fill="#0B1630" letterSpacing="1.2">UNTRUSTED INSTRUCTION</text>
        <text x="130" y="143" fontSize="10.5" fill="#55627A">third-party skill README</text>
        <rect x="282" y="132" width="72" height="16" rx="8" fill="#FFFBEB" stroke="#FCD34D" />
        <text x="318" y="143.5" fontSize="8.5" fontWeight="700" fill="#92400E" textAnchor="middle" letterSpacing=".8">UNVERIFIED</text>

        {/* 3. security layer */}
        <g filter="url(#hf-soft)"><rect x="24" y="196" width="432" height="108" rx="20" fill="url(#hf-band)" /></g>
        <g clipPath="url(#hf-clip)">
          <rect x="24" y="196" width="432" height="108" fill="none" />
          <rect y="196" width="90" height="108" fill="url(#hf-scan)" x="-90">
            <animate attributeName="x" dur="3.2s" repeatCount="indefinite" values="-90;470" />
          </rect>
          {Array.from({ length: 11 }).map((_, i) => <path key={i} d={`M${40 + i * 40} 196 V304`} stroke="#fff" strokeOpacity=".05" />)}
        </g>
        <g transform="translate(46 216) scale(1.05)">
          <path d={SHIELD} fill="url(#hf-shield)" />
          <path d={RING} fill="none" stroke="#fff" strokeWidth="4.6" />
          <path d={TAIL} stroke="#fff" strokeWidth="4" strokeLinecap="round" />
          <path d={GATE} stroke="#67E8F9" strokeWidth="5.4" />
          <circle cx="32" cy="29" r="3.6" fill="#67E8F9" />
        </g>
        <text x="128" y="236" fontSize="13" fontWeight="800" fill="#fff" letterSpacing="2.4">QYRIX SENTINEL</text>
        <text x="128" y="253" fontSize="10.5" fill="#A5B4CF">security layer between agent and tools</text>
        {[["INSPECT", 128], ["PROVENANCE", 202], ["POLICY", 300]].map(([l, x]) => (
          <g key={l as string}>
            <rect x={x as number} y="266" width={(l as string).length * 7.2 + 18} height="20" rx="10" fill="#fff" fillOpacity=".08" stroke="#fff" strokeOpacity=".18" />
            <text x={(x as number) + 9} y="279.5" fontSize="9" fontWeight="700" fill="#CFFAFE" letterSpacing="1.2">{l}</text>
          </g>))}

        {/* 4. gate */}
        <g transform="translate(240 370)">
          <rect x="-26" y="-26" width="52" height="52" rx="10" transform="rotate(45)" fill="#fff" stroke="#0B1630" strokeWidth="1.5" />
          <Flash begin="0s" times="0;0.29;0.33;0.4;1"><rect x="-26" y="-26" width="52" height="52" rx="10" transform="rotate(45)" fill="#ECFEFF" stroke="#06B6D4" strokeWidth="2.5" /></Flash>
          <Flash begin="4s" times="0;0.29;0.33;0.4;1"><rect x="-26" y="-26" width="52" height="52" rx="10" transform="rotate(45)" fill="#FFF1F2" stroke="#E11D48" strokeWidth="2.5" /></Flash>
          <path d="M-11 0 H11 M-11 -7 V7 M11 -7 V7" stroke="#0B1630" strokeWidth="2" strokeLinecap="round" />
        </g>
        <text x="284" y="364" fontSize="11.5" fontWeight="800" fill="#0B1630" letterSpacing="1.2">DETERMINISTIC GATE</text>
        <text x="284" y="380" fontSize="10" fill="#55627A">destination · action · data · auth</text>
        <text x="104" y="364" fontSize="10" fill="#55627A" textAnchor="end">AI is advisory.</text>
        <text x="104" y="379" fontSize="10" fill="#55627A" textAnchor="end">Policy decides.</text>

        {/* 5. outcomes */}
        <g filter="url(#hf-soft)">
          <rect x="36" y="466" width="180" height="76" rx="16" fill="#fff" stroke="#A5F3FC" />
          <rect x="264" y="466" width="180" height="76" rx="16" fill="#fff" stroke="#FECDD3" />
        </g>
        <Flash begin="0s"><rect x="36" y="466" width="180" height="76" rx="16" fill="#ECFEFF" stroke="#06B6D4" strokeWidth="2" /></Flash>
        <Flash begin="4s"><rect x="264" y="466" width="180" height="76" rx="16" fill="#FFF1F2" stroke="#E11D48" strokeWidth="2" /></Flash>
        <circle cx="62" cy="492" r="10" fill="#06B6D4" /><path d="M57 492 l3.5 3.5 L67 488" stroke="#fff" strokeWidth="2.2" fill="none" strokeLinecap="round" strokeLinejoin="round" />
        <text x="80" y="496" fontSize="13" fontWeight="800" fill="#0E7490" letterSpacing="1.5">ALLOW</text>
        <text x="52" y="524" fontSize="10.5" fill="#55627A">grant issued · tool executes</text>
        <circle cx="290" cy="492" r="10" fill="#E11D48" /><path d="M286 488 l8 8 M294 488 l-8 8" stroke="#fff" strokeWidth="2.2" strokeLinecap="round" />
        <text x="308" y="496" fontSize="13" fontWeight="800" fill="#BE123C" letterSpacing="1.5">BLOCK</text>
        <text x="280" y="524" fontSize="10.5" fill="#55627A">stopped before execution</text>

        <Packet path={A} begin="0s" to="#06B6D4" />
        <Packet path={B} begin="4s" to="#E11D48" />
      </svg>
      <p className="mt-2 text-center font-mono text-[10.5px] uppercase tracking-[.16em] text-site-mute/80">Concept animation · the live demo below runs the real Gate</p>
    </div>);
}
