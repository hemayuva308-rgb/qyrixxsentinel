"use client";
import type { Proof } from "@/lib/types";
import { Badge, Card, Empty, Mono, verdictTone } from "./ui";

export default function DecisionFeed({ items }: { items: Proof[] | undefined }) {
  return (
    <Card title="RECENT DECISIONS (PROOF CHAIN)">
      <div className="max-h-[28rem] space-y-2 overflow-auto">
        {!items?.length ? <Empty text="No decisions recorded yet - run the gate" /> : items.map((p) => (
          <div key={p.n} className="rounded-lg border border-white/10 bg-bg2 p-2.5 text-xs">
            <div className="flex flex-wrap items-center gap-2"><Mono>#{p.n}</Mono><Badge t={verdictTone(p.verdict)}>{p.verdict}</Badge><Badge>{p.tool}</Badge>
              <span className="ml-auto text-mute">{new Date(p.ts).toLocaleTimeString()}</span></div>
            {p.rule_ids.length > 0 && <div className="mt-1.5 flex flex-wrap gap-1">{p.rule_ids.map((r) => <Badge key={r} t="crit">{r}</Badge>)}</div>}
            {p.blocked_dest && <p className="mt-1 text-mute">blocked dest: <Mono>{p.blocked_dest}</Mono></p>}
            <p className="mt-1 text-mute">hash <Mono>{p.hash.slice(0, 16)}...</Mono></p>
          </div>))}
      </div>
    </Card>);
}
