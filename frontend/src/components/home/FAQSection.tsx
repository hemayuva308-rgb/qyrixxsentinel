"use client";
import { useState } from "react";
import { ChevronDown } from "lucide-react";
import { FAQ } from "@/lib/home-content";
import { Heading, Section } from "./ui";

/** Accessible accordion: each header is a button with aria-expanded/aria-controls; panels are regions. Several can be open. */
export default function FAQSection() {
  const [open, setOpen] = useState<number | null>(0);
  return (
    <Section id="faq" tone="mist" labelledBy="faq-h">
      <div className="grid gap-10 lg:grid-cols-[1fr_1.7fr]">
        <Heading id="faq-h" eyebrow="FAQ" title="Straight answers." lead="Including the limits." />
        <ul className="reveal divide-y divide-qx-line overflow-hidden rounded-2xl border border-qx-line bg-white shadow-qx-card">
          {FAQ.map((f, i) => {
            const on = open === i;
            return (
              <li key={f.q}>
                <h3>
                  <button type="button" id={`faq-q-${i}`} aria-expanded={on} aria-controls={`faq-a-${i}`} onClick={() => setOpen(on ? null : i)}
                    className="flex min-h-14 w-full items-center justify-between gap-4 px-5 py-4 text-left text-[15.5px] font-semibold text-qx-ink transition hover:bg-qx-mist/70 sm:px-6">
                    <span>{f.q}</span>
                    <ChevronDown className={`h-5 w-5 shrink-0 text-qx-mute transition-transform duration-300 ${on ? "rotate-180 text-qx-blue" : ""}`} aria-hidden />
                  </button>
                </h3>
                <div id={`faq-a-${i}`} role="region" aria-labelledby={`faq-q-${i}`} data-open={on} className="qx-acc">
                  <div className="overflow-hidden"><p className="px-5 pb-5 text-[15px] leading-relaxed text-qx-body sm:px-6">{f.a}</p></div>
                </div>
              </li>);
          })}
        </ul>
      </div>
    </Section>);
}
