"use client";

import { motion } from "framer-motion";
import { siteConfig } from "@/lib/site-config";
import { sectionFadeUp } from "@/lib/motion-presets";

const highlights = [
  "Incident triage and IOC analysis with evidence-first case documentation",
  "Threat intelligence enrichment and ATT&CK-aligned detection workflow thinking",
  "Python/Flask API implementation for security automation and response consistency",
];

export function About() {
  return (
    <motion.section
      id="about"
      className="scroll-mt-28 px-4 py-28 sm:px-6 sm:py-32"
      {...sectionFadeUp}
    >
      <div className="mx-auto max-w-6xl">
        <div className="space-y-3">
          <h2 className="font-display text-3xl font-bold tracking-tight text-white md:text-4xl">
            About
          </h2>
          <div className="h-1 w-20 rounded-full bg-gradient-to-r from-cyan-500 to-emerald-500" />
        </div>

        <div className="mt-12 grid gap-8 md:grid-cols-2 md:gap-10">
          <div className="rounded-2xl border border-cyber-border bg-cyber-surface/60 p-8 shadow-lg shadow-black/20 backdrop-blur-sm md:p-9">
            <h3 className="font-display text-lg font-semibold text-cyan-400">
              Professional summary
            </h3>
            <p className="mt-4 leading-relaxed text-slate-400 whitespace-pre-line">
              {siteConfig.about}
            </p>
          </div>
          <div className="rounded-2xl border border-cyber-border bg-cyber-surface/60 p-8 shadow-lg shadow-black/20 backdrop-blur-sm md:p-9">
            <h3 className="font-display text-lg font-semibold text-emerald-400">
              Focus areas
            </h3>
            <ul className="mt-4 space-y-3">
              {highlights.map((item) => (
                <li
                  key={item}
                  className="flex items-start gap-3 text-slate-400"
                >
                  <span className="mt-1.5 h-2 w-2 shrink-0 rounded-full bg-cyan-500" />
                  {item}
                </li>
              ))}
            </ul>
          </div>
        </div>
      </div>
    </motion.section>
  );
}
