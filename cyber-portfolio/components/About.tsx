"use client";

import { motion } from "framer-motion";
import { siteConfig } from "@/lib/site-config";

const highlights = [
  "Threat-informed automation & API integrations",
  "Detection engineering mindset (SIEM / EDR context)",
  "Python backends & secure configuration practices",
];

export function About() {
  return (
    <section id="about" className="scroll-mt-24 px-4 py-24 sm:px-6">
      <div className="mx-auto max-w-6xl">
        <motion.h2
          initial={{ opacity: 0, y: 12 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          className="font-display text-3xl font-bold text-white md:text-4xl"
        >
          About
        </motion.h2>
        <div className="mt-3 h-1 w-20 rounded-full bg-gradient-to-r from-cyan-500 to-emerald-500" />

        <div className="mt-10 grid gap-10 md:grid-cols-2">
          <motion.div
            initial={{ opacity: 0, x: -20 }}
            whileInView={{ opacity: 1, x: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.5 }}
            className="rounded-2xl border border-cyber-border bg-cyber-surface/60 p-8 backdrop-blur-sm"
          >
            <h3 className="font-display text-lg font-semibold text-cyan-400">
              Professional summary
            </h3>
            <p className="mt-4 leading-relaxed text-slate-400 whitespace-pre-line">
              {siteConfig.about}
            </p>
          </motion.div>
          <motion.div
            initial={{ opacity: 0, x: 20 }}
            whileInView={{ opacity: 1, x: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.5 }}
            className="rounded-2xl border border-cyber-border bg-cyber-surface/60 p-8 backdrop-blur-sm"
          >
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
          </motion.div>
        </div>
      </div>
    </section>
  );
}
