"use client";

import { motion, useReducedMotion } from "framer-motion";
import { sectionFadeUp } from "@/lib/motion-presets";

const skillGroups = [
  {
    title: "Security operations",
    items: ["SIEM", "EDR", "Threat detection"],
    icon: "🛡️",
  },
  {
    title: "Development",
    items: ["Python", "Flask", "SQLite"],
    icon: "⚙️",
  },
  {
    title: "Integration & automation",
    items: ["REST APIs", "Webhooks", "Automation"],
    icon: "🔗",
  },
  {
    title: "Infrastructure",
    items: ["Cloud basics"],
    icon: "☁️",
  },
];

export function Skills() {
  const reduceMotion = useReducedMotion();

  return (
    <motion.section
      id="skills"
      className="scroll-mt-28 px-4 py-28 sm:px-6 sm:py-32"
      {...sectionFadeUp}
    >
      <div className="mx-auto max-w-6xl">
        <div className="space-y-3">
          <h2 className="font-display text-3xl font-bold tracking-tight text-white md:text-4xl">
            Skills
          </h2>
          <div className="h-1 w-20 rounded-full bg-gradient-to-r from-cyan-500 to-emerald-500" />
        </div>

        <div className="mt-12 grid gap-6 sm:grid-cols-2 lg:grid-cols-4">
          {skillGroups.map((group) => (
            <motion.div
              key={group.title}
              whileHover={
                reduceMotion
                  ? undefined
                  : {
                      y: -4,
                      boxShadow: "0 20px 40px -12px rgba(34, 211, 238, 0.14)",
                    }
              }
              transition={{ duration: 0.28, ease: [0.22, 1, 0.36, 1] }}
              className="rounded-2xl border border-cyber-border bg-cyber-surface/50 p-6 shadow-md shadow-black/15 transition-colors hover:border-cyan-500/35"
            >
              <div className="text-2xl" aria-hidden>
                {group.icon}
              </div>
              <h3 className="font-display mt-3 text-lg font-semibold text-white">
                {group.title}
              </h3>
              <ul className="mt-4 space-y-2 text-sm leading-relaxed text-slate-400">
                {group.items.map((item) => (
                  <li key={item}>{item}</li>
                ))}
              </ul>
            </motion.div>
          ))}
        </div>
      </div>
    </motion.section>
  );
}
