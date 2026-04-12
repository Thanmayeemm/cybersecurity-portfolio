"use client";

import { motion } from "framer-motion";

const skillGroups = [
  {
    title: "Security operations",
    items: ["SIEM", "EDR", "Threat detection"],
    icon: "🛡️",
  },
  {
    title: "Development",
    items: ["Python", "Flask"],
    icon: "⚙️",
  },
  {
    title: "Integration & automation",
    items: ["REST APIs", "Automation"],
    icon: "🔗",
  },
  {
    title: "Infrastructure",
    items: ["Cloud basics"],
    icon: "☁️",
  },
];

export function Skills() {
  return (
    <section id="skills" className="scroll-mt-24 px-4 py-24 sm:px-6">
      <div className="mx-auto max-w-6xl">
        <motion.h2
          initial={{ opacity: 0, y: 12 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          className="font-display text-3xl font-bold text-white md:text-4xl"
        >
          Skills
        </motion.h2>
        <div className="mt-3 h-1 w-20 rounded-full bg-gradient-to-r from-cyan-500 to-emerald-500" />

        <div className="mt-12 grid gap-6 sm:grid-cols-2 lg:grid-cols-4">
          {skillGroups.map((group, i) => (
            <motion.div
              key={group.title}
              initial={{ opacity: 0, y: 20 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ delay: i * 0.08 }}
              className="rounded-2xl border border-cyber-border bg-cyber-surface/50 p-6 transition hover:-translate-y-1 hover:border-cyan-500/30 hover:shadow-lg hover:shadow-cyan-500/5"
            >
              <div className="text-2xl">{group.icon}</div>
              <h3 className="font-display mt-3 text-lg font-semibold text-white">
                {group.title}
              </h3>
              <ul className="mt-4 space-y-2 text-sm text-slate-400">
                {group.items.map((item) => (
                  <li key={item}>{item}</li>
                ))}
              </ul>
            </motion.div>
          ))}
        </div>
      </div>
    </section>
  );
}
