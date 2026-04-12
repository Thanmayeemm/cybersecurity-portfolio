"use client";

import { motion } from "framer-motion";
import Link from "next/link";
import { siteConfig } from "@/lib/site-config";

const features = [
  "Threat intelligence integration (VirusTotal, AbuseIPDB)",
  "Configurable decision engine (verdicts, confidence)",
  "Slack alerting for high-signal events",
  "SOAR-style automation: enrich → decide → respond",
];

const stack = ["Python", "Flask", "SQLite", "REST APIs", "Slack Webhooks"];

export function Projects() {
  return (
    <section id="projects" className="scroll-mt-24 px-4 py-24 sm:px-6">
      <div className="mx-auto max-w-6xl">
        <motion.h2
          initial={{ opacity: 0, y: 12 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          className="font-display text-3xl font-bold text-white md:text-4xl"
        >
          Projects
        </motion.h2>
        <div className="mt-3 h-1 w-20 rounded-full bg-gradient-to-r from-cyan-500 to-emerald-500" />

        <motion.article
          initial={{ opacity: 0, y: 24 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ duration: 0.5 }}
          className="group mt-12 overflow-hidden rounded-2xl border border-cyber-border bg-gradient-to-br from-cyber-surface to-cyber-bg p-1 transition hover:border-cyan-500/40"
        >
          <div className="rounded-xl bg-cyber-surface/90 p-8 md:p-10">
            <div className="flex flex-col gap-6 md:flex-row md:items-start md:justify-between">
              <div>
                <span className="inline-block rounded-full border border-cyan-500/30 bg-cyan-500/10 px-3 py-1 text-xs font-medium uppercase tracking-wider text-cyan-400">
                  Featured
                </span>
                <h3 className="font-display mt-4 text-2xl font-bold text-white transition group-hover:text-cyan-300 md:text-3xl">
                  Automated Threat Intelligence &amp; SOAR Engine
                </h3>
                <p className="mt-4 max-w-2xl leading-relaxed text-slate-400">
                  A production-style pipeline that ingests security indicators (IPs,
                  domains, file hashes), enriches them with external threat intel,
                  scores risk with a weighted model, and executes response
                  playbooks—including Slack notifications and incident logging.
                </p>
              </div>
              <Link
                href={siteConfig.soarProjectUrl}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex shrink-0 items-center justify-center gap-2 rounded-xl bg-cyan-500 px-6 py-3 text-sm font-semibold text-cyber-bg transition hover:bg-cyan-400 md:self-start"
              >
                View project
                <svg
                  className="h-4 w-4"
                  fill="none"
                  stroke="currentColor"
                  viewBox="0 0 24 24"
                  aria-hidden
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14"
                  />
                </svg>
              </Link>
            </div>

            <div className="mt-8 flex flex-wrap gap-2">
              {stack.map((tech) => (
                <span
                  key={tech}
                  className="rounded-lg border border-slate-600/80 bg-slate-900/50 px-3 py-1 text-xs font-medium text-slate-300"
                >
                  {tech}
                </span>
              ))}
            </div>

            <ul className="mt-8 grid gap-3 sm:grid-cols-2">
              {features.map((f) => (
                <li
                  key={f}
                  className="flex items-center gap-3 text-sm text-slate-400"
                >
                  <span className="flex h-6 w-6 items-center justify-center rounded-md bg-emerald-500/15 text-emerald-400">
                    ✓
                  </span>
                  {f}
                </li>
              ))}
            </ul>
          </div>
        </motion.article>
      </div>
    </section>
  );
}
