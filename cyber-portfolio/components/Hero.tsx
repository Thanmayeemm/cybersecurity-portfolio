"use client";

import { motion } from "framer-motion";
import Link from "next/link";
import { siteConfig } from "@/lib/site-config";

export function Hero() {
  return (
    <section
      id="home"
      className="relative flex min-h-screen flex-col justify-center px-4 pt-24 pb-16 sm:px-6"
    >
      <div className="pointer-events-none absolute inset-0 bg-glow" />
      <div
        className="pointer-events-none absolute inset-0 opacity-[0.35] bg-[length:48px_48px] bg-grid-pattern"
        aria-hidden
      />

      <div className="relative mx-auto max-w-4xl">
        <motion.p
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
          className="mb-4 font-mono text-sm text-cyan-500/90"
        >
          &gt; initializing_profile.exe
        </motion.p>
        <motion.h1
          initial={{ opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }}
          className="font-display text-4xl font-bold tracking-tight text-white sm:text-5xl md:text-6xl"
        >
          {siteConfig.name}
        </motion.h1>
        <motion.p
          initial={{ opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.35 }}
          className="mt-4 text-xl text-cyan-400/90 sm:text-2xl"
        >
          {siteConfig.title}
        </motion.p>
        <motion.p
          initial={{ opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.5 }}
          className="mt-6 max-w-2xl text-lg leading-relaxed text-slate-400"
        >
          {siteConfig.intro}
        </motion.p>
        <motion.div
          initial={{ opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.65 }}
          className="mt-10 flex flex-wrap gap-4"
        >
          <Link
            href="#projects"
            className="group inline-flex items-center gap-2 rounded-xl bg-gradient-to-r from-cyan-500 to-emerald-500 px-8 py-3.5 text-sm font-semibold text-cyber-bg shadow-lg shadow-cyan-500/20 transition hover:shadow-cyan-500/40"
          >
            View projects
            <span className="transition group-hover:translate-x-1">→</span>
          </Link>
          <Link
            href="#contact"
            className="rounded-xl border border-slate-600 bg-cyber-surface/50 px-8 py-3.5 text-sm font-semibold text-slate-200 transition hover:border-cyan-500/50 hover:text-white"
          >
            Contact me
          </Link>
        </motion.div>
      </div>
    </section>
  );
}
