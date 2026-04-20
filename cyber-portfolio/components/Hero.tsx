"use client";

import { motion, useReducedMotion } from "framer-motion";
import Link from "next/link";
import { siteConfig } from "@/lib/site-config";

const MotionLink = motion(Link);

const smooth = [0.22, 1, 0.36, 1] as const;

export function Hero() {
  const reduceMotion = useReducedMotion();
  const hoverPrimary = reduceMotion
    ? {}
    : { scale: 1.02, boxShadow: "0 12px 40px -8px rgba(34, 211, 238, 0.25)" };
  const hoverGhost = reduceMotion ? {} : { scale: 1.02 };

  return (
    <section
      id="home"
      className="relative flex min-h-screen flex-col justify-center overflow-hidden px-4 pt-28 pb-20 sm:px-6 sm:pb-24"
    >
      <div className="pointer-events-none absolute inset-0 bg-glow" />
      <div
        className="pointer-events-none absolute inset-x-0 top-1/3 h-[min(70vh,560px)] -translate-y-1/2 bg-[radial-gradient(ellipse_at_center,rgba(52,211,153,0.07),transparent_62%)]"
        aria-hidden
      />
      <div
        className="pointer-events-none absolute inset-0 opacity-[0.35] bg-[length:48px_48px] bg-grid-pattern"
        aria-hidden
      />

      <motion.div
        initial={{ opacity: 0, y: 26 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.7, ease: smooth }}
        className="relative mx-auto w-full max-w-4xl text-center md:text-left"
      >
        <motion.h1
          initial={{ opacity: 0, y: 18 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.06, duration: 0.6, ease: smooth }}
          className="font-display text-3xl font-bold tracking-tight text-white sm:text-4xl md:text-5xl"
        >
          {siteConfig.title}
        </motion.h1>
        <motion.p
          initial={{ opacity: 0, y: 18 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.18, duration: 0.6, ease: smooth }}
          className="mt-4 text-xl text-cyan-400/90 sm:text-2xl"
        >
          {siteConfig.name}
        </motion.p>
        <motion.p
          initial={{ opacity: 0, y: 18 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.3, duration: 0.6, ease: smooth }}
          className="mx-auto mt-6 max-w-2xl text-lg leading-relaxed text-slate-400 md:mx-0"
        >
          {siteConfig.intro}
        </motion.p>
        <motion.p
          initial={{ opacity: 0, y: 18 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.38, duration: 0.6, ease: smooth }}
          className="mx-auto mt-8 max-w-2xl text-center text-sm text-slate-500 md:mx-0 md:text-left"
        >
          <span className="text-slate-600">Featured on GitHub:</span>{" "}
          <a
            href={siteConfig.soarProjectUrl}
            target="_blank"
            rel="noopener noreferrer"
            className="font-medium text-cyan-400/95 underline decoration-cyan-500/30 underline-offset-4 transition hover:text-cyan-300 hover:decoration-cyan-400/60"
          >
            SOAR threat-intel &amp; automation engine
          </a>
        </motion.p>
        <motion.div
          initial={{ opacity: 0, y: 18 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.42, duration: 0.6, ease: smooth }}
          className="mt-10 flex flex-wrap justify-center gap-4 md:justify-start"
        >
          <MotionLink
            href="#projects"
            whileHover={hoverPrimary}
            whileTap={reduceMotion ? {} : { scale: 0.98 }}
            transition={{ duration: 0.28, ease: smooth }}
            className="group inline-flex items-center gap-2 rounded-xl bg-gradient-to-r from-cyan-500 to-emerald-500 px-8 py-3.5 text-sm font-semibold text-white shadow-lg shadow-cyan-500/20 ring-1 ring-white/15"
          >
            <span className="drop-shadow-sm">View projects</span>
            <span
              className="transition-transform duration-300 ease-out group-hover:translate-x-0.5"
              aria-hidden
            >
              →
            </span>
          </MotionLink>
          <MotionLink
            href="#contact"
            whileHover={hoverGhost}
            whileTap={reduceMotion ? {} : { scale: 0.98 }}
            transition={{ duration: 0.28, ease: smooth }}
            className="rounded-xl border border-slate-600/90 bg-cyber-surface/50 px-8 py-3.5 text-sm font-semibold text-slate-200 shadow-sm transition-all duration-300 ease-out hover:border-cyan-500/45 hover:bg-cyber-surface/80 hover:text-white"
          >
            Contact me
          </MotionLink>
        </motion.div>
      </motion.div>
    </section>
  );
}
