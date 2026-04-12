"use client";

import { motion } from "framer-motion";
import Link from "next/link";
import { useState } from "react";
import { siteConfig } from "@/lib/site-config";

const links = [
  { href: "#home", label: "Home" },
  { href: "#about", label: "About" },
  { href: "#projects", label: "Projects" },
  { href: "#skills", label: "Skills" },
  { href: "#contact", label: "Contact" },
];

export function Navbar() {
  const [open, setOpen] = useState(false);

  return (
    <motion.header
      initial={{ y: -20, opacity: 0 }}
      animate={{ y: 0, opacity: 1 }}
      transition={{ duration: 0.5 }}
      className="fixed top-0 left-0 right-0 z-40 border-b border-cyber-border/60 bg-cyber-bg/80 backdrop-blur-md"
    >
      <nav className="mx-auto flex max-w-6xl items-center justify-between px-4 py-4 sm:px-6">
        <Link
          href="#home"
          className="font-display text-lg font-semibold tracking-tight text-cyan-400 transition hover:text-cyan-300"
        >
          {siteConfig.name.split(" ")[0]}
          <span className="text-slate-500">.sec</span>
        </Link>
        <ul className="hidden gap-8 text-sm font-medium text-slate-400 md:flex">
          {links.map((l) => (
            <li key={l.href}>
              <Link href={l.href} className="transition hover:text-cyan-400">
                {l.label}
              </Link>
            </li>
          ))}
        </ul>
        <div className="flex items-center gap-3">
          <button
            type="button"
            className="rounded-lg p-2 text-slate-400 md:hidden"
            aria-expanded={open}
            aria-label="Toggle menu"
            onClick={() => setOpen((o) => !o)}
          >
            <svg className="h-6 w-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              {open ? (
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M6 18L18 6M6 6l12 12"
                />
              ) : (
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M4 6h16M4 12h16M4 18h16"
                />
              )}
            </svg>
          </button>
          <Link
            href="#contact"
            className="hidden rounded-lg border border-cyan-500/40 bg-cyan-500/10 px-4 py-2 text-sm font-medium text-cyan-400 transition hover:border-cyan-400/60 hover:bg-cyan-500/20 sm:inline-flex"
          >
            Get in touch
          </Link>
        </div>
      </nav>
      {open && (
        <motion.div
          initial={{ opacity: 0, height: 0 }}
          animate={{ opacity: 1, height: "auto" }}
          className="border-t border-cyber-border/60 bg-cyber-bg/95 px-4 py-4 md:hidden"
        >
          <ul className="flex flex-col gap-3 text-sm font-medium text-slate-300">
            {links.map((l) => (
              <li key={l.href}>
                <Link
                  href={l.href}
                  onClick={() => setOpen(false)}
                  className="block py-1 transition hover:text-cyan-400"
                >
                  {l.label}
                </Link>
              </li>
            ))}
            <li>
              <Link
                href="#contact"
                onClick={() => setOpen(false)}
                className="mt-2 block rounded-lg border border-cyan-500/40 bg-cyan-500/10 px-4 py-2 text-center text-cyan-400"
              >
                Get in touch
              </Link>
            </li>
          </ul>
        </motion.div>
      )}
    </motion.header>
  );
}
