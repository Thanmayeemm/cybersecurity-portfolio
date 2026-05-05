"use client";

import { motion, useReducedMotion } from "framer-motion";
import Image from "next/image";
import Link from "next/link";
import { useState } from "react";
import { siteConfig } from "@/lib/site-config";
import { sectionFadeUp } from "@/lib/motion-presets";

const MotionLink = motion(Link);

const features = [
  "Threat intelligence enrichment via VirusTotal and AbuseIPDB",
  "IOC triage workflow: ingest → enrich → risk score → incident handling action",
  "Analyst-facing alerting and playbook-style response flow",
  "Standardized API-driven scoring logic for consistent triage decisions",
];

const stack = ["Python", "Flask", "SQLite", "REST APIs", "Slack Webhooks"];

const socHighlights = [
  "5+ completed investigations spanning 6 SOC scenarios (phishing, brute force, ransomware, data exfiltration, malware infection, insider threat)",
  "Repeatable case workflow: triage → IOC extraction → enrichment → ATT&CK mapping → remediation",
  "Evidence-based case documentation for consistent incident response decisions",
];

const awsStack = [
  "Prowler",
  "AWS CLI",
  "CIS AWS Foundations v2.0",
  "IAM",
  "S3",
  "CloudTrail",
  "VPC security groups",
];

const awsFeatures = [
  "Lab-scoped CIS AWS Foundations v2.0.0 assessment using Prowler with scripted introduce/remediate flows",
  "Six deliberate misconfigurations mapped to CIS controls (S3 exposure, IAM admin attachment, CloudTrail coverage, public SSH ingress, root MFA, password policy)",
  "Formal audit narrative with risk ratings, attacker impact scenarios, and remediation verification placeholders",
  "MITRE ATT&CK mapping table tying findings to tactics and techniques",
];

function ProjectScreenshot({
  src,
  alt,
  caption,
  contain = false,
}: {
  src: string;
  alt: string;
  caption: string;
  contain?: boolean;
}) {
  const [failed, setFailed] = useState(false);
  const reduceMotion = useReducedMotion();

  const ease = [0.22, 1, 0.36, 1] as const;

  if (failed) {
    return (
      <figure className="flex h-full min-h-0 flex-col overflow-hidden rounded-xl border border-dashed border-cyber-border/80 bg-cyber-bg/80">
        <div className="relative flex aspect-[16/10] w-full shrink-0 flex-col items-center justify-center gap-2 px-6 py-10 text-center">
          <span className="text-sm text-slate-500">Add screenshot</span>
          <span className="break-all font-mono text-xs text-slate-600">
            public{src}
          </span>
        </div>
        <figcaption className="mt-auto border-t border-cyber-border/60 px-3 py-2.5 text-center text-xs text-slate-500">
          {caption}
        </figcaption>
      </figure>
    );
  }

  return (
    <figure className="group/shot flex h-full min-h-0 flex-col overflow-hidden rounded-xl border border-cyber-border/80 bg-black/25 shadow-xl shadow-cyan-500/10 ring-1 ring-cyan-500/15">
      <motion.div
        className="relative aspect-[16/10] w-full shrink-0 overflow-hidden bg-black/30"
        whileHover={reduceMotion ? undefined : { scale: 1.03 }}
        transition={{ duration: 0.48, ease }}
      >
        <Image
          src={src}
          alt={alt}
          fill
          sizes="(min-width: 1024px) min(50vw, 36rem), 100vw"
          className={
            contain
              ? "object-contain bg-black/55 p-2"
              : "object-cover object-top"
          }
          unoptimized
          onError={() => setFailed(true)}
        />
      </motion.div>
      <figcaption className="mt-auto border-t border-cyber-border/60 px-3 py-2.5 text-center text-xs leading-relaxed text-slate-500">
        {caption}
      </figcaption>
    </figure>
  );
}

export function Projects() {
  const reduceMotion = useReducedMotion();
  const cardHover = reduceMotion
    ? {}
    : {
        scale: 1.008,
        boxShadow: "0 24px 48px -16px rgba(34, 211, 238, 0.12)",
      };

  return (
    <motion.section
      id="projects"
      className="scroll-mt-28 px-4 py-28 sm:px-6 sm:py-32"
      {...sectionFadeUp}
      initial={false}
    >
      <div className="mx-auto max-w-6xl">
        <div className="space-y-3">
          <h2 className="font-display text-3xl font-bold tracking-tight text-white md:text-4xl">
            Projects
          </h2>
          <div className="h-1 w-20 rounded-full bg-gradient-to-r from-cyan-500 to-emerald-500" />
        </div>

        <motion.article
          whileHover={cardHover}
          transition={{ duration: 0.35, ease: [0.22, 1, 0.36, 1] }}
          className="group mt-12 overflow-hidden rounded-2xl border border-cyber-border bg-gradient-to-br from-cyber-surface to-cyber-bg p-1 shadow-lg shadow-black/25 transition-[border-color] hover:border-cyan-500/45"
        >
          <div className="rounded-xl bg-cyber-surface/90 p-8 md:p-10">
            <div className="flex flex-col gap-8 md:flex-row md:items-start md:justify-between md:gap-10">
              <div className="min-w-0 flex-1">
                <span className="inline-block rounded-full border border-cyan-500/30 bg-cyan-500/10 px-3 py-1 text-xs font-medium uppercase tracking-wider text-cyan-400">
                  Featured
                </span>
                <h3 className="font-display mt-4 text-2xl font-bold text-white transition group-hover:text-cyan-300 md:text-3xl">
                  Automated Threat Intelligence &amp; SOAR Engine
                </h3>
                <p className="mt-4 max-w-2xl leading-relaxed text-slate-400">
                  Security automation pipeline for Security Operations workflows:
                  ingest IOC data (IP/domain/hash), enrich with threat intelligence,
                  risk-score outcomes, and trigger alerting/playbook response steps
                  for SOC analyst triage and incident handling.
                </p>
                <p className="mt-3 max-w-2xl text-sm leading-relaxed text-slate-300">
                  Impact: Standardized enrichment, scoring, and alerting to
                  reduce manual triage variance and improve analyst response
                  consistency.
                </p>
              </div>
              <div className="flex shrink-0 flex-col gap-3 sm:flex-row md:flex-col lg:flex-row lg:items-start">
                <MotionLink
                  href={siteConfig.soarProjectUrl}
                  target="_blank"
                  rel="noopener noreferrer"
                  whileHover={reduceMotion ? {} : { scale: 1.02 }}
                  whileTap={reduceMotion ? {} : { scale: 0.98 }}
                  transition={{ duration: 0.2, ease: [0.22, 1, 0.36, 1] }}
                  className="inline-flex items-center justify-center gap-2 rounded-xl bg-cyan-500 px-6 py-3 text-sm font-semibold text-cyber-bg shadow-md shadow-cyan-500/20 hover:bg-cyan-400"
                >
                  SOAR source
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
                </MotionLink>
                <MotionLink
                  href={siteConfig.github}
                  target="_blank"
                  rel="noopener noreferrer"
                  whileHover={reduceMotion ? {} : { scale: 1.02 }}
                  whileTap={reduceMotion ? {} : { scale: 0.98 }}
                  transition={{ duration: 0.2, ease: [0.22, 1, 0.36, 1] }}
                  className="inline-flex items-center justify-center rounded-xl border border-slate-600 bg-transparent px-6 py-3 text-sm font-semibold text-slate-200 hover:border-cyan-500/50 hover:text-white"
                >
                  Full repo
                </MotionLink>
              </div>
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

            <ul className="mt-8 grid gap-3 sm:grid-cols-2 sm:gap-x-8 sm:gap-y-3">
              {features.map((f) => (
                <li
                  key={f}
                  className="flex items-center gap-3 text-sm leading-snug text-slate-400"
                >
                  <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-md bg-emerald-500/15 text-emerald-400">
                    ✓
                  </span>
                  {f}
                </li>
              ))}
            </ul>

            <div className="mt-12 grid items-stretch gap-8 lg:grid-cols-2 lg:gap-10">
              <ProjectScreenshot
                src="/images/dashboard.png"
                alt="SOAR engine web dashboard with indicator analysis and incident table"
                caption="Web dashboard — enrichment, verdict, incidents"
              />
              <ProjectScreenshot
                src="/images/slack-alert.png"
                alt="Slack alert from SOAR playbook with VT and Abuse scores"
                caption="Slack alerting — suspicious indicator notification"
              />
            </div>
          </div>
        </motion.article>

        <motion.article
          whileHover={cardHover}
          transition={{ duration: 0.35, ease: [0.22, 1, 0.36, 1] }}
          className="group mt-8 overflow-hidden rounded-2xl border border-cyber-border bg-gradient-to-br from-cyber-surface to-cyber-bg p-1 shadow-lg shadow-black/25 transition-[border-color] hover:border-emerald-500/45"
        >
          <div className="rounded-xl bg-cyber-surface/90 p-8 md:p-10">
            <div className="flex flex-col gap-8 md:flex-row md:items-start md:justify-between md:gap-10">
              <div className="min-w-0 flex-1">
                <span className="inline-block rounded-full border border-emerald-500/30 bg-emerald-500/10 px-3 py-1 text-xs font-medium uppercase tracking-wider text-emerald-400">
                  SOC Case Lab
                </span>
                <h3 className="font-display mt-4 text-2xl font-bold text-white transition group-hover:text-emerald-300 md:text-3xl">
                  SOC Incident Investigation Lab
                </h3>
                <p className="mt-4 max-w-2xl leading-relaxed text-slate-400">
                  Analyst-readiness case lab demonstrating Security Operations
                  workflows across six incident types using repeatable
                  investigation steps and defensible evidence handling.
                </p>
                <p className="mt-3 max-w-2xl text-sm leading-relaxed text-slate-300">
                  Impact: Demonstrates repeatable, evidence-based SOC case
                  handling that supports faster and more consistent incident
                  decisions.
                </p>
              </div>
              <div className="flex shrink-0 flex-col gap-3 sm:flex-row md:flex-col lg:flex-row lg:items-start">
                <MotionLink
                  href={siteConfig.socInvestigationUrl}
                  target="_blank"
                  rel="noopener noreferrer"
                  whileHover={reduceMotion ? {} : { scale: 1.02 }}
                  whileTap={reduceMotion ? {} : { scale: 0.98 }}
                  transition={{ duration: 0.2, ease: [0.22, 1, 0.36, 1] }}
                  className="inline-flex items-center justify-center gap-2 rounded-xl bg-emerald-500 px-6 py-3 text-sm font-semibold text-cyber-bg shadow-md shadow-emerald-500/20 hover:bg-emerald-400"
                >
                  SOC lab source
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
                </MotionLink>
              </div>
            </div>

            <div className="mt-8 grid gap-6 lg:grid-cols-2">
              <div>
                <h4 className="text-sm font-semibold uppercase tracking-wider text-slate-300">
                  Highlights
                </h4>
                <ul className="mt-4 grid gap-3">
                  {socHighlights.map((item) => (
                    <li
                      key={item}
                      className="flex items-start gap-3 text-sm leading-snug text-slate-400"
                    >
                      <span className="mt-0.5 flex h-6 w-6 shrink-0 items-center justify-center rounded-md bg-emerald-500/15 text-emerald-400">
                        ✓
                      </span>
                      {item}
                    </li>
                  ))}
                </ul>
              </div>

              <div>
                <h4 className="text-sm font-semibold uppercase tracking-wider text-slate-300">
                  Snapshot
                </h4>
                <p className="mt-5 text-sm leading-relaxed text-slate-400">
                  Operational evidence from real case work: command-line triage
                  output and suspicious access analysis tied to incident
                  response decisions.
                </p>
              </div>
            </div>

            <div className="mt-10 grid items-stretch gap-8 lg:grid-cols-2 lg:gap-10">
              <ProjectScreenshot
                src="/images/attacker_ip.png"
                alt="Terminal output showing ranked failed login attempts by attacker IP"
                caption="Incident triage evidence — failed login IOC pattern analysis"
                contain
              />
              <ProjectScreenshot
                src="/images/sensitive_access.png"
                alt="Evidence view showing suspicious or sensitive access behavior"
                caption="Detection evidence — suspicious access behavior for response validation"
                contain
              />
            </div>
          </div>
        </motion.article>

        <motion.article
          whileHover={cardHover}
          transition={{ duration: 0.35, ease: [0.22, 1, 0.36, 1] }}
          className="group mt-8 overflow-hidden rounded-2xl border border-cyber-border bg-gradient-to-br from-cyber-surface to-cyber-bg p-1 shadow-lg shadow-black/25 transition-[border-color] hover:border-violet-500/45"
        >
          <div className="rounded-xl bg-cyber-surface/90 p-8 md:p-10">
            <div className="flex flex-col gap-8 md:flex-row md:items-start md:justify-between md:gap-10">
              <div className="min-w-0 flex-1">
                <span className="inline-block rounded-full border border-violet-500/30 bg-violet-500/10 px-3 py-1 text-xs font-medium uppercase tracking-wider text-violet-300">
                  Cloud Security Audit
                </span>
                <h3 className="font-display mt-4 text-2xl font-bold text-white transition group-hover:text-violet-200 md:text-3xl">
                  AWS Cloud Security Audit — CIS Foundations Benchmark v2.0
                </h3>
                <p className="mt-4 max-w-2xl leading-relaxed text-slate-400">
                  Cloud posture assessment of an AWS lab account using Prowler
                  against CIS AWS Foundations expectations: introduce controlled
                  misconfigurations, capture failing checks, document findings with
                  severity and attacker impact narratives, remediate, and re-scan for
                  verification evidence.
                </p>
                <p className="mt-3 max-w-2xl text-sm leading-relaxed text-slate-300">
                  Impact: Demonstrates end-to-end cloud security auditing literacy —
                  from CSPM evidence collection through analyst-grade reporting and
                  controlled remediation.
                </p>
              </div>
              <div className="flex shrink-0 flex-col gap-3 sm:flex-row md:flex-col lg:flex-row lg:items-start">
                <MotionLink
                  href={siteConfig.awsSecurityAuditUrl}
                  target="_blank"
                  rel="noopener noreferrer"
                  whileHover={reduceMotion ? {} : { scale: 1.02 }}
                  whileTap={reduceMotion ? {} : { scale: 0.98 }}
                  transition={{ duration: 0.2, ease: [0.22, 1, 0.36, 1] }}
                  className="inline-flex items-center justify-center gap-2 rounded-xl bg-violet-500 px-6 py-3 text-sm font-semibold text-white shadow-md shadow-violet-500/25 hover:bg-violet-400"
                >
                  AWS audit source
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
                </MotionLink>
                <MotionLink
                  href={siteConfig.github}
                  target="_blank"
                  rel="noopener noreferrer"
                  whileHover={reduceMotion ? {} : { scale: 1.02 }}
                  whileTap={reduceMotion ? {} : { scale: 0.98 }}
                  transition={{ duration: 0.2, ease: [0.22, 1, 0.36, 1] }}
                  className="inline-flex items-center justify-center rounded-xl border border-slate-600 bg-transparent px-6 py-3 text-sm font-semibold text-slate-200 hover:border-violet-500/50 hover:text-white"
                >
                  Full repo
                </MotionLink>
              </div>
            </div>

            <div className="mt-8 flex flex-wrap gap-2">
              {awsStack.map((tech) => (
                <span
                  key={tech}
                  className="rounded-lg border border-slate-600/80 bg-slate-900/50 px-3 py-1 text-xs font-medium text-slate-300"
                >
                  {tech}
                </span>
              ))}
            </div>

            <ul className="mt-8 grid gap-3 sm:grid-cols-2 sm:gap-x-8 sm:gap-y-3">
              {awsFeatures.map((f) => (
                <li
                  key={f}
                  className="flex items-center gap-3 text-sm leading-snug text-slate-400"
                >
                  <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-md bg-violet-500/15 text-violet-300">
                    ✓
                  </span>
                  {f}
                </li>
              ))}
            </ul>

            <div className="mt-12 grid items-stretch gap-8 lg:grid-cols-2 lg:gap-10">
              <ProjectScreenshot
                src="/images/prowler-before.png"
                alt="Prowler terminal output before remediation (CIS findings)"
                caption="Prowler — representative failing checks before remediation (add image)"
                contain
              />
              <ProjectScreenshot
                src="/images/prowler-after.png"
                alt="Prowler terminal output after remediation (improved posture)"
                caption="Prowler — representative results after remediation (add image)"
                contain
              />
            </div>
          </div>
        </motion.article>
      </div>
    </motion.section>
  );
}
