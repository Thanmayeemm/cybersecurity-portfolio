import Link from "next/link";
import { siteConfig } from "@/lib/site-config";

export function Footer() {
  return (
    <footer className="border-t border-cyber-border px-4 py-10 sm:px-6">
      <div className="mx-auto flex max-w-6xl flex-col items-center justify-between gap-4 sm:flex-row">
        <p className="text-sm text-slate-500">
          © {new Date().getFullYear()} {siteConfig.name}. Built with Next.js &amp;
          Tailwind CSS.
        </p>
        <div className="flex gap-6 text-sm text-slate-500">
          <Link href={siteConfig.github} className="hover:text-cyan-400">
            GitHub
          </Link>
          <Link href={siteConfig.linkedIn} className="hover:text-cyan-400">
            LinkedIn
          </Link>
        </div>
      </div>
    </footer>
  );
}
