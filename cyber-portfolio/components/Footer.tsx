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
          <a
            href={siteConfig.github}
            target="_blank"
            rel="noopener noreferrer"
            className="transition hover:text-cyan-400"
          >
            GitHub
          </a>
          <a
            href={siteConfig.linkedIn}
            target="_blank"
            rel="noopener noreferrer"
            className="transition hover:text-cyan-400"
          >
            LinkedIn
          </a>
        </div>
      </div>
    </footer>
  );
}
