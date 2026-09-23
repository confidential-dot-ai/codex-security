"use client";

import { usePathname } from "next/navigation";
import Link from "next/link";
import { Logo } from "./logo";
import { ThemeToggle } from "./theme-toggle";

const TABS = [
  { href: "/", label: "Trust" },
  { href: "/scan", label: "Scan" },
];

/** Top bar with the two pages. Not sticky: the page never takes over the screen. */
export function Topbar() {
  const pathname = usePathname();
  return (
    <header className="border-b border-border">
      <div className="mx-auto flex max-w-[860px] items-center justify-between gap-4 px-5 py-4">
        <div className="flex min-w-0 items-center gap-3">
          <a
            href="https://confidential.ai/"
            target="_blank"
            rel="noreferrer"
            className="text-heading transition-opacity hover:opacity-80"
            aria-label="Confidential AI"
          >
            <Logo height={18} />
          </a>
          <span className="hidden font-mono text-[0.65rem] uppercase tracking-[0.12em] text-muted sm:inline">
            codex-security · attested console
          </span>
        </div>
        <nav className="flex items-center gap-4">
          {TABS.map((t) => {
            const active = pathname === t.href;
            return (
              <Link
                key={t.href}
                href={t.href}
                className={`font-mono text-xs uppercase tracking-wider transition-colors ${
                  active ? "text-accent" : "text-muted hover:text-foreground"
                }`}
                aria-current={active ? "page" : undefined}
              >
                {t.label}
              </Link>
            );
          })}
          <ThemeToggle />
        </nav>
      </div>
    </header>
  );
}
