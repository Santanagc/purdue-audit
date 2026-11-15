import { ChevronRight } from "lucide-react";
import Link from "next/link";

import { LINKEDIN_URL, REPO_URL } from "@/lib/site";

interface SiteHeaderProps {
  onHome: () => void;
  onAbout: () => void;
  context: string;
}

export function SiteHeader({ onHome, onAbout, context }: SiteHeaderProps) {
  return (
    <header className="no-print sticky top-0 z-40 border-b border-line bg-panel">
      <div className="flex h-12 items-center justify-between gap-3 px-4">
        <div className="flex min-w-0 items-center gap-2">
          <Link href="/" className="flex shrink-0 items-center gap-2" aria-label="Purdue Audit — página inicial">
            <span className="grid h-7 w-7 place-items-center rounded border border-line bg-band font-mono text-[10px] font-medium text-fg" aria-hidden>
              OT
            </span>
            <span className="font-display text-[17px] font-semibold text-fg">Purdue Audit</span>
          </Link>
          <ChevronRight className="h-3.5 w-3.5 shrink-0 text-fg-faint" aria-hidden />
          <button
            type="button"
            onClick={onHome}
            className="truncate text-[13px] text-fg-muted transition-colors duration-150 hover:text-fg"
            title="Voltar para nova auditoria"
          >
            {context}
          </button>
        </div>

        <nav className="flex shrink-0 items-center gap-2" aria-label="Links do projeto">
          <button type="button" onClick={onAbout} className="btn-ghost">
            Sobre o projeto
          </button>
          {LINKEDIN_URL && (
            <a href={LINKEDIN_URL} target="_blank" rel="noopener noreferrer" className="btn-secondary">
              LinkedIn
            </a>
          )}
          {REPO_URL && (
            <a href={REPO_URL} target="_blank" rel="noopener noreferrer" className="btn-secondary">
              Código no GitHub
            </a>
          )}
        </nav>
      </div>
    </header>
  );
}
