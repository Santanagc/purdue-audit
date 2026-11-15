import type { ReactNode } from "react";

import type { SeverityStyle } from "@/lib/format";

/** Rótulo de status: marcador colorido + texto neutro (identidade nunca depende só da cor). */
export function StatusTag({ tone, children }: { tone: SeverityStyle; children?: ReactNode }) {
  return (
    <span className="tag">
      <span className={`dot ${tone.dot}`} aria-hidden />
      <span className="text-fg">{children ?? tone.label}</span>
    </span>
  );
}

interface PanelHeaderProps {
  title: string;
  id?: string;
  meta?: ReactNode;
  icon?: ReactNode;
}

export function PanelHeader({ title, id, meta, icon }: PanelHeaderProps) {
  return (
    <div className="panel-header">
      <h2 id={id} className="panel-title flex items-center gap-2">
        {icon}
        {title}
      </h2>
      {meta && <div className="num text-[11.5px] text-fg-faint">{meta}</div>}
    </div>
  );
}
