import type { ReactNode } from "react";

/**
 * Abertura de seção: rótulo em caixa alta, título em serifa (entrelinha 1, 32 px abaixo) e texto de apoio.
 * `align="center"` segue o padrão de seções institucionais do estilo Enterprise; `left` para seções de conteúdo denso.
 */
export function SectionHead({
  kicker,
  title,
  titleId,
  align = "left",
  children,
}: {
  kicker: string;
  title: string;
  titleId: string;
  align?: "left" | "center";
  children?: ReactNode;
}) {
  const centered = align === "center";
  return (
    <header className={centered ? "mx-auto max-w-2xl text-center" : "max-w-3xl"}>
      <p className="eyebrow">{kicker}</p>
      <h2 id={titleId} className="h-section mt-4">
        {title}
      </h2>
      {children && <div className={`lede mt-8 ${centered ? "mx-auto" : ""} max-w-2xl`}>{children}</div>}
    </header>
  );
}

/** Ficha técnica do diagrama ou do laudo: grade de metadados com valores monoespaçados. */
export function TitleBlock({ cells, className = "" }: { cells: ReadonlyArray<[string, string]>; className?: string }) {
  return (
    <dl className={`grid grid-cols-2 gap-px bg-line sm:grid-cols-3 ${className}`}>
      {cells.map(([term, value]) => (
        <div key={term} className="min-w-0 bg-band px-4 py-3">
          <dt className="text-[13px] text-fg-faint">{term}</dt>
          <dd className="num mt-0.5 truncate text-[14px] text-fg">{value}</dd>
        </div>
      ))}
    </dl>
  );
}
