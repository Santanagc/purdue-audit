"use client";

import { Check, Circle, LoaderCircle } from "lucide-react";
import { useEffect, useState } from "react";

import type { AuditMode } from "@/lib/view";

const STEPS: readonly string[] = [
  "Leitura da captura em streaming",
  "Inventário de ativos e inferência de papéis",
  "Dissecação dos cabeçalhos MBAP (Modbus TCP)",
  "Classificação de Function Codes de escrita e diagnóstico",
  "Inspeção dos canais seguros OPC UA",
  "Verificação de isolamento entre zonas Purdue",
  "Remoção do arquivo original",
  "Cruzamento com requisitos IEC 62443-3-3",
  "Geração do laudo e do plano de mitigação",
];

const STEP_INTERVAL_MS = 380;

interface ProgressTerminalProps {
  mode: AuditMode;
  fileName: string;
  onCancel: () => void;
}

export function ProgressTerminal({ mode, fileName, onCancel }: ProgressTerminalProps) {
  const [active, setActive] = useState(0);

  useEffect(() => {
    const timer = window.setInterval(() => {
      setActive((current) => (current < STEPS.length - 1 ? current + 1 : current));
    }, STEP_INTERVAL_MS);
    return () => window.clearInterval(timer);
  }, []);

  const progress = Math.round(((active + 1) / STEPS.length) * 100);
  const waiting = active === STEPS.length - 1;

  return (
    <section className="panel" role="status" aria-live="polite" aria-labelledby="progress-title">
      <div className="panel-header">
        <div className="min-w-0">
          <h2 id="progress-title" className="panel-title">
            Análise em andamento {mode === "demo" && <span className="font-normal text-fg-faint">· demo</span>}
          </h2>
          <p className="truncate font-mono text-[12px] text-fg-faint">{fileName}</p>
        </div>
        <button type="button" onClick={onCancel} className="btn-secondary">
          Cancelar
        </button>
      </div>

      <ol className="px-4 py-3">
        {STEPS.map((step, index) => {
          const done = index < active;
          const current = index === active;
          return (
            <li key={step} className="flex items-center gap-2.5 py-1 text-[13px]">
              {done ? (
                <Check className="h-4 w-4 shrink-0 text-fg-muted" aria-hidden />
              ) : current ? (
                <LoaderCircle className="h-4 w-4 shrink-0 animate-spin text-accent-text" aria-hidden />
              ) : (
                <Circle className="h-4 w-4 shrink-0 text-line-strong" aria-hidden />
              )}
              <span className={current ? "text-fg" : done ? "text-fg-muted" : "text-fg-faint"}>{step}</span>
              {current && waiting && <span className="text-fg-faint">· aguardando o auditor</span>}
            </li>
          );
        })}
      </ol>

      <div className="flex items-center gap-3 border-t border-line px-4 py-3">
        <div className="meter flex-1">
          <div className="h-full bg-accent transition-[width] duration-300" style={{ width: `${progress}%` }} />
        </div>
        <span className="w-10 text-right font-mono text-[12px] tabular-nums text-fg-muted">{progress}%</span>
      </div>
    </section>
  );
}
