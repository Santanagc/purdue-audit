"use client";

import { FileDown, Plus, ShieldCheck, Trash2 } from "lucide-react";
import { useCallback, useMemo } from "react";

import { AssetTable } from "@/components/dashboard/AssetTable";
import { FindingsAppendix } from "@/components/dashboard/FindingsAppendix";
import { ProtocolInsights } from "@/components/dashboard/ProtocolInsights";
import { PurdueAnalysis } from "@/components/dashboard/PurdueAnalysis";
import { ScoreCard } from "@/components/dashboard/ScoreCard";
import { SecurityFlagsPanel } from "@/components/dashboard/SecurityFlagsPanel";
import { VulnerabilityList } from "@/components/dashboard/VulnerabilityList";
import { PROVIDER_LABELS, findingSeverityStyle, formatDateTime, formatNumber, riskStyle, type SeverityStyle } from "@/lib/format";
import type { AuditResponse } from "@/lib/types";

interface DashboardProps {
  result: AuditResponse;
  snapshot: boolean;
  onNewAudit: () => void;
}

function PrintHeader({ result }: { result: AuditResponse }) {
  const risk = riskStyle(result.report.risk_level);
  const meta = result.network_summary.capture_metadata;
  const rows: ReadonlyArray<[string, string]> = [
    ["ID da auditoria", result.audit_id],
    ["Emitido em", formatDateTime(result.generated_at)],
    ["Arquivo analisado", result.file_name],
    ["Janela da captura", `${formatDateTime(meta.capture_start)} → ${formatDateTime(meta.capture_end)}`],
    ["Motor de laudo", PROVIDER_LABELS[result.ai_provider]],
    ["Score / Risco", `${result.report.overall_security_score}/100 · ${risk.label}`],
  ];

  return (
    <header className="hidden print:mb-5 print:block">
      <div className="flex items-start justify-between border-b-2 border-fg pb-3">
        <div>
          <p className="flex items-center gap-1.5 text-[11pt] font-semibold text-fg">
            <ShieldCheck className="h-4 w-4" aria-hidden />
            Purdue Audit
          </p>
          <h1 className="mt-1 text-[16pt] font-semibold text-fg">Laudo Técnico de Auditoria de Cibersegurança Industrial</h1>
          <p className="text-[9pt] text-fg-muted">Análise passiva de tráfego OT · Referência normativa ISA/IEC 62443-3-3</p>
        </div>
        <p className="rounded-[3px] border border-fg px-2 py-0.5 text-[8pt] font-semibold uppercase tracking-wider text-fg">
          Confidencial
        </p>
      </div>
      <table className="mt-3 w-full text-[9pt]">
        <tbody>
          {rows.map(([label, value]) => (
            <tr key={label} className="border-b border-line">
              <th scope="row" className="w-44 py-1 pr-3 text-left font-medium text-fg-muted">
                {label}
              </th>
              <td className="py-1 font-mono text-fg">{value}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </header>
  );
}

interface NavItem {
  id: string;
  label: string;
  count?: number;
}

export function Dashboard({ result, snapshot, onNewAudit }: DashboardProps) {
  const { report, network_summary: summary } = result;

  /** Para cada ativo, a severidade mais alta entre os achados em que ele aparece (INFO não marca o ativo). */
  const flaggedAssets = useMemo(() => {
    const worst = new Map<string, SeverityStyle>();
    for (const finding of summary.deterministic_findings) {
      if (finding.severity === "INFO") continue;
      const style = findingSeverityStyle(finding.severity);
      for (const ip of finding.affected_assets) {
        const current = worst.get(ip);
        if (!current || style.rank < current.rank) worst.set(ip, style);
      }
    }
    return worst;
  }, [summary.deterministic_findings]);

  const exportPdf = useCallback(() => {
    const previousTitle = document.title;
    const stamp = new Date(result.generated_at).toISOString().slice(0, 10);
    document.title = `Laudo-Purdue-Audit-IEC62443-${stamp}-${result.audit_id.slice(0, 8)}`;
    const restore = () => {
      document.title = previousTitle;
      window.removeEventListener("afterprint", restore);
    };
    window.addEventListener("afterprint", restore);
    window.print();
  }, [result.audit_id, result.generated_at]);

  const hasProtocols = summary.modbus_analysis !== null || summary.opcua_channels.length > 0;
  const nav: NavItem[] = [
    { id: "resumo", label: "Resumo" },
    { id: "indicadores", label: "Indicadores" },
    { id: "ativos", label: "Ativos", count: summary.assets.length },
    { id: "purdue", label: "Modelo Purdue" },
    ...(hasProtocols ? [{ id: "protocolos", label: "Protocolos" }] : []),
    { id: "vulnerabilidades", label: "Vulnerabilidades", count: report.vulnerabilities.length },
    ...(summary.deterministic_findings.length > 0
      ? [{ id: "anexo", label: "Anexo técnico", count: summary.deterministic_findings.length }]
      : []),
  ];

  return (
    <main className="flex-1 print:p-0">
      <div className="mx-auto max-w-7xl px-4 pb-10 pt-6 sm:px-6 print:max-w-none print:p-0">
        <PrintHeader result={result} />

        <div className="no-print flex flex-col gap-3 border-b border-line pb-4 md:flex-row md:items-end md:justify-between">
          <div className="min-w-0">
            <p className="label">
              Laudo de auditoria · {result.source === "demo" ? "captura de demonstração" : "upload do cliente"}
            </p>
            <h1 className="mt-1 truncate font-mono text-[18px] font-medium text-fg">{result.file_name}</h1>
            <p className="num mt-1 flex flex-wrap gap-x-3 gap-y-0.5 text-[12px] text-fg-faint">
              <span>{formatDateTime(result.generated_at)}</span>
              <span>{formatNumber(result.processing_time_ms)} ms</span>
              <span>{PROVIDER_LABELS[result.ai_provider]}</span>
              <span className="font-mono">ID {result.audit_id.slice(0, 8)}</span>
            </p>
          </div>
          <div className="flex shrink-0 flex-wrap gap-2">
            <button type="button" onClick={onNewAudit} className="btn-secondary">
              <Plus className="h-3.5 w-3.5" aria-hidden />
              Nova auditoria
            </button>
            <button type="button" onClick={exportPdf} className="btn-primary">
              <FileDown className="h-3.5 w-3.5" aria-hidden />
              Exportar laudo (PDF)
            </button>
          </div>
        </div>

        <p className="no-print mt-3 flex items-center gap-2 text-[12px] text-fg-muted">
          <Trash2 className="h-3.5 w-3.5 text-status-low" aria-hidden />
          PCAP descartado após a análise · {formatNumber(result.llm_payload_bytes)} bytes de metadados enviados ao
          motor de laudo
        </p>
        {snapshot && (
          <p className="no-print mt-1.5 flex items-center gap-2 text-[12px] text-fg-muted">
            <span className="dot bg-status-info" aria-hidden />
            Laudo pré-gerado pelo mesmo motor a partir da captura de demonstração (o servidor de análise pode estar hibernando).
          </p>
        )}

        {summary.capture_metadata.analysis_truncated && (
          <p className="mt-3 flex items-center gap-2 rounded border border-status-medium/50 bg-status-medium/[0.08] px-3 py-2.5 text-[13px] text-fg">
            <span className="dot bg-status-medium" aria-hidden />
            A captura excedeu o limite de pacotes processados; o laudo considera a porção inicial do arquivo.
          </p>
        )}

        <div className="mt-5 grid gap-6 lg:grid-cols-[180px_minmax(0,1fr)] print:block">
          <nav className="no-print hidden lg:block" aria-label="Seções do laudo">
            <ul className="sticky top-16 space-y-0.5">
              {nav.map((item) => (
                <li key={item.id}>
                  <a
                    href={`#${item.id}`}
                    className="flex items-center justify-between rounded px-2.5 py-1.5 text-[13px] text-fg-muted transition-colors hover:bg-raised hover:text-fg"
                  >
                    {item.label}
                    {item.count !== undefined && (
                      <span className="font-mono text-[11px] tabular-nums text-fg-faint">{item.count}</span>
                    )}
                  </a>
                </li>
              ))}
            </ul>
          </nav>

          <div className="min-w-0 space-y-4">
            <ScoreCard report={report} metadata={summary.capture_metadata} assetCount={summary.assets.length} />
            <SecurityFlagsPanel flags={summary.security_flags} />
            <AssetTable assets={summary.assets} flaggedAssets={flaggedAssets} />
            <PurdueAnalysis
              assets={summary.assets}
              findings={summary.deterministic_findings}
              analysis={report.purdue_segmentation_analysis}
            />
            <ProtocolInsights modbus={summary.modbus_analysis} opcua={summary.opcua_channels} />
            <VulnerabilityList vulnerabilities={report.vulnerabilities} />
            <FindingsAppendix findings={summary.deterministic_findings} />

            <footer className="border-t border-line pt-4 text-[12px] leading-relaxed text-fg-faint">
              Laudo gerado por análise passiva de tráfego capturado; nenhum pacote foi transmitido aos ativos da planta.
              O arquivo de captura foi descartado imediatamente após a extração de metadados. Recomendações devem ser
              validadas pela engenharia de automação responsável antes da implementação em produção. Referências:
              ISA/IEC 62443-3-2 (zonas e conduítes) e ISA/IEC 62443-3-3 (requisitos de segurança de sistema).
              <span className="mt-1 block font-mono">ID {result.audit_id}</span>
            </footer>
          </div>
        </div>
      </div>
    </main>
  );
}
