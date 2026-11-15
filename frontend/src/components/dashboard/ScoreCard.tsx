import { StatusTag } from "@/components/ui";
import { VULN_SEVERITY_STYLES, formatDuration, formatNumber, riskStyle, scoreTone } from "@/lib/format";
import type { AuditReportOutput, CaptureMetadata, VulnSeverity } from "@/lib/types";

interface ScoreCardProps {
  report: AuditReportOutput;
  metadata: CaptureMetadata;
  assetCount: number;
}

const SEVERITY_ORDER: readonly VulnSeverity[] = ["CRÍTICO", "ALTO", "MÉDIO", "BAIXO"];

export function ScoreCard({ report, metadata, assetCount }: ScoreCardProps) {
  const score = Math.max(0, Math.min(100, report.overall_security_score));
  const tone = scoreTone(score);
  const risk = riskStyle(report.risk_level);
  const counts = SEVERITY_ORDER.map((severity) => ({
    severity,
    count: report.vulnerabilities.filter((v) => v.severity === severity).length,
  }));
  const paragraphs = report.executive_summary.split(/\n\s*\n/).filter((p) => p.trim().length > 0);

  const stats = [
    { label: "Pacotes analisados", value: formatNumber(metadata.total_packets) },
    { label: "Duração da captura", value: formatDuration(metadata.duration_seconds) },
    { label: "Ativos identificados", value: formatNumber(assetCount) },
    { label: "Vulnerabilidades", value: formatNumber(report.vulnerabilities.length) },
  ];

  return (
    <section id="resumo" className="panel scroll-mt-16 overflow-hidden" aria-labelledby="score-title">
      <div className="grid grid-cols-[minmax(0,1fr)] lg:grid-cols-[260px_minmax(0,1fr)]">
        <div className="border-b border-line p-4 lg:border-b-0 lg:border-r">
          <h2 id="score-title" className="label">
            Security score
          </h2>
          <p className="mt-2 flex items-baseline gap-1">
            <span className="num text-[44px] font-medium leading-none text-fg">{score}</span>
            <span className="num text-[14px] text-fg-faint">/ 100</span>
          </p>
          <div
            className="meter mt-3"
            role="meter"
            aria-valuemin={0}
            aria-valuemax={100}
            aria-valuenow={score}
            aria-label="Security score"
          >
            <div className={`h-full ${tone.dot}`} style={{ width: `${Math.max(score, 2)}%` }} />
          </div>
          <div className="mt-3">
            <StatusTag tone={risk}>Risco {risk.label.toLowerCase()}</StatusTag>
          </div>

          <table className="mt-4 w-full text-[13px]">
            <caption className="label mb-1.5 text-left">Vulnerabilidades por severidade</caption>
            <tbody>
              {counts.map(({ severity, count }) => {
                const style = VULN_SEVERITY_STYLES[severity];
                return (
                  <tr key={severity} className="border-t border-line/70">
                    <th scope="row" className="py-1.5 text-left font-normal text-fg-muted">
                      <span className="flex items-center gap-2">
                        <span className={`dot ${style.dot}`} aria-hidden />
                        {style.label}
                      </span>
                    </th>
                    <td className="py-1.5 text-right font-mono tabular-nums text-fg">{count}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>

        <div className="p-4">
          <h3 className="label">Resumo executivo</h3>
          <div className="mt-2 max-w-3xl space-y-3 text-[14px] leading-relaxed text-fg">
            {paragraphs.map((paragraph) => (
              <p key={paragraph.slice(0, 48)}>{paragraph}</p>
            ))}
          </div>
          <dl className="mt-4 grid grid-cols-2 gap-px overflow-hidden rounded border border-line bg-line md:grid-cols-4">
            {stats.map(({ label, value }) => (
              <div key={label} className="bg-panel px-3 py-2.5">
                <dt className="text-[12px] text-fg-faint">{label}</dt>
                <dd className="num mt-0.5 text-[16px] font-medium text-fg">{value}</dd>
              </div>
            ))}
          </dl>
          <div className="mt-3 flex flex-wrap items-center gap-1.5">
            <span className="mr-1 text-[12px] text-fg-faint">Protocolos:</span>
            {metadata.protocols_detected.map((protocol) => (
              <span key={protocol} className="tag font-mono">
                {protocol}
              </span>
            ))}
          </div>
        </div>
      </div>
    </section>
  );
}
