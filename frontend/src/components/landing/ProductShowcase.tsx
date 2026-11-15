import { StatusTag } from "@/components/ui";
import { DEMO_REPORT } from "@/lib/demo";
import {
  ROLE_LABELS,
  VULN_SEVERITY_STYLES,
  classifyFunctionCode,
  findingSeverityStyle,
  formatNumber,
  functionCodeName,
  riskStyle,
  scoreTone,
} from "@/lib/format";
import type { VulnSeverity } from "@/lib/types";

const SEVERITIES: readonly VulnSeverity[] = ["CRÍTICO", "ALTO", "MÉDIO", "BAIXO"];
const FC_BAR: Record<ReturnType<typeof classifyFunctionCode>, string> = {
  read: "bg-fg-muted",
  write: "bg-status-high",
  diag: "bg-status-critical",
  exception: "bg-status-medium",
  other: "bg-fg-faint",
};

function WindowBar({ url }: { url: string }) {
  return (
    <div className="window-bar">
      <span className="flex gap-1.5" aria-hidden>
        <span className="h-2.5 w-2.5 rounded-full bg-line" />
        <span className="h-2.5 w-2.5 rounded-full bg-line" />
        <span className="h-2.5 w-2.5 rounded-full bg-line" />
      </span>
      <span className="mx-auto flex min-w-0 max-w-[60%] items-center gap-1.5 truncate rounded-sm bg-canvas/70 px-3 py-0.5 font-mono text-[11px] text-fg-faint">
        <span className="truncate">{url}</span>
      </span>
    </div>
  );
}

function ReportWindow() {
  const { report, network_summary: summary } = DEMO_REPORT;
  const tone = scoreTone(report.overall_security_score);
  const risk = riskStyle(report.risk_level);
  const firstSentence = report.executive_summary.split(/(?<=\.)\s/)[0] ?? "";

  return (
    <div className="overflow-hidden rounded-lg border border-line bg-panel">
      <WindowBar url={`purdue-audit/app · laudo · ${DEMO_REPORT.file_name}`} />
      <div className="grid grid-cols-[minmax(0,1fr)] gap-px bg-line md:grid-cols-[220px_minmax(0,1fr)]">
        <div className="bg-panel p-4">
          <p className="label">Security score</p>
          <p className="mt-1.5 flex items-baseline gap-1">
            <span className="num text-[40px] font-medium leading-none text-fg">
              {report.overall_security_score}
            </span>
            <span className="num text-[13px] text-fg-faint">/ 100</span>
          </p>
          <div className="meter mt-2.5">
            <div className={`h-full ${tone.dot}`} style={{ width: `${Math.max(report.overall_security_score, 2)}%` }} />
          </div>
          <div className="mt-2.5">
            <StatusTag tone={risk}>Risco {risk.label.toLowerCase()}</StatusTag>
          </div>
          <ul className="mt-3 space-y-1 text-[12px]">
            {SEVERITIES.map((severity) => {
              const style = VULN_SEVERITY_STYLES[severity];
              const count = report.vulnerabilities.filter((v) => v.severity === severity).length;
              return (
                <li key={severity} className="flex items-center justify-between text-fg-muted">
                  <span className="flex items-center gap-2">
                    <span className={`dot ${style.dot}`} aria-hidden />
                    {style.label}
                  </span>
                  <span className="font-mono tabular-nums text-fg">{count}</span>
                </li>
              );
            })}
          </ul>
        </div>

        <div className="min-w-0 bg-panel">
          <div className="border-b border-line p-4">
            <p className="label">Resumo executivo</p>
            <p className="mt-1.5 text-[13px] leading-relaxed text-fg">{firstSentence}</p>
          </div>
          <table className="w-full text-left text-[12px]">
            <thead>
              <tr className="font-mono text-[10.5px] uppercase tracking-wider text-fg-faint">
                <th scope="col" className="px-4 py-2 font-normal">
                  Ativo
                </th>
                <th scope="col" className="px-2 py-2 font-normal">
                  Papel inferido
                </th>
                <th scope="col" className="hidden px-4 py-2 text-right font-normal sm:table-cell">
                  Pacotes
                </th>
              </tr>
            </thead>
            <tbody>
              {summary.assets.slice(0, 5).map((asset) => (
                <tr key={asset.ip} className="border-t border-line/70">
                  <td className="px-4 py-1.5 font-mono text-fg">{asset.ip}</td>
                  <td className="truncate px-2 py-1.5 text-fg-muted">{ROLE_LABELS[asset.inferred_role]}</td>
                  <td className="hidden px-4 py-1.5 text-right font-mono tabular-nums text-fg-muted sm:table-cell">
                    {formatNumber(asset.packets_sent + asset.packets_received)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

function HistogramCard() {
  const histogram = DEMO_REPORT.network_summary.modbus_analysis?.function_code_histogram ?? {};
  const rows = Object.entries(histogram)
    .map(([hex, count]) => ({ hex, code: Number.parseInt(hex, 16), count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 5);
  const max = Math.max(1, ...rows.map((r) => r.count));

  return (
    <div className="rounded-lg border border-line bg-panel p-4">
      <p className="text-[14px] font-semibold text-fg">Modbus TCP · Function Codes</p>
      <ul className="mt-3 space-y-2">
        {rows.map((row) => (
          <li key={row.hex} className="grid grid-cols-[minmax(0,190px)_minmax(0,1fr)_24px] items-center gap-2 text-[11px]">
            <span className="truncate text-fg-muted">
              <span className="font-mono text-fg">{row.hex}</span> {functionCodeName(row.code)}
            </span>
            <span className="h-2 rounded-r-sm bg-raised">
              <span
                className={`block h-2 rounded-r-sm ${FC_BAR[classifyFunctionCode(row.code)]}`}
                style={{ width: `${Math.max(4, (row.count / max) * 100)}%` }}
              />
            </span>
            <span className="text-right font-mono tabular-nums text-fg-muted">{row.count}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

function OpcUaCard() {
  const channel = DEMO_REPORT.network_summary.opcua_channels[0];
  if (!channel) return null;
  return (
    <div className="rounded-lg border border-line bg-panel p-4">
      <div className="flex items-center justify-between gap-3">
        <p className="text-[14px] font-semibold text-fg">OPC UA · canal seguro</p>
        <StatusTag tone={VULN_SEVERITY_STYLES["CRÍTICO"]}>Sem criptografia</StatusTag>
      </div>
      <p className="mt-2.5 flex items-center gap-2 font-mono text-[12px] text-fg">
        <span className="dot bg-status-critical" aria-hidden />
        {channel.client_ip} → {channel.server_ip}:{channel.server_port}
      </p>
      <p className="mt-1 font-mono text-[11px] text-fg-faint">SecurityPolicy#{channel.security_policy}</p>
    </div>
  );
}

function FindingToast() {
  const finding = DEMO_REPORT.network_summary.deterministic_findings.find((f) => f.rule_id === "OT-MODBUS-001");
  if (!finding) return null;
  return (
    <div className="rounded-lg border border-line bg-panel px-4 py-3">
      <div className="flex items-center gap-2">
        <StatusTag tone={findingSeverityStyle(finding.severity)} />
        <span className="font-mono text-[11px] text-fg-faint">{finding.rule_id}</span>
      </div>
      <p className="mt-1.5 text-[12px] font-medium text-fg">{finding.title}</p>
      <p className="mt-0.5 num text-[11px] text-fg-muted">ativos: {finding.affected_assets.join(", ")}</p>
    </div>
  );
}

/** Composição em camadas (janela do laudo + cartões flutuantes), montada com os dados reais da demo. */
export function ProductShowcase() {
  return (
    <div className="relative">
      <div className="relative rounded-lg border border-line bg-canvas p-3 sm:p-6 lg:px-16 lg:pb-24 lg:pt-10">
        <ReportWindow />

        <div className="mt-3 grid grid-cols-[minmax(0,1fr)] gap-3 sm:grid-cols-2 lg:hidden">
          <HistogramCard />
          <OpcUaCard />
        </div>

        <div className="absolute -bottom-10 left-4 hidden w-[320px] lg:block xl:-left-6">
          <HistogramCard />
        </div>
        <div className="absolute -right-4 -top-6 hidden w-[350px] lg:block xl:-right-8">
          <OpcUaCard />
        </div>
        <div className="absolute -bottom-6 right-10 hidden w-[340px] lg:block">
          <FindingToast />
        </div>
      </div>

      <p className="num mt-14 text-center text-[13px] text-fg-faint lg:mt-16">
        {DEMO_REPORT.file_name} · {formatNumber(DEMO_REPORT.network_summary.capture_metadata.total_packets)} pkts ·{" "}
        {formatNumber(DEMO_REPORT.processing_time_ms)} ms · payload LLM {formatNumber(DEMO_REPORT.llm_payload_bytes)} B ·
        temp removido
      </p>
    </div>
  );
}
