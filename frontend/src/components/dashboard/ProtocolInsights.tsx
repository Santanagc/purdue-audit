import { LockKeyhole, LockKeyholeOpen } from "lucide-react";

import { PanelHeader, StatusTag } from "@/components/ui";
import {
  VULN_SEVERITY_STYLES,
  classifyFunctionCode,
  formatNumber,
  functionCodeName,
  type FcClass,
  type SeverityStyle,
} from "@/lib/format";
import type { ModbusAnalysis, OpcUaChannel, OpcUaPolicyRisk } from "@/lib/types";

/** Leitura usa o acento (tráfego esperado); classes de risco usam a escala de status, sempre com rótulo. */
const FC_CLASS_STYLES: Record<FcClass, { label: string; bar: string }> = {
  read: { label: "Leitura", bar: "bg-fg-muted" },
  write: { label: "Escrita", bar: "bg-status-high" },
  diag: { label: "Diagnóstico", bar: "bg-status-critical" },
  exception: { label: "Exceção", bar: "bg-status-medium" },
  other: { label: "Outro", bar: "bg-fg-faint" },
};

const UNKNOWN_TONE: SeverityStyle = { label: "Indeterminada", dot: "bg-fg-faint", text: "text-fg-faint", rank: 5 };

const POLICY_STYLES: Record<OpcUaPolicyRisk, { label: string; tone: SeverityStyle; secure: boolean }> = {
  CRITICAL: { label: "Sem criptografia", tone: VULN_SEVERITY_STYLES["CRÍTICO"], secure: false },
  DEPRECATED: { label: "Depreciada", tone: VULN_SEVERITY_STYLES["MÉDIO"], secure: false },
  SECURE: { label: "Segura", tone: VULN_SEVERITY_STYLES.BAIXO, secure: true },
  UNKNOWN: { label: "Indeterminada", tone: UNKNOWN_TONE, secure: false },
};

function FunctionCodeHistogram({ histogram }: { histogram: Record<string, number> }) {
  const rows = Object.entries(histogram)
    .map(([hex, count]) => ({ hex, code: Number.parseInt(hex, 16), count }))
    .filter((row) => !Number.isNaN(row.code))
    .sort((a, b) => b.count - a.count);
  const max = Math.max(1, ...rows.map((r) => r.count));
  const total = rows.reduce((sum, r) => sum + r.count, 0);
  const classes = Array.from(new Set(rows.map((row) => classifyFunctionCode(row.code))));

  return (
    <div>
      <div className="mb-2 flex flex-wrap gap-3 text-[12px] text-fg-muted" aria-label="Legenda">
        {classes.map((cls) => (
          <span key={cls} className="flex items-center gap-1.5">
            <span className={`dot ${FC_CLASS_STYLES[cls].bar}`} aria-hidden />
            {FC_CLASS_STYLES[cls].label}
          </span>
        ))}
      </div>
      <table className="w-full text-[13px]" aria-label="Distribuição de Function Codes Modbus">
        <thead className="sr-only">
          <tr>
            <th scope="col">Function Code</th>
            <th scope="col">Volume</th>
            <th scope="col">Mensagens</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => {
            const cls = FC_CLASS_STYLES[classifyFunctionCode(row.code)];
            const share = total > 0 ? Math.round((row.count / total) * 100) : 0;
            return (
              <tr key={row.hex} className="group">
                <td className="w-[48%] py-1 pr-3 align-middle">
                  <span className="font-mono text-[12px] text-fg">{row.hex}</span>{" "}
                  <span className="text-[12px] text-fg-muted">{functionCodeName(row.code)}</span>
                  <span className="sr-only"> ({cls.label})</span>
                </td>
                <td className="py-1 pr-3 align-middle">
                  <div className="relative h-2.5">
                    <div
                      className={`h-2.5 rounded-r-[2px] ${cls.bar}`}
                      style={{ width: `${Math.max(2, (row.count / max) * 100)}%` }}
                    />
                    <span className="pointer-events-none absolute -top-7 left-0 z-10 hidden whitespace-nowrap rounded border border-line-strong bg-raised px-2 py-0.5 font-mono text-[11px] text-fg group-hover:block print:hidden">
                      {row.hex} · {cls.label} · {formatNumber(row.count)} msgs · {share}%
                    </span>
                  </div>
                </td>
                <td className="w-[1%] whitespace-nowrap py-1 text-right align-middle font-mono text-[12px] tabular-nums text-fg-muted">
                  {formatNumber(row.count)}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

interface ProtocolInsightsProps {
  modbus: ModbusAnalysis | null;
  opcua: OpcUaChannel[];
}

export function ProtocolInsights({ modbus, opcua }: ProtocolInsightsProps) {
  if (!modbus && opcua.length === 0) return null;

  return (
    <section id="protocolos" className="grid scroll-mt-16 gap-4 xl:grid-cols-2" aria-label="Protocolos industriais">
      {modbus && (
        <div className="panel" aria-labelledby="modbus-title">
          <PanelHeader id="modbus-title" title="Modbus TCP · Function Codes" meta="porta 502" />
          <dl className="grid grid-cols-3 gap-px border-b border-line bg-line">
            {[
              { label: "Requisições", value: modbus.total_requests },
              { label: "Respostas", value: modbus.total_responses },
              { label: "Exceções", value: modbus.exception_responses },
            ].map((stat) => (
              <div key={stat.label} className="bg-panel px-4 py-2.5">
                <dt className="text-[12px] text-fg-faint">{stat.label}</dt>
                <dd className="mt-0.5 text-[16px] font-medium tabular-nums text-fg">{formatNumber(stat.value)}</dd>
              </div>
            ))}
          </dl>
          <div className="p-4">
            <FunctionCodeHistogram histogram={modbus.function_code_histogram} />
          </div>
          <ul className="divide-y divide-line border-t border-line">
            {modbus.slaves.map((slave) => (
              <li key={slave.slave_ip} className="px-4 py-2.5 text-[12px]">
                <p className="font-mono text-[13px] text-fg">CLP {slave.slave_ip}</p>
                <p className="mt-1 text-fg-muted">
                  Mestre primário <span className="font-mono text-fg">{slave.primary_master ?? "—"}</span> · Mestres{" "}
                  <span className="font-mono text-fg">{slave.masters.join(", ")}</span>
                </p>
                <p className="mt-0.5 flex flex-wrap items-center gap-x-1 text-fg-muted">
                  Escritores
                  {slave.writers.length > 1 && <span className="dot ml-0.5 bg-status-high" aria-hidden />}
                  <span className="font-mono text-fg">{slave.writers.length > 0 ? slave.writers.join(", ") : "nenhum"}</span>
                  {slave.writers.length > 1 && <span className="text-fg">(múltiplos)</span>}
                  <span>
                    · Leituras {slave.read_requests} · Escritas {slave.write_requests} · Diag. {slave.diagnostic_requests} ·
                    Exceções {slave.exception_responses}
                  </span>
                </p>
              </li>
            ))}
          </ul>
        </div>
      )}

      <div className="panel h-fit" aria-labelledby="opcua-title">
        <PanelHeader id="opcua-title" title="OPC UA · Canais seguros" meta="porta 4840" />
        {opcua.length === 0 ? (
          <p className="px-4 py-3 text-[13px] text-fg-muted">Nenhuma sessão OPC UA observada nesta captura.</p>
        ) : (
          <ul className="divide-y divide-line">
            {opcua.map((channel) => {
              const style = POLICY_STYLES[channel.policy_risk];
              const Icon = style.secure ? LockKeyhole : LockKeyholeOpen;
              return (
                <li key={`${channel.client_ip}-${channel.server_ip}-${channel.server_port}`} className="px-4 py-3">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <p className="flex items-center gap-2 font-mono text-[13px] text-fg">
                      <Icon className="h-3.5 w-3.5 text-fg-faint" aria-hidden />
                      {channel.client_ip} → {channel.server_ip}:{channel.server_port}
                    </p>
                    <StatusTag tone={style.tone}>{style.label}</StatusTag>
                  </div>
                  <p className="mt-1.5 break-all font-mono text-[12px] text-fg-muted">
                    SecurityPolicy#{channel.security_policy}
                  </p>
                </li>
              );
            })}
          </ul>
        )}
        <p className="border-t border-line px-4 py-2.5 text-[12px] leading-relaxed text-fg-faint">
          Políticas recomendadas pela OPC Foundation: Basic256Sha256, Aes128_Sha256_RsaOaep e Aes256_Sha256_RsaPss, com
          modo SignAndEncrypt e certificados X.509.
        </p>
      </div>
    </section>
  );
}
