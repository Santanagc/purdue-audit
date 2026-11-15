import { PanelHeader, StatusTag } from "@/components/ui";
import { findingSeverityStyle } from "@/lib/format";
import type { DeterministicFinding } from "@/lib/types";

export function FindingsAppendix({ findings }: { findings: DeterministicFinding[] }) {
  if (findings.length === 0) return null;

  return (
    <section id="anexo" className="panel scroll-mt-16 overflow-hidden" aria-labelledby="findings-title">
      <PanelHeader
        id="findings-title"
        title="Anexo · Descobertas do motor determinístico"
        meta="Regras aplicadas aos pacotes (Scapy), antes de qualquer interpretação por IA"
      />
      <div className="overflow-x-auto print:overflow-visible">
        <table className="data-table min-w-[720px] print:min-w-0">
          <thead>
            <tr>
              <th scope="col">Regra</th>
              <th scope="col">Severidade</th>
              <th scope="col">Descoberta</th>
              <th scope="col">Ativos</th>
            </tr>
          </thead>
          <tbody>
            {findings.map((finding) => (
              <tr key={`${finding.rule_id}-${finding.title}`}>
                <td className="whitespace-nowrap font-mono text-[12px] text-fg-muted">{finding.rule_id}</td>
                <td>
                  <StatusTag tone={findingSeverityStyle(finding.severity)} />
                </td>
                <td>
                  <p className="text-fg">{finding.title}</p>
                  <p className="mt-0.5 text-[12px] leading-relaxed text-fg-muted">{finding.evidence}</p>
                </td>
                <td className="font-mono text-[12px] text-fg-muted">{finding.affected_assets.join(", ")}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}
