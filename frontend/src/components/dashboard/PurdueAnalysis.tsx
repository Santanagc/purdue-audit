import { PanelHeader, StatusTag } from "@/components/ui";
import { findingSeverityStyle } from "@/lib/format";
import type { AssetInventoryItem, DeterministicFinding } from "@/lib/types";

interface PurdueAnalysisProps {
  assets: AssetInventoryItem[];
  findings: DeterministicFinding[];
  analysis: string;
}

interface Zone {
  id: string;
  level: string;
  title: string;
  hosts: string[];
}

function isPrivateOrLocal(ip: string): boolean {
  if (ip.includes(":")) {
    const lower = ip.toLowerCase();
    return lower === "::1" || lower.startsWith("fe80") || lower.startsWith("fc") || lower.startsWith("fd");
  }
  const parts = ip.split(".").map(Number);
  if (parts.length !== 4 || parts.some((p) => Number.isNaN(p))) return true;
  const [a = 0, b = 0] = parts;
  return a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || a === 127 || (a === 169 && b === 254);
}

export function PurdueAnalysis({ assets, findings, analysis }: PurdueAnalysisProps) {
  const violations = findings.filter((f) => f.category === "PURDUE" || f.category === "EXPOSURE");
  const violatingHosts = new Set(violations.flatMap((f) => f.affected_assets));

  const external = assets.filter((a) => !isPrivateOrLocal(a.ip)).map((a) => a.ip);
  const internal = assets.filter((a) => isPrivateOrLocal(a.ip));
  const zones: Zone[] = [
    { id: "ext", level: "Internet", title: "Rede externa / IPs públicos", hosts: external },
    {
      id: "it",
      level: "Níveis 3–4",
      title: "TI corporativa / Engenharia",
      hosts: internal
        .filter((a) => a.inferred_role === "Engineering Workstation / IT Host" || a.inferred_role === "Unknown")
        .map((a) => a.ip),
    },
    {
      id: "sup",
      level: "Nível 2",
      title: "Supervisão (HMI / SCADA)",
      hosts: internal.filter((a) => a.inferred_role === "HMI / SCADA Master").map((a) => a.ip),
    },
    {
      id: "ctl",
      level: "Nível 1",
      title: "Controle (CLP / Field)",
      hosts: internal.filter((a) => a.inferred_role === "PLC / Field Slave").map((a) => a.ip),
    },
  ];
  const visibleZones = zones.filter((z) => z.id !== "ext" || z.hosts.length > 0);

  return (
    <section id="purdue" className="panel scroll-mt-16" aria-labelledby="purdue-title">
      <PanelHeader
        id="purdue-title"
        title="Segmentação · Modelo Purdue"
        meta={`${violations.length} violaç${violations.length === 1 ? "ão" : "ões"} de conduíte`}
      />

      <div className="grid gap-5 p-4 lg:grid-cols-[minmax(0,380px)_minmax(0,1fr)]">
        <div aria-label="Diagrama de zonas observadas">
          <ol className="overflow-hidden rounded border border-line">
            {visibleZones.map((zone, index) => {
              const breach = zone.hosts.some((h) => violatingHosts.has(h));
              return (
                <li
                  key={zone.id}
                  className={`relative px-3 py-2.5 ${index > 0 ? "border-t border-line" : ""} ${
                    breach ? "bg-status-critical/[0.06]" : ""
                  }`}
                >
                  {breach && <span className="absolute inset-y-0 left-0 w-[3px] bg-status-critical" aria-hidden />}
                  <div className="flex items-center justify-between gap-2">
                    <p className="text-[13px] font-medium text-fg">{zone.title}</p>
                    <span className="font-mono text-[11px] text-fg-faint">{zone.level}</span>
                  </div>
                  <div className="mt-1.5 flex flex-wrap gap-1">
                    {zone.hosts.length === 0 ? (
                      <span className="text-[12px] text-fg-faint">Nenhum ativo observado</span>
                    ) : (
                      zone.hosts.map((host) => (
                        <span key={host} className="tag font-mono">
                          {violatingHosts.has(host) && <span className="dot bg-status-critical" aria-hidden />}
                          <span className={violatingHosts.has(host) ? "text-fg" : undefined}>{host}</span>
                        </span>
                      ))
                    )}
                  </div>
                </li>
              );
            })}
          </ol>
          <p className="mt-2 flex items-center gap-2 text-[12px] text-fg-faint">
            <span className="dot bg-status-critical" aria-hidden />
            Zona ou ativo envolvido em violação de conduíte
          </p>
        </div>

        <div className="min-w-0">
          <p className="max-w-3xl text-[14px] leading-relaxed text-fg">{analysis}</p>
          {violations.length > 0 && (
            <ul className="mt-4 divide-y divide-line rounded border border-line">
              {violations.map((finding) => (
                <li key={`${finding.rule_id}-${finding.title}`} className="px-3 py-2.5">
                  <div className="flex flex-wrap items-center gap-2">
                    <StatusTag tone={findingSeverityStyle(finding.severity)} />
                    <span className="font-mono text-[11px] text-fg-faint">{finding.rule_id}</span>
                  </div>
                  <p className="mt-1 text-[13px] text-fg">{finding.title}</p>
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>
    </section>
  );
}
