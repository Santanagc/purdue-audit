import { Cpu, Globe, HelpCircle, Laptop, Monitor, type LucideIcon } from "lucide-react";

import { PanelHeader, StatusTag } from "@/components/ui";
import { ROLE_LABELS, formatNumber, type SeverityStyle } from "@/lib/format";
import type { AssetInventoryItem, InferredRole } from "@/lib/types";

const ROLE_ICONS: Record<InferredRole, LucideIcon> = {
  "PLC / Field Slave": Cpu,
  "HMI / SCADA Master": Monitor,
  "Engineering Workstation / IT Host": Laptop,
  "External Host": Globe,
  Unknown: HelpCircle,
};

interface AssetTableProps {
  assets: AssetInventoryItem[];
  /** Pior severidade de achado por IP; ativos sem achado não aparecem no mapa. */
  flaggedAssets: ReadonlyMap<string, SeverityStyle>;
}

export function AssetTable({ assets, flaggedAssets }: AssetTableProps) {
  return (
    <section id="ativos" className="panel scroll-mt-16 overflow-hidden" aria-labelledby="assets-title">
      <PanelHeader id="assets-title" title="Inventário de ativos OT" meta={`${assets.length} ativos inferidos passivamente`} />
      <div className="overflow-x-auto print:overflow-visible">
        <table className="data-table min-w-[760px] print:min-w-0">
          <thead>
            <tr>
              <th scope="col">Endereço IP</th>
              <th scope="col">MAC</th>
              <th scope="col">Papel inferido</th>
              <th scope="col">Portas de serviço</th>
              <th scope="col" className="text-right">
                Pkts enviados
              </th>
              <th scope="col" className="text-right">
                Pkts recebidos
              </th>
            </tr>
          </thead>
          <tbody>
            {assets.map((asset) => {
              const RoleIcon = ROLE_ICONS[asset.inferred_role];
              const worst = flaggedAssets.get(asset.ip);
              return (
                <tr key={asset.ip} className="hover:bg-raised/40">
                  <td className="font-mono text-fg">
                    <span className="flex items-center gap-2">
                      {asset.ip}
                      {worst && <StatusTag tone={worst} />}
                    </span>
                  </td>
                  <td className="font-mono text-[12px] text-fg-muted">{asset.mac ?? "— (roteado)"}</td>
                  <td>
                    <span className="flex items-center gap-2 text-fg">
                      <RoleIcon className="h-3.5 w-3.5 text-fg-faint" aria-hidden />
                      {ROLE_LABELS[asset.inferred_role]}
                    </span>
                  </td>
                  <td>
                    <div className="flex flex-wrap gap-1">
                      {asset.open_ports.length === 0 ? (
                        <span className="text-[12px] text-fg-faint">cliente</span>
                      ) : (
                        asset.open_ports.map((port) => (
                          <span key={port} className="tag font-mono">
                            {port}
                          </span>
                        ))
                      )}
                    </div>
                  </td>
                  <td className="text-right font-mono tabular-nums text-fg-muted">{formatNumber(asset.packets_sent)}</td>
                  <td className="text-right font-mono tabular-nums text-fg-muted">
                    {formatNumber(asset.packets_received)}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </section>
  );
}
