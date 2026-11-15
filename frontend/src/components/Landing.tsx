import { AUTHOR_NAME } from "@/lib/site";
import { ProgressTerminal } from "@/components/ProgressTerminal";
import { PanelHeader } from "@/components/ui";
import { UploadPanel } from "@/components/UploadPanel";
import type { ViewState } from "@/lib/view";

interface LandingProps {
  view: Exclude<ViewState, { kind: "done" }>;
  onDemo: () => void;
  onUpload: (file: File) => void;
  onCancel: () => void;
  onDismissError: () => void;
  maxUploadMb: number;
  backendOnline: boolean;
}

interface Guarantee {
  title: string;
  text: string;
}

const GUARANTEES: readonly Guarantee[] = [
  {
    title: "Análise passiva",
    text: "Nenhum pacote é enviado à sua rede. Lemos apenas a captura feita no SPAN/TAP — sem risco de parada de planta.",
  },
  {
    title: "Zero retenção",
    text: "O PCAP é apagado no mesmo request, logo após a dissecação. Só metadados estatísticos (≤ 4.096 B) chegam ao auditor.",
  },
  {
    title: "ISA/IEC 62443-3-3",
    text: "Cada achado é mapeado a um requisito SR (1.1, 3.1, 4.1, 5.1…) com evidência técnica e plano de mitigação.",
  },
];

interface Rule {
  scope: string;
  port: string;
  checks: string;
}

const COVERAGE: readonly Rule[] = [
  { scope: "Modbus TCP", port: "502", checks: "Escritas 0x05/0x06/0x0F/0x10, enumeração 0x08/0x11/0x2B, exceções, múltiplos mestres" },
  { scope: "OPC UA", port: "4840", checks: "SecurityPolicy#None, Basic128Rsa15 e Basic256 depreciadas" },
  { scope: "Modelo Purdue", port: "—", checks: "SMB, RDP, VNC, Telnet, FTP, HTTP e SNMP v1/v2c no segmento de controle" },
  { scope: "Exposição", port: "—", checks: "Ativos OT conversando com IPs públicos fora da RFC 1918" },
];

export function Landing({ view, onDemo, onUpload, onCancel, onDismissError, maxUploadMb, backendOnline }: LandingProps) {
  return (
    <main className="flex-1">
      <div className="mx-auto max-w-6xl px-4 py-8 sm:px-6">
        <div className="max-w-3xl">
          <p className="label">/app · nova auditoria</p>
          <h1 className="mt-2 text-[22px] font-semibold leading-tight tracking-tight text-fg">Enviar captura .pcap / .pcapng</h1>
          <p className="mt-2 text-[14px] leading-relaxed text-fg-muted">
            Capture a partir de uma porta SPAN ou TAP passivo. O motor aplica 17 regras determinísticas (Modbus TCP, OPC UA,
            Modelo Purdue, exposição) e gera o laudo ISA/IEC 62443-3-3.
          </p>
        </div>

        <div className="mt-6 grid gap-4 lg:grid-cols-[minmax(0,1fr)_340px]">
          <div className="min-w-0">
            {view.kind === "loading" ? (
              <ProgressTerminal mode={view.mode} fileName={view.fileName} onCancel={onCancel} />
            ) : (
              <UploadPanel
                disabled={false}
                backendOnline={backendOnline}
                maxUploadMb={maxUploadMb}
                error={view.kind === "error" ? view.message : null}
                onDemo={onDemo}
                onUpload={onUpload}
                onDismissError={onDismissError}
              />
            )}
          </div>

          <aside className="panel h-fit" aria-labelledby="guarantees-title">
            <PanelHeader id="guarantees-title" title="Garantias de processamento" />
            <ul className="divide-y divide-line">
              {GUARANTEES.map((item) => (
                <li key={item.title} className="px-4 py-3">
                  <p className="text-[13px] font-medium text-fg">{item.title}</p>
                  <p className="mt-0.5 text-[12px] leading-relaxed text-fg-muted">{item.text}</p>
                </li>
              ))}
            </ul>
          </aside>
        </div>

        <section className="panel mt-4" aria-labelledby="coverage-title">
          <PanelHeader id="coverage-title" title="Cobertura de análise" meta="Regras determinísticas aplicadas aos pacotes" />
          <div className="overflow-x-auto">
            <table className="data-table min-w-[620px]">
              <thead>
                <tr>
                  <th scope="col" className="w-40">Escopo</th>
                  <th scope="col" className="w-20">Porta</th>
                  <th scope="col">O que é verificado</th>
                </tr>
              </thead>
              <tbody>
                {COVERAGE.map((rule) => (
                  <tr key={rule.scope}>
                    <td className="font-medium text-fg">{rule.scope}</td>
                    <td className="num text-fg-muted">{rule.port}</td>
                    <td className="text-fg-muted">{rule.checks}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>

        <p className="num mt-8 text-[11px] text-fg-faint">
          OT-Shield AI · projeto de portfólio{AUTHOR_NAME ? ` de ${AUTHOR_NAME}` : ""} · ferramenta passiva e
          defensiva: nunca se conecta a redes ou CLPs reais.
        </p>
      </div>
    </main>
  );
}
