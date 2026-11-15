import { PanelHeader } from "@/components/ui";
import type { SecurityFlags } from "@/lib/types";

const FLAG_LABELS: ReadonlyArray<{ key: keyof SecurityFlags; label: string; detail: string }> = [
  {
    key: "unencrypted_cleartext_protocol",
    label: "Protocolos em texto claro",
    detail: "Tráfego de controle sem criptografia (SR 4.1)",
  },
  {
    key: "lack_of_authentication",
    label: "Ausência de autenticação",
    detail: "Comandos aceitos sem identificar a origem (SR 1.1)",
  },
  {
    key: "it_ot_convergence_detected",
    label: "Convergência TI/OT",
    detail: "Protocolos de TI no segmento dos CLPs (SR 5.1)",
  },
  {
    key: "external_exposure_detected",
    label: "Exposição externa",
    detail: "Ativos OT falando com IPs públicos (SR 5.2)",
  },
];

export function SecurityFlagsPanel({ flags }: { flags: SecurityFlags }) {
  const raisedCount = FLAG_LABELS.filter(({ key }) => flags[key]).length;

  return (
    <section id="indicadores" className="panel scroll-mt-16 overflow-hidden" aria-labelledby="flags-title">
      <PanelHeader id="flags-title" title="Indicadores de segurança" meta={`${raisedCount} de ${FLAG_LABELS.length} detectados`} />
      <ul className="grid gap-px bg-line sm:grid-cols-2 lg:grid-cols-4">
        {FLAG_LABELS.map(({ key, label, detail }) => {
          const raised = flags[key];
          return (
            <li key={key} className="bg-panel px-4 py-3">
              <p className="flex items-center gap-2 text-[13px] font-medium text-fg">
                <span className={`dot ${raised ? "bg-status-critical" : "bg-status-low"}`} aria-hidden />
                {raised ? "Detectado" : "Não detectado"}
              </p>
              <p className="mt-1 text-[13px] text-fg">{label}</p>
              <p className="mt-0.5 text-[12px] text-fg-faint">{detail}</p>
            </li>
          );
        })}
      </ul>
    </section>
  );
}
