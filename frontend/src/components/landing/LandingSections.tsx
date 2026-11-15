import { ArrowRight, ChevronRight } from "lucide-react";
import Link from "next/link";
import type { ReactNode } from "react";

import { SectionHead } from "@/components/landing/Sheet";
import { StatusTag } from "@/components/ui";
import { DEMO_REPORT } from "@/lib/demo";
import { VULN_SEVERITY_STYLES, findingSeverityStyle, formatNumber } from "@/lib/format";
import { AUTHOR_NAME, LINKEDIN_URL, REPO_URL } from "@/lib/site";

export const DEMO_HREF = "/app?demo";
export const TOOL_HREF = "/app";

const SUMMARY = DEMO_REPORT.network_summary;
const MODBUS = SUMMARY.modbus_analysis;

/* -------------------------------------------------------------------------- */
/* Faixa de aviso, marca e navegação                                          */
/* -------------------------------------------------------------------------- */

export function AnnouncementBar() {
  return (
    <div className="bg-accent text-band">
      <p className="frame flex min-h-[44px] flex-wrap items-center justify-center gap-x-2 py-2 text-center text-[14px]">
        <span>Projeto de portfólio · motor de 17 regras e laudo ISA/IEC 62443-3-3.</span>
        <Link href={DEMO_HREF} className="font-medium underline underline-offset-4 hover:text-inverse-muted">
          Ver laudo de exemplo
        </Link>
      </p>
    </div>
  );
}

export function Wordmark({ inverse = false }: { inverse?: boolean }) {
  return (
    <span className="flex items-center gap-2">
      <span
        className={`grid h-8 w-8 place-items-center rounded border font-mono text-[11px] font-medium ${
          inverse ? "border-inverse-line bg-inverse-raised text-inverse-fg" : "border-line bg-band text-fg"
        }`}
        aria-hidden
      >
        OT
      </span>
      <span className={`font-display text-[19px] font-semibold ${inverse ? "text-inverse-fg" : "text-fg"}`}>OT-Shield</span>
    </span>
  );
}

const NAV_LINKS: ReadonlyArray<[string, string]> = [
  ["#pipeline", "Pipeline"],
  ["#regras", "Regras"],
  ["#api", "API"],
  ["#seguranca", "Segurança"],
];

export function LandingNav() {
  return (
    <header className="sticky top-0 z-40 border-b border-line bg-canvas/95 backdrop-blur supports-[backdrop-filter]:bg-canvas/85">
      <div className="frame grid h-16 grid-cols-[1fr_auto] items-center gap-4 md:grid-cols-[1fr_auto_1fr]">
        <nav className="hidden items-center gap-1 md:flex" aria-label="Seções">
          {NAV_LINKS.map(([href, label]) => (
            <a
              key={href}
              href={href}
              className="rounded px-3 py-2 text-[15px] text-fg-muted transition-colors duration-150 hover:bg-raised/70 hover:text-fg"
            >
              {label}
            </a>
          ))}
        </nav>
        <Link href="/" aria-label="OT-Shield AI — início" className="justify-self-start md:justify-self-center">
          <Wordmark />
        </Link>
        <div className="flex items-center justify-end gap-2">
          {REPO_URL && (
            <a href={REPO_URL} target="_blank" rel="noopener noreferrer" className="btn-ghost hidden sm:inline-flex">
              GitHub
            </a>
          )}
          <Link href={TOOL_HREF} className="btn-primary font-display">
            Abrir ferramenta
          </Link>
        </div>
      </div>
    </header>
  );
}

/* -------------------------------------------------------------------------- */
/* Protocolos cobertos                                                        */
/* -------------------------------------------------------------------------- */

const COVERAGE: ReadonlyArray<[string, string]> = [
  ["Modbus TCP", "502"],
  ["OPC UA", "4840"],
  ["S7comm", "102"],
  ["EtherNet/IP", "44818"],
  ["DNP3", "20000"],
  ["IEC 60870-5-104", "2404"],
  ["BACnet", "47808"],
];

export function CoverageStrip() {
  return (
    <section className="border-y border-line bg-band" aria-labelledby="coverage-title">
      <div className="frame py-12 text-center">
        <h2 id="coverage-title" className="eyebrow">
          Protocolos reconhecidos pelo motor
        </h2>
        <ul className="mt-8 flex flex-wrap items-baseline justify-center gap-x-8 gap-y-5">
          {COVERAGE.map(([name, port]) => (
            <li key={name} className="flex items-baseline gap-2">
              <span className="font-display text-[19px] font-semibold text-fg-muted">{name}</span>
              <span className="num text-[13px] text-fg-faint">{port}</span>
            </li>
          ))}
        </ul>
      </div>
    </section>
  );
}

/* -------------------------------------------------------------------------- */
/* Pipeline                                                                   */
/* -------------------------------------------------------------------------- */

interface Stage {
  name: string;
  text: string;
  artifact: string;
  module: string;
}

const STAGES: readonly Stage[] = [
  {
    name: "Captura",
    text: "Espelhamento de porta SPAN ou TAP passivo. A ferramenta nunca injeta tráfego na rede.",
    artifact: "tcpdump -i eth1 -w planta.pcap",
    module: "fora da ferramenta",
  },
  {
    name: "Upload",
    text: "Streaming em blocos de 1 MiB para um temporário isolado, com limite de tamanho e verificação da assinatura do arquivo.",
    artifact: "0xA1B2C3D4 · 0x0A0D0D0A",
    module: "audit_upload()",
  },
  {
    name: "Dissecação",
    text: "Leitura pacote a pacote: cabeçalho MBAP do Modbus, OpenSecureChannel do OPC UA, SNMP e fluxos entre zonas.",
    artifact: `${formatNumber(SUMMARY.capture_metadata.total_packets)} pacotes · ${SUMMARY.assets.length} ativos · ${SUMMARY.deterministic_findings.length} achados`,
    module: "pcap_analyzer.py",
  },
  {
    name: "Descarte",
    text: "O arquivo é removido no bloco finally, com sucesso ou erro, antes de qualquer chamada à IA.",
    artifact: "os.remove(temp_path)",
    module: "_secure_remove()",
  },
  {
    name: "Laudo",
    text: "Resumo de até 4 KB enviado ao auditor; a resposta é validada pelo schema AuditReportOutput.",
    artifact: `${formatNumber(DEMO_REPORT.llm_payload_bytes)} B → score ${DEMO_REPORT.report.overall_security_score}/100`,
    module: "ai_auditor.py",
  },
];

export function Pipeline() {
  return (
    <section id="pipeline" className="frame section scroll-mt-20" aria-labelledby="pipeline-title">
      <SectionHead kicker="Como funciona" title="Cinco etapas entre o arquivo e o laudo." titleId="pipeline-title">
        Sem agente instalado, sem varredura ativa e sem janela de manutenção. Cada etapa corresponde a um módulo do
        backend.
      </SectionHead>

      <ol className="mt-14 overflow-hidden rounded-lg border border-line bg-panel">
        {STAGES.map((stage, index) => (
          <li
            key={stage.name}
            className={`grid gap-3 px-5 py-5 transition-colors duration-150 hover:bg-band lg:grid-cols-12 lg:items-center lg:gap-6 ${
              index > 0 ? "border-t border-line" : ""
            }`}
          >
            <span className="font-display text-[24px] font-semibold leading-none text-fg-faint lg:col-span-1">
              {index + 1}
            </span>
            <span className="text-[16px] font-semibold text-fg lg:col-span-2">{stage.name}</span>
            <span className="text-[15px] leading-relaxed text-fg-muted lg:col-span-5">{stage.text}</span>
            <span className="min-w-0 lg:col-span-4">
              <code className="block truncate rounded border border-line bg-band px-2.5 py-1.5 font-mono text-[13px] text-fg">
                {stage.artifact}
              </code>
              <span className="num mt-1.5 block text-[13px] text-fg-faint">{stage.module}</span>
            </span>
          </li>
        ))}
      </ol>
    </section>
  );
}

/* -------------------------------------------------------------------------- */
/* Regras (bento 7/5)                                                         */
/* -------------------------------------------------------------------------- */

function Card({
  title,
  rules,
  text,
  children,
  className = "",
}: {
  title: string;
  rules: string;
  text: string;
  children: ReactNode;
  className?: string;
}) {
  return (
    <article className={`flex min-w-0 flex-col rounded-lg border border-line bg-panel p-6 sm:p-8 ${className}`}>
      <p className="num text-[13px] text-fg-faint">{rules}</p>
      <h3 className="mt-3 font-display text-[24px] font-semibold leading-tight text-fg">{title}</h3>
      <p className="mt-3 max-w-lg text-[15px] leading-relaxed text-fg-muted">{text}</p>
      <div className="mt-8 flex-1">{children}</div>
    </article>
  );
}

function WritersVisual() {
  const slave = MODBUS?.slaves[0];
  if (!slave) return null;
  const writers = new Set(slave.writers);
  return (
    <div className="overflow-hidden rounded-md border border-line">
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-line bg-band px-4 py-2.5">
        <span className="num text-[14px] text-fg">CLP {slave.slave_ip}:502</span>
        <span className="num text-[13px] text-fg-faint">
          leitura {slave.read_requests} · escrita {slave.write_requests} · exceções {slave.exception_responses}
        </span>
      </div>
      <ul className="divide-y divide-line">
        {slave.masters.map((master) => {
          const writes = writers.has(master);
          const primary = master === slave.primary_master;
          return (
            <li key={master} className="flex flex-wrap items-center justify-between gap-2 px-4 py-2.5 text-[14px]">
              <span className="num text-fg">
                {master}
                {primary && <span className="ml-2 font-sans text-[13px] text-fg-faint">mestre primário</span>}
              </span>
              {writes ? (
                <StatusTag tone={primary ? VULN_SEVERITY_STYLES["MÉDIO"] : VULN_SEVERITY_STYLES["CRÍTICO"]}>
                  {primary ? "escrita" : "escrita não autorizada"}
                </StatusTag>
              ) : (
                <span className="tag">leitura</span>
              )}
            </li>
          );
        })}
      </ul>
    </div>
  );
}

const POLICIES: ReadonlyArray<{ name: string; tone: keyof typeof VULN_SEVERITY_STYLES; verdict: string }> = [
  { name: "None", tone: "CRÍTICO", verdict: "sem assinatura nem criptografia" },
  { name: "Basic128Rsa15", tone: "MÉDIO", verdict: "depreciada" },
  { name: "Basic256", tone: "MÉDIO", verdict: "depreciada" },
  { name: "Basic256Sha256", tone: "BAIXO", verdict: "recomendada" },
];

function PolicyVisual() {
  const detected = SUMMARY.opcua_channels[0]?.security_policy ?? "";
  return (
    <ul className="overflow-hidden rounded-md border border-line">
      {POLICIES.map((policy, index) => {
        const hit = policy.name === detected;
        return (
          <li
            key={policy.name}
            className={`flex items-center justify-between gap-3 px-4 py-2.5 text-[14px] ${index > 0 ? "border-t border-line" : ""} ${
              hit ? "bg-band" : ""
            }`}
          >
            <span className="flex min-w-0 items-center gap-2.5">
              <span className={`dot ${VULN_SEVERITY_STYLES[policy.tone].dot}`} aria-hidden />
              <span className="num truncate text-fg">#{policy.name}</span>
            </span>
            {hit ? <span className="tag text-fg">detectada</span> : <span className="text-[13px] text-fg-faint">{policy.verdict}</span>}
          </li>
        );
      })}
    </ul>
  );
}

function ZonesVisual() {
  const zones: ReadonlyArray<[string, string, boolean]> = [
    ["Internet", "203.0.113.77", true],
    ["Níveis 3–4 · TI", "192.168.10.50 · .60", true],
    ["Nível 2 · Supervisão", "192.168.10.5", false],
    ["Nível 1 · Controle", "192.168.10.10 · .20", true],
  ];
  return (
    <ol className="overflow-hidden rounded-md border border-line">
      {zones.map(([zone, hosts, breach], index) => (
        <li
          key={zone}
          className={`flex flex-wrap items-center justify-between gap-2 px-4 py-2.5 text-[14px] ${index > 0 ? "border-t border-line" : ""}`}
        >
          <span className="flex items-center gap-2.5 text-fg">
            <span className={`dot ${breach ? "bg-status-critical" : "bg-line-strong"}`} aria-hidden />
            {zone}
          </span>
          <span className="num text-[13px] text-fg-faint">{hosts}</span>
        </li>
      ))}
    </ol>
  );
}

function ReportExcerpt() {
  const vulns = DEMO_REPORT.report.vulnerabilities.slice(0, 4);
  return (
    <div className="grid grid-cols-[minmax(0,1fr)] gap-6 sm:grid-cols-[minmax(0,1fr)_180px] sm:items-end">
      <div className="rounded-md border border-line bg-white p-5 text-fg">
        <div className="flex items-start justify-between gap-3 border-b border-fg pb-2">
          <p className="font-display text-[15px] font-semibold leading-tight">
            Laudo Técnico de Auditoria de Cibersegurança Industrial
          </p>
          <span className="shrink-0 rounded border border-fg px-1 font-mono text-[9px] uppercase">Confidencial</span>
        </div>
        <p className="num mt-2 text-[11px] text-fg-faint">
          score {DEMO_REPORT.report.overall_security_score}/100 · ISA/IEC 62443-3-3
        </p>
        <ul className="mt-3 space-y-1.5">
          {vulns.map((vuln) => (
            <li key={vuln.id} className="flex items-start gap-2 text-[12px] leading-snug">
              <span className="dot mt-[5px] h-1.5 w-1.5 bg-status-critical" aria-hidden />
              <span>{vuln.title}</span>
            </li>
          ))}
        </ul>
      </div>
      <div className="space-y-3">
        <p className="text-[14px] leading-relaxed text-fg-muted">
          {DEMO_REPORT.report.vulnerabilities.length} vulnerabilidades com requisito SR, evidência e mitigação.
        </p>
        <Link href={DEMO_HREF} className="link-arrow">
          Abrir laudo
          <ChevronRight className="h-4 w-4" aria-hidden />
        </Link>
      </div>
    </div>
  );
}

export function RulesBento() {
  return (
    <section id="regras" className="scroll-mt-20 border-t border-line bg-band" aria-labelledby="rules-title">
      <div className="frame section">
        <SectionHead kicker="Motor determinístico" title="17 regras aplicadas antes de qualquer IA." titleId="rules-title">
          Cada achado traz evidência extraída dos pacotes, impacto operacional e o requisito SR correspondente da
          IEC 62443-3-3. Os dados abaixo são da captura de demonstração.
        </SectionHead>

        <div className="mt-14 grid gap-4 lg:grid-cols-12">
          <Card
            className="lg:col-span-7"
            rules="OT-MODBUS-001 · 002 · 006"
            title="Escrita Modbus por mais de um mestre"
            text="Function Codes 0x05, 0x06, 0x0F e 0x10 lidos do cabeçalho MBAP. Mais de uma origem escrevendo no mesmo CLP indica um mestre não autorizado."
          >
            <WritersVisual />
          </Card>
          <Card
            className="lg:col-span-5"
            rules="OT-OPCUA-001 · 002 · 003"
            title="SecurityPolicy do OPC UA"
            text="A política de segurança é lida da mensagem OpenSecureChannel e classificada conforme a OPC Foundation."
          >
            <PolicyVisual />
          </Card>
          <Card
            className="lg:col-span-5"
            rules="OT-PURDUE-001 · 002 · OT-EXPOSURE-001"
            title="Zonas e conduítes"
            text="SMB, RDP, Telnet, FTP, HTTP e SNMP v1/v2c no segmento de controle; CLPs falando com endereços públicos."
          >
            <ZonesVisual />
          </Card>
          <Card
            className="lg:col-span-7"
            rules="Exportação A4"
            title="Laudo pronto para o cliente"
            text="Resumo executivo, inventário, análise Purdue e plano de mitigação sem parada de planta, exportados em PDF."
          >
            <ReportExcerpt />
          </Card>
        </div>
      </div>
    </section>
  );
}

/* -------------------------------------------------------------------------- */
/* Segurança                                                                  */
/* -------------------------------------------------------------------------- */

const CONTROLS: ReadonlyArray<[string, string, string]> = [
  ["Análise passiva", "Somente leitura de arquivo; nenhum socket é aberto para a rede de origem.", "PcapReader(handle)"],
  ["Zero retenção", "Temporário removido no finally, inclusive quando a captura é inválida (422).", "_secure_remove()"],
  ["Validação de entrada", "Extensão, assinatura do arquivo e limite de tamanho em streaming (400 / 413 / 422).", "PCAP_MAGIC_NUMBERS"],
  ["Rate limit", "O IP do cliente é o salto adicionado pelo proxy; X-Forwarded-For forjado é ignorado.", "client_ip()"],
  ["Cabeçalhos HTTP", "CSP restritiva, X-Frame-Options DENY, nosniff, no-store e HSTS em produção.", "SECURITY_HEADERS"],
  ["Container", "Imagem multi-stage slim, usuário não-root (UID 10001) e healthcheck.", "backend/Dockerfile"],
];

export function SecuritySection() {
  return (
    <section id="seguranca" className="frame section scroll-mt-20" aria-labelledby="security-title">
      <SectionHead kicker="Segurança" title="Controles da própria ferramenta." titleId="security-title">
        Capturas de planta revelam topologia, endereçamento e lógica de controle. Cada controle abaixo é coberto pelos 33
        testes automatizados do backend.
      </SectionHead>

      <div className="mt-14 overflow-x-auto rounded-lg border border-line bg-panel">
        <table className="data-table min-w-[680px]">
          <thead>
            <tr>
              <th scope="col" className="w-48">
                Controle
              </th>
              <th scope="col">Implementação</th>
              <th scope="col" className="w-52">
                Referência
              </th>
            </tr>
          </thead>
          <tbody>
            {CONTROLS.map(([control, impl, ref]) => (
              <tr key={control} className="transition-colors duration-150 hover:bg-band">
                <td className="font-semibold text-fg">{control}</td>
                <td className="text-fg-muted">{impl}</td>
                <td className="num text-[13px] text-fg-faint">{ref}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}

/* -------------------------------------------------------------------------- */
/* Chamada final e rodapé                                                     */
/* -------------------------------------------------------------------------- */

export function CtaBand() {
  const top = SUMMARY.deterministic_findings[0];
  return (
    <section className="frame pb-20 lg:pb-28" aria-labelledby="cta-title">
      <div className="grid gap-10 rounded-lg bg-accent p-8 text-band sm:p-12 lg:grid-cols-12 lg:items-center">
        <div className="lg:col-span-7">
          <h2 id="cta-title" className="font-display text-[32px] font-semibold leading-none sm:text-[40px]">
            Veja o laudo completo da demonstração.
          </h2>
          <p className="mt-8 max-w-xl text-[16px] leading-relaxed text-inverse-muted sm:text-[18px]">
            SCADA, dois CLPs, um mestre Modbus não autorizado, OPC UA sem criptografia e Telnet a partir da estação de
            engenharia.
          </p>
          <div className="mt-10 flex flex-wrap gap-3">
            <Link href={DEMO_HREF} className="btn btn-lg border-band bg-band text-accent hover:border-raised hover:bg-raised">
              Abrir laudo de demonstração
              <ArrowRight className="h-4 w-4" aria-hidden />
            </Link>
            <Link href={TOOL_HREF} className="btn btn-lg border-inverse-line bg-transparent text-band hover:bg-inverse-raised">
              Enviar .pcap
            </Link>
          </div>
        </div>
        {top && (
          <div className="rounded-md border border-inverse-line bg-inverse-raised p-6 lg:col-span-5">
            <p className="text-[13px] font-semibold uppercase tracking-[0.12em] text-inverse-muted">Primeiro achado</p>
            <p className="num mt-4 text-[13px] text-inverse-muted">
              {findingSeverityStyle(top.severity).label} · {top.rule_id}
            </p>
            <p className="mt-2 text-[16px] font-semibold leading-snug text-band">{top.title}</p>
            <p className="num mt-3 text-[13px] leading-relaxed text-inverse-muted">{top.evidence}</p>
          </div>
        )}
      </div>
    </section>
  );
}

export function LandingFooter() {
  const columns: ReadonlyArray<{ title: string; links: ReadonlyArray<{ label: string; href: string; external?: boolean }> }> = [
    {
      title: "Ferramenta",
      links: [
        { label: "Enviar captura", href: TOOL_HREF },
        { label: "Laudo de demonstração", href: DEMO_HREF },
        { label: "Como funciona", href: "#pipeline" },
        { label: "Segurança", href: "#seguranca" },
      ],
    },
    {
      title: "Código",
      links: [
        { label: "API", href: "#api" },
        ...(REPO_URL ? [{ label: "Repositório", href: REPO_URL, external: true }] : []),
      ],
    },
    ...(LINKEDIN_URL ? [{ title: "Autor", links: [{ label: "LinkedIn", href: LINKEDIN_URL, external: true }] }] : []),
  ];
  const linkClass = "text-[15px] text-inverse-fg transition-colors duration-150 hover:text-inverse-muted";

  return (
    <footer className="bg-accent text-inverse-muted">
      <div className="frame py-16">
        <div className="grid grid-cols-2 gap-10 md:grid-cols-12">
          <div className="col-span-2 md:col-span-6">
            <Wordmark inverse />
            <p className="mt-4 max-w-sm text-[15px] leading-relaxed">
              Auditoria passiva de redes OT/ICS com laudo ISA/IEC 62443-3-3. Projeto de portfólio
              {AUTHOR_NAME ? ` de ${AUTHOR_NAME}` : ""}.
            </p>
          </div>
          {columns.map((column) => (
            <div key={column.title} className="md:col-span-2">
              <h4 className="text-[14px] font-semibold uppercase tracking-[0.12em] text-inverse-muted">{column.title}</h4>
              <ul className="mt-4 space-y-3">
                {column.links.map((link) => (
                  <li key={link.label}>
                    {link.external ? (
                      <a href={link.href} target="_blank" rel="noopener noreferrer" className={linkClass}>
                        {link.label}
                      </a>
                    ) : (
                      <Link href={link.href} className={linkClass}>
                        {link.label}
                      </Link>
                    )}
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>
        <p className="mt-12 border-t border-inverse-line pt-6 text-[14px]">
          v1.0.0 · análise estritamente passiva: nunca se conecta a redes ou CLPs reais.
        </p>
      </div>
    </footer>
  );
}
