import { ArrowRight } from "lucide-react";
import Link from "next/link";

import { ApiSection, type ApiSample } from "@/components/landing/ApiSection";
import {
  AnnouncementBar,
  CoverageStrip,
  CtaBand,
  DEMO_HREF,
  LandingFooter,
  LandingNav,
  Pipeline,
  RulesBento,
  SecuritySection,
  TOOL_HREF,
} from "@/components/landing/LandingSections";
import { ProductShowcase } from "@/components/landing/ProductShowcase";
import { PurdueDiagram } from "@/components/landing/PurdueDiagram";
import { TitleBlock } from "@/components/landing/Sheet";
import { DEMO_REPORT } from "@/lib/demo";
import { formatNumber } from "@/lib/format";

function apiSample(): ApiSample {
  const finding = DEMO_REPORT.network_summary.deterministic_findings[0];
  return {
    score: DEMO_REPORT.report.overall_security_score,
    riskLevel: DEMO_REPORT.report.risk_level,
    provider: DEMO_REPORT.ai_provider,
    payloadBytes: DEMO_REPORT.llm_payload_bytes,
    ruleId: finding?.rule_id ?? "",
    severity: finding?.severity ?? "",
    title: finding?.title ?? "",
  };
}

export default function LandingPage() {
  const summary = DEMO_REPORT.network_summary;
  const stats: ReadonlyArray<[string, string]> = [
    ["Pacotes na captura de demo", formatNumber(summary.capture_metadata.total_packets)],
    ["Tempo de análise", `${formatNumber(DEMO_REPORT.processing_time_ms)} ms`],
    ["Metadados enviados à IA", `${formatNumber(DEMO_REPORT.llm_payload_bytes)} B`],
    ["Captura retida após o laudo", "0 B"],
  ];
  const titleBlock: ReadonlyArray<[string, string]> = [
    ["Desenho", "Topologia Purdue"],
    ["Fonte", DEMO_REPORT.file_name],
    ["Norma", "IEC 62443-3-2"],
    ["Captura", `${formatNumber(summary.capture_metadata.total_packets)} pacotes`],
    ["Laudo", DEMO_REPORT.audit_id.slice(0, 8)],
    ["Achados", `${summary.deterministic_findings.length} determinísticos`],
  ];

  return (
    <div className="min-h-screen">
      <AnnouncementBar />
      <LandingNav />
      <main>
        <section className="frame pb-20 pt-16 text-center sm:pt-20" aria-labelledby="hero-title">
          <span className="inline-flex items-center gap-2 rounded border border-line bg-band px-2.5 py-1 text-[14px] text-fg">
            <span className="dot bg-status-critical" aria-hidden />
            Auditoria passiva de redes OT/ICS
          </span>
          <h1 id="hero-title" className="display mx-auto mt-6 max-w-4xl">
            Auditoria de redes industriais que a engenharia pode assinar.
          </h1>
          <p className="lede mx-auto mt-8 max-w-2xl">
            Envie uma captura .pcap e receba inventário de ativos, falhas de Modbus TCP e OPC UA, violações do Modelo Purdue
            e um laudo mapeado à ISA/IEC 62443-3-3. Nenhum pacote é enviado à planta.
          </p>
          <div className="mt-10 flex flex-wrap justify-center gap-3">
            <Link href={DEMO_HREF} className="btn-primary btn-lg">
              Abrir laudo de demonstração
              <ArrowRight className="h-4 w-4" aria-hidden />
            </Link>
            <Link href={TOOL_HREF} className="btn-secondary btn-lg">
              Enviar .pcap
            </Link>
          </div>

          <dl className="mx-auto mt-16 grid max-w-4xl grid-cols-2 gap-y-8 border-t border-line pt-10 lg:grid-cols-4">
            {stats.map(([label, value]) => (
              <div key={label} className="px-2">
                <dt className="text-[14px] text-fg-muted">{label}</dt>
                <dd className="mt-2 font-display text-[32px] font-semibold leading-none text-fg">{value}</dd>
              </div>
            ))}
          </dl>

          <figure className="mx-auto mt-16 max-w-5xl overflow-hidden rounded-lg border border-line bg-panel text-left">
            <figcaption className="flex flex-wrap items-center justify-between gap-2 border-b border-line px-4 py-3">
              <span className="text-[15px] font-semibold text-fg">Topologia da captura de demonstração</span>
              <span className="text-[14px] text-fg-muted">Modelo Purdue · tracejado = conduíte violado</span>
            </figcaption>
            <div className="overflow-x-auto" tabIndex={0} role="region" aria-label="Diagrama do Modelo Purdue (role na horizontal em telas estreitas)">
              <div className="min-w-[620px] p-4 sm:p-6">
                <PurdueDiagram />
              </div>
            </div>
            <TitleBlock cells={titleBlock} className="border-t border-line" />
          </figure>
        </section>

        <CoverageStrip />

        <section className="bg-band" aria-labelledby="showcase-title">
          <div className="frame section">
            <div className="mx-auto max-w-2xl text-center">
              <p className="eyebrow">Laudo de demonstração</p>
              <h2 id="showcase-title" className="h-section mt-4">
                O laudo que sai da ferramenta.
              </h2>
              <p className="lede mx-auto mt-8">
                Score, risco, inventário e achados abaixo são os dados reais da captura sintética, não uma ilustração.
              </p>
            </div>
            <div className="mt-14">
              <ProductShowcase />
            </div>
          </div>
        </section>

        <Pipeline />
        <RulesBento />
        <ApiSection sample={apiSample()} />
        <SecuritySection />
        <CtaBand />
      </main>
      <LandingFooter />
    </div>
  );
}
