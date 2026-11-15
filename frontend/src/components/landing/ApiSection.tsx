"use client";

import { ChevronRight } from "lucide-react";
import { useId, useState, type ReactNode } from "react";

import { SectionHead } from "@/components/landing/Sheet";
import { REPO_URL } from "@/lib/site";

export interface ApiSample {
  score: number;
  riskLevel: string;
  provider: string;
  payloadBytes: number;
  ruleId: string;
  severity: string;
  title: string;
}

type Tab = "curl" | "python";

const TABS: ReadonlyArray<[Tab, string]> = [
  ["curl", "cURL"],
  ["python", "Python"],
];

/* Realce de sintaxe sobre o verde-petróleo: tons areia e âmbar só para números. */
const K = ({ children }: { children: ReactNode }) => <span className="font-medium text-inverse-fg">{children}</span>;
const S = ({ children }: { children: ReactNode }) => <span className="text-[#d9e4cf]">{children}</span>;
const N = ({ children }: { children: ReactNode }) => <span className="text-[#f2c879]">{children}</span>;
const C = ({ children }: { children: ReactNode }) => <span className="text-[#8fa8a4]">{children}</span>;

function CurlSample() {
  return (
    <>
      <C># Envia a captura; o arquivo é apagado ao fim da análise</C>
      {"\n"}
      <K>curl</K> -X POST <S>&quot;$OT_SHIELD_API/api/v1/audit/upload&quot;</S> \{"\n"}
      {"  "}-F <S>&quot;file=@planta.pcap&quot;</S>
    </>
  );
}

function PythonSample() {
  return (
    <>
      <K>import</K> httpx{"\n\n"}
      API = <S>&quot;http://localhost:8000&quot;</S>{"\n\n"}
      <K>with</K> open(<S>&quot;planta.pcap&quot;</S>, <S>&quot;rb&quot;</S>) <K>as</K> captura:{"\n"}
      {"    "}laudo = httpx.post({"\n"}
      {"        "}<S>f&quot;{"{"}API{"}"}/api/v1/audit/upload&quot;</S>,{"\n"}
      {"        "}files={"{"}<S>&quot;file&quot;</S>: captura{"}"},{"\n"}
      {"        "}timeout=<N>120</N>,{"\n"}
      {"    "}).json(){"\n\n"}
      print(laudo[<S>&quot;report&quot;</S>][<S>&quot;overall_security_score&quot;</S>])
    </>
  );
}

function ResponseSample({ sample }: { sample: ApiSample }) {
  return (
    <>
      {"{"}
      {"\n  "}
      <S>&quot;ai_provider&quot;</S>: <S>&quot;{sample.provider}&quot;</S>,{"\n  "}
      <S>&quot;llm_payload_bytes&quot;</S>: <N>{sample.payloadBytes}</N>,{"\n  "}
      <S>&quot;report&quot;</S>: {"{"}
      {"\n    "}
      <S>&quot;overall_security_score&quot;</S>: <N>{sample.score}</N>,{"\n    "}
      <S>&quot;risk_level&quot;</S>: <S>&quot;{sample.riskLevel}&quot;</S>, <C>…</C>
      {"\n  },\n  "}
      <S>&quot;network_summary&quot;</S>: {"{"}
      {"\n    "}
      <S>&quot;deterministic_findings&quot;</S>: [{"{"}
      {"\n      "}
      <S>&quot;rule_id&quot;</S>: <S>&quot;{sample.ruleId}&quot;</S>,{"\n      "}
      <S>&quot;severity&quot;</S>: <S>&quot;{sample.severity}&quot;</S>,{"\n      "}
      <S>&quot;title&quot;</S>: <S>&quot;{sample.title}&quot;</S>
      {"\n    }"}, <C>…</C>]{"\n  }\n}"}
    </>
  );
}

const BULLETS: readonly string[] = [
  "Contratos Pydantic compartilhados entre o motor, o LLM e o frontend TypeScript",
  "Erros previsíveis: 400 extensão/assinatura, 413 tamanho, 422 captura corrompida, 429 rate limit",
  "O LLM responde em saída estruturada validada por schema, com fallback local determinístico",
];

export function ApiSection({ sample }: { sample: ApiSample }) {
  const [tab, setTab] = useState<Tab>("curl");
  const baseId = useId();

  return (
    <section id="api" className="scroll-mt-20 border-y border-line bg-band" aria-labelledby="api-title">
      <div className="frame section">
      <SectionHead kicker="API" title="Uma rota, um laudo tipado." titleId="api-title" />
      <div className="mt-14 grid grid-cols-[minmax(0,1fr)] gap-12 lg:grid-cols-12 lg:items-start">
        <div className="lg:col-span-5">
          <p className="lede">
            <code className="num text-[16px] text-fg">POST /api/v1/audit/upload</code> com multipart/form-data. A resposta
            segue o schema AuditResponse.
          </p>
          <ol className="mt-8 border-t border-line">
            {BULLETS.map((bullet, index) => (
              <li key={bullet} className="flex gap-4 border-b border-line py-4 text-[15px] leading-relaxed text-fg-muted">
                <span className="font-display text-[18px] font-semibold leading-tight text-fg-faint">{index + 1}</span>
                {bullet}
              </li>
            ))}
          </ol>
          {REPO_URL && (
            <a href={REPO_URL} target="_blank" rel="noopener noreferrer" className="link-arrow mt-8">
              Ver documentação no repositório
              <ChevronRight className="h-4 w-4" aria-hidden />
            </a>
          )}
        </div>

        <div className="min-w-0 overflow-hidden rounded-lg bg-inverse text-inverse-fg lg:col-span-7">
          <div className="flex items-center justify-between border-b border-inverse-line bg-inverse-raised pr-3">
            <div role="tablist" aria-label="Exemplo de requisição" className="flex">
              {TABS.map(([id, label]) => (
                <button
                  key={id}
                  type="button"
                  role="tab"
                  id={`${baseId}-${id}-tab`}
                  aria-selected={tab === id}
                  aria-controls={`${baseId}-${id}-panel`}
                  onClick={() => setTab(id)}
                  className={`min-h-[44px] border-b-2 px-4 font-mono text-[13px] transition-colors duration-150 ${
                    tab === id ? "border-inverse-fg text-inverse-fg" : "border-transparent text-inverse-muted hover:text-inverse-fg"
                  }`}
                >
                  {label}
                </button>
              ))}
            </div>
            <span className="hidden font-mono text-[12px] text-inverse-muted sm:inline">POST /api/v1/audit/upload</span>
          </div>
          <pre
            role="tabpanel"
            id={`${baseId}-${tab}-panel`}
            aria-labelledby={`${baseId}-${tab}-tab`}
            className="overflow-x-auto p-5 font-mono text-[13px] leading-relaxed text-inverse-fg"
          >
            <code>{tab === "curl" ? <CurlSample /> : <PythonSample />}</code>
          </pre>
          <div className="border-t border-inverse-line">
            <p className="flex items-center gap-2 bg-inverse-raised px-5 py-2 font-mono text-[12px] text-inverse-muted">
              <span className="dot bg-status-low" aria-hidden />
              200 OK · resposta da captura de demonstração
            </p>
            <pre className="overflow-x-auto p-5 font-mono text-[13px] leading-relaxed text-inverse-fg">
              <code>
                <ResponseSample sample={sample} />
              </code>
            </pre>
          </div>
        </div>
      </div>
      </div>
    </section>
  );
}
