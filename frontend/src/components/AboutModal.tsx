"use client";

import { Modal } from "@/components/Modal";
import { AUTHOR_NAME, LINKEDIN_URL, REPO_URL } from "@/lib/site";

interface AboutModalProps {
  open: boolean;
  onClose: () => void;
}

const HIGHLIGHTS: ReadonlyArray<{ title: string; text: string }> = [
  {
    title: "Protocolos industriais byte a byte",
    text: "Dissecação do cabeçalho MBAP do Modbus TCP (vários ADUs por segmento, Function Codes, exceções) e do OpenSecureChannel do OPC UA para extrair a SecurityPolicyUri.",
  },
  {
    title: "ISA/IEC 62443 e Modelo Purdue",
    text: "Regras determinísticas mapeadas a requisitos SR da IEC 62443-3-3: escrita por múltiplos mestres, enumeração, protocolos de TI no nível de controle e exposição à Internet.",
  },
  {
    title: "IA com saída estruturada",
    text: "Resumo estatístico de no máximo 4 KB enviado ao LLM (Claude ou OpenAI) com resposta validada por schema Pydantic e fallback para um motor especialista local.",
  },
  {
    title: "Segurança da própria aplicação",
    text: "Processamento stateless (PCAP apagado no mesmo request), validação de assinatura do arquivo, rate limit por IP resistente a X-Forwarded-For forjado, CSP e container não-root.",
  },
  {
    title: "Qualidade",
    text: "TypeScript estrito, type hints em 100% do Python, testes automatizados com PCAP sintético e CI com build da imagem Docker.",
  },
];

const STACK: ReadonlyArray<[string, string]> = [
  ["Motor de análise", "Python 3.12 · Scapy (sem tshark) · Pydantic v2"],
  ["API", "FastAPI · Uvicorn · Docker multi-stage"],
  ["Laudo", "Claude (Anthropic) / OpenAI com Structured Outputs · motor local"],
  ["Interface", "Next.js 15 · React 19 · TypeScript · Tailwind CSS"],
  ["Qualidade", "pytest · GitHub Actions · hadolint"],
];

export function AboutModal({ open, onClose }: AboutModalProps) {
  return (
    <Modal
      open={open}
      onClose={onClose}
      size="xl"
      title="Sobre o projeto"
      description="Projeto de portfólio: auditoria passiva de redes industriais (OT/ICS) a partir de capturas de tráfego, com laudo alinhado à ISA/IEC 62443-3-3."
    >
      <div className="grid gap-5 md:grid-cols-[minmax(0,1fr)_280px]">
        <div>
          <h3 className="label">O que este projeto demonstra</h3>
          <ul className="mt-2 divide-y divide-line rounded border border-line">
            {HIGHLIGHTS.map((item) => (
              <li key={item.title} className="px-3 py-2.5">
                <p className="text-[13px] font-medium text-fg">{item.title}</p>
                <p className="mt-0.5 text-[12px] leading-relaxed text-fg-muted">{item.text}</p>
              </li>
            ))}
          </ul>
        </div>

        <div className="space-y-5">
          <div>
            <h3 className="label">Stack</h3>
            <dl className="mt-2 space-y-2">
              {STACK.map(([label, value]) => (
                <div key={label}>
                  <dt className="text-[12px] text-fg-faint">{label}</dt>
                  <dd className="text-[13px] text-fg">{value}</dd>
                </div>
              ))}
            </dl>
          </div>

          <div>
            <h3 className="label">Como usar</h3>
            <p className="mt-2 text-[13px] leading-relaxed text-fg-muted">
              Rode a demo com a captura sintética (SCADA, CLP, mestre não autorizado, OPC UA sem criptografia) ou envie
              um .pcap próprio. O arquivo é apagado ao fim da análise.
            </p>
          </div>

          {(AUTHOR_NAME || LINKEDIN_URL || REPO_URL) && (
            <div>
              <h3 className="label">Autor</h3>
              {AUTHOR_NAME && <p className="mt-2 text-[13px] text-fg">{AUTHOR_NAME}</p>}
              <div className="mt-2 flex flex-wrap gap-2">
                {LINKEDIN_URL && (
                  <a href={LINKEDIN_URL} target="_blank" rel="noopener noreferrer" className="btn-secondary">
                    LinkedIn
                  </a>
                )}
                {REPO_URL && (
                  <a href={REPO_URL} target="_blank" rel="noopener noreferrer" className="btn-secondary">
                    Código-fonte
                  </a>
                )}
              </div>
            </div>
          )}
        </div>
      </div>

      <p className="mt-5 border-t border-line pt-3 text-[12px] text-fg-faint">
        Ferramenta estritamente passiva e defensiva: nunca se conecta a redes ou CLPs reais, apenas lê capturas enviadas.
      </p>
    </Modal>
  );
}
