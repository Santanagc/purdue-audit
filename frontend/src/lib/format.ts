import type { AiProvider, FindingSeverity, InferredRole, RiskLevel, VulnSeverity } from "@/lib/types";

export interface SeverityStyle {
  label: string;
  /** Classe de fundo do marcador (quadrado/barra) de status. */
  dot: string;
  /** Classe de texto de status — use apenas em ícones; rótulos ficam em texto neutro. */
  text: string;
  rank: number;
}

/** Cores de status reservadas (crítico/alto/médio/baixo) — sempre acompanhadas de rótulo textual. */
export const VULN_SEVERITY_STYLES: Record<VulnSeverity, SeverityStyle> = {
  CRÍTICO: { label: "Crítico", dot: "bg-status-critical", text: "text-status-critical", rank: 0 },
  ALTO: { label: "Alto", dot: "bg-status-high", text: "text-status-high", rank: 1 },
  MÉDIO: { label: "Médio", dot: "bg-status-medium", text: "text-status-medium", rank: 2 },
  BAIXO: { label: "Baixo", dot: "bg-status-low", text: "text-status-low", rank: 3 },
};

const FINDING_TO_VULN: Record<Exclude<FindingSeverity, "INFO">, VulnSeverity> = {
  CRITICAL: "CRÍTICO",
  HIGH: "ALTO",
  MEDIUM: "MÉDIO",
  LOW: "BAIXO",
};

const INFO_STYLE: SeverityStyle = { label: "Info", dot: "bg-status-info", text: "text-status-info", rank: 4 };

export function findingSeverityStyle(severity: FindingSeverity): SeverityStyle {
  return severity === "INFO" ? INFO_STYLE : VULN_SEVERITY_STYLES[FINDING_TO_VULN[severity]];
}

export function riskStyle(level: RiskLevel): SeverityStyle {
  return VULN_SEVERITY_STYLES[level];
}

/** O medidor de score segue a mesma escala de status do nível de risco. */
export function scoreTone(score: number): SeverityStyle {
  if (score < 40) return VULN_SEVERITY_STYLES["CRÍTICO"];
  if (score < 60) return VULN_SEVERITY_STYLES.ALTO;
  if (score < 80) return VULN_SEVERITY_STYLES["MÉDIO"];
  return VULN_SEVERITY_STYLES.BAIXO;
}

export const ROLE_LABELS: Record<InferredRole, string> = {
  "PLC / Field Slave": "PLC / Field Slave",
  "HMI / SCADA Master": "HMI / SCADA Master",
  "Engineering Workstation / IT Host": "IT Host / Eng. Workstation",
  "External Host": "Host externo (Internet)",
  Unknown: "Não classificado",
};

export const PROVIDER_LABELS: Record<AiProvider, string> = {
  anthropic: "Claude (Anthropic)",
  openai: "OpenAI",
  mock: "Motor Especialista Local",
  "mock-fallback": "Motor Especialista Local (fallback)",
};

const dateTimeFormatter = new Intl.DateTimeFormat("pt-BR", {
  dateStyle: "short",
  timeStyle: "medium",
});

export function formatDateTime(iso: string | null | undefined): string {
  if (!iso) return "—";
  const date = new Date(iso);
  return Number.isNaN(date.getTime()) ? "—" : dateTimeFormatter.format(date);
}

const numberFormatter = new Intl.NumberFormat("pt-BR");

export function formatNumber(value: number): string {
  return numberFormatter.format(value);
}

export function formatDuration(seconds: number): string {
  if (seconds < 60) return `${seconds.toFixed(1)} s`;
  const minutes = Math.floor(seconds / 60);
  const rest = Math.round(seconds % 60);
  if (minutes < 60) return `${minutes} min ${rest} s`;
  return `${Math.floor(minutes / 60)} h ${minutes % 60} min`;
}

export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

export const MODBUS_FC_NAMES: Record<number, string> = {
  0x01: "Read Coils",
  0x02: "Read Discrete Inputs",
  0x03: "Read Holding Registers",
  0x04: "Read Input Registers",
  0x05: "Write Single Coil",
  0x06: "Write Single Register",
  0x08: "Diagnostics",
  0x0f: "Write Multiple Coils",
  0x10: "Write Multiple Registers",
  0x11: "Report Server ID",
  0x17: "Read/Write Multiple Registers",
  0x2b: "Read Device Identification",
};

export type FcClass = "read" | "write" | "diag" | "exception" | "other";

export function classifyFunctionCode(code: number): FcClass {
  if (code >= 0x80) return "exception";
  if ([0x01, 0x02, 0x03, 0x04].includes(code)) return "read";
  if ([0x05, 0x06, 0x0f, 0x10].includes(code)) return "write";
  if ([0x08, 0x11, 0x2b].includes(code)) return "diag";
  return "other";
}

export function functionCodeName(code: number): string {
  if (code >= 0x80) {
    const base = code - 0x80;
    return `Exceção de ${MODBUS_FC_NAMES[base] ?? `FC 0x${base.toString(16).toUpperCase().padStart(2, "0")}`}`;
  }
  return MODBUS_FC_NAMES[code] ?? "Função não padronizada";
}
