import type { AuditResponse, HealthResponse } from "@/lib/types";

/**
 * Em produção sem NEXT_PUBLIC_API_URL (publicação só da vitrine), nenhuma requisição sai do navegador:
 * evita que o site chame http://localhost:8000 na máquina do visitante. Em desenvolvimento, usa a API local.
 */
export const API_URL: string = (
  process.env.NEXT_PUBLIC_API_URL ?? (process.env.NODE_ENV === "production" ? "" : "http://localhost:8000")
).replace(/\/+$/, "");

/** Há servidor de análise configurado? Se não, a ferramenta funciona só com o laudo de demonstração embutido. */
export const API_ENABLED: boolean = API_URL !== "";

export const DEFAULT_MAX_UPLOAD_MB = 10;
export const ACCEPTED_EXTENSIONS: readonly string[] = [".pcap", ".pcapng", ".cap"];

export class ApiError extends Error {
  readonly status: number;

  constructor(message: string, status: number) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

async function extractDetail(response: Response): Promise<string> {
  try {
    const body: unknown = await response.json();
    if (isRecord(body)) {
      const detail = body["detail"];
      if (typeof detail === "string") return detail;
      if (Array.isArray(detail) && detail.length > 0 && isRecord(detail[0]) && typeof detail[0]["msg"] === "string") {
        return detail[0]["msg"];
      }
    }
  } catch {
    return `Erro HTTP ${response.status}`;
  }
  return `Erro HTTP ${response.status}`;
}

async function request<T>(path: string, init: RequestInit): Promise<T> {
  if (!API_ENABLED) {
    throw new ApiError(
      "Esta publicação mostra apenas o laudo de demonstração: o servidor de análise não está configurado.",
      0,
    );
  }
  let response: Response;
  try {
    response = await fetch(`${API_URL}${path}`, { ...init, credentials: "omit", cache: "no-store" });
  } catch (error: unknown) {
    if (error instanceof DOMException && error.name === "AbortError") throw error;
    throw new ApiError(
      "Não foi possível conectar ao servidor de análise. Na hospedagem gratuita ele hiberna após inatividade e leva " +
        "cerca de 1 minuto para acordar — tente novamente em instantes.",
      0,
    );
  }
  if (!response.ok) {
    throw new ApiError(await extractDetail(response), response.status);
  }
  return (await response.json()) as T;
}

export function runDemoAudit(signal?: AbortSignal): Promise<AuditResponse> {
  return request<AuditResponse>("/api/v1/audit/demo", { method: "POST", signal });
}

export function uploadAudit(file: File, signal?: AbortSignal): Promise<AuditResponse> {
  const form = new FormData();
  form.append("file", file, file.name);
  return request<AuditResponse>("/api/v1/audit/upload", { method: "POST", body: form, signal });
}

/**
 * Laudo da captura de demonstração pré-gerado pelo mesmo motor (`python -m app.utils.export_demo_report`).
 * Garante que a demo funcione mesmo com o backend hibernando na hospedagem gratuita.
 */
export async function loadDemoSnapshot(signal?: AbortSignal): Promise<AuditResponse> {
  const response = await fetch("/demo-report.json", { signal, cache: "force-cache" });
  if (!response.ok) throw new ApiError("Laudo de demonstração indisponível.", response.status);
  return (await response.json()) as AuditResponse;
}

export function getHealth(signal?: AbortSignal): Promise<HealthResponse> {
  return request<HealthResponse>("/api/v1/health", { method: "GET", signal });
}

export function validateCaptureFile(file: File, maxMb: number): string | null {
  const lower = file.name.toLowerCase();
  if (!ACCEPTED_EXTENSIONS.some((ext) => lower.endsWith(ext))) {
    return "Formato não suportado. Envie um arquivo .pcap, .pcapng ou .cap.";
  }
  if (file.size === 0) {
    return "O arquivo está vazio.";
  }
  if (file.size > maxMb * 1024 * 1024) {
    return `O arquivo excede o limite de ${maxMb} MB .`;
  }
  return null;
}
