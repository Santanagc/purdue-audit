import raw from "../../public/demo-report.json";

import type { AuditResponse } from "@/lib/types";

/** Laudo da captura de demonstração (mesmo arquivo servido em /demo-report.json), usado nas vitrines da landing. */
export const DEMO_REPORT: AuditResponse = raw as unknown as AuditResponse;
