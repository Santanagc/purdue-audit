import type { AuditResponse } from "@/lib/types";

export type AuditMode = "demo" | "upload";

export type ViewState =
  | { kind: "idle" }
  | { kind: "loading"; mode: AuditMode; fileName: string }
  | { kind: "error"; message: string }
  | { kind: "done"; result: AuditResponse; snapshot: boolean };
