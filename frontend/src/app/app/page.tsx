"use client";

import { useCallback, useEffect, useRef, useState } from "react";

import { AboutModal } from "@/components/AboutModal";
import { Dashboard } from "@/components/dashboard/Dashboard";
import { Landing } from "@/components/Landing";
import { SiteHeader } from "@/components/SiteHeader";
import { StatusBar } from "@/components/StatusBar";
import { ApiError, DEFAULT_MAX_UPLOAD_MB, getHealth, loadDemoSnapshot, runDemoAudit, uploadAudit } from "@/lib/api";
import type { AuditResponse, HealthResponse } from "@/lib/types";
import type { AuditMode, ViewState } from "@/lib/view";

/** Tempo mínimo do painel de progresso para que as etapas da análise fiquem legíveis. */
const MIN_PROGRESS_MS = 3600;

function wait(ms: number, signal: AbortSignal): Promise<void> {
  return new Promise((resolve) => {
    const timer = window.setTimeout(resolve, ms);
    signal.addEventListener("abort", () => {
      window.clearTimeout(timer);
      resolve();
    });
  });
}

export default function HomePage() {
  const [view, setView] = useState<ViewState>({ kind: "idle" });
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [healthError, setHealthError] = useState(false);
  const [aboutOpen, setAboutOpen] = useState(false);
  const controllerRef = useRef<AbortController | null>(null);

  useEffect(() => () => controllerRef.current?.abort(), []);

  // Link direto para o laudo de demonstração (ex.: https://.../app?demo), útil para compartilhar o resultado.
  useEffect(() => {
    if (!new URLSearchParams(window.location.search).has("demo")) return;
    const controller = new AbortController();
    loadDemoSnapshot(controller.signal)
      .then((result) => setView({ kind: "done", result, snapshot: true }))
      .catch(() => {
        if (!controller.signal.aborted) setView({ kind: "error", message: "Laudo de demonstração indisponível." });
      });
    return () => controller.abort();
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    getHealth(controller.signal)
      .then((value) => {
        setHealth(value);
        setHealthError(false);
      })
      .catch(() => {
        if (!controller.signal.aborted) setHealthError(true);
      });
    return () => controller.abort();
  }, []);

  const runAudit = useCallback(
    async (mode: AuditMode, file?: File) => {
      controllerRef.current?.abort();
      const controller = new AbortController();
      controllerRef.current = controller;
      setView({ kind: "loading", mode, fileName: file?.name ?? "sample_ot_capture.pcap" });

      try {
        let request: Promise<{ result: AuditResponse; snapshot: boolean }>;
        if (mode === "upload" && file) {
          request = uploadAudit(file, controller.signal).then((result) => ({ result, snapshot: false }));
        } else if (health) {
          // Backend no ar: análise ao vivo; se falhar no meio do caminho, usa o laudo pré-gerado.
          request = runDemoAudit(controller.signal)
            .then((result) => ({ result, snapshot: false }))
            .catch(async (error: unknown) => {
              if (controller.signal.aborted) throw error;
              return { result: await loadDemoSnapshot(controller.signal), snapshot: true };
            });
        } else {
          request = loadDemoSnapshot(controller.signal).then((result) => ({ result, snapshot: true }));
        }
        const [outcome] = await Promise.all([request, wait(MIN_PROGRESS_MS, controller.signal)]);
        if (controller.signal.aborted) return;
        setView({ kind: "done", result: outcome.result, snapshot: outcome.snapshot });
        window.scrollTo({ top: 0, behavior: "smooth" });
      } catch (error: unknown) {
        if (controller.signal.aborted) return;
        const message =
          error instanceof ApiError ? error.message : "Falha inesperada ao processar a auditoria. Tente novamente em instantes.";
        setView({ kind: "error", message });
      }
    },
    [health],
  );

  const cancel = useCallback(() => {
    controllerRef.current?.abort();
    setView({ kind: "idle" });
  }, []);

  const reset = useCallback(() => {
    controllerRef.current?.abort();
    setView({ kind: "idle" });
    // Remove ?demo e âncoras: recarregar a página deve manter a tela de nova auditoria.
    window.history.replaceState(null, "", window.location.pathname);
    window.scrollTo({ top: 0, behavior: "smooth" });
  }, []);

  const context =
    view.kind === "done"
      ? `Laudo · ${view.result.file_name}`
      : view.kind === "loading"
        ? "Análise em andamento"
        : "Nova auditoria";

  return (
    <div className="flex min-h-screen flex-col">
      <SiteHeader onHome={reset} onAbout={() => setAboutOpen(true)} context={context} />
      {view.kind === "done" ? (
        <Dashboard result={view.result} snapshot={view.snapshot} onNewAudit={reset} />
      ) : (
        <Landing
          view={view}
          maxUploadMb={health?.max_upload_mb ?? DEFAULT_MAX_UPLOAD_MB}
          backendOnline={health !== null}
          onDemo={() => void runAudit("demo")}
          onUpload={(file) => void runAudit("upload", file)}
          onCancel={cancel}
          onDismissError={() => setView({ kind: "idle" })}
        />
      )}
      <StatusBar health={health} healthError={healthError} />
      <AboutModal open={aboutOpen} onClose={() => setAboutOpen(false)} />
    </div>
  );
}
