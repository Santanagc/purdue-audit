"use client";

import { FileText, Lock, Play, TriangleAlert, Upload, X } from "lucide-react";
import { useCallback, useId, useRef, useState, type DragEvent, type KeyboardEvent } from "react";

import { PanelHeader } from "@/components/ui";
import { ACCEPTED_EXTENSIONS, API_ENABLED, validateCaptureFile } from "@/lib/api";
import { formatBytes } from "@/lib/format";

interface UploadPanelProps {
  disabled: boolean;
  backendOnline: boolean;
  maxUploadMb: number;
  error: string | null;
  onDemo: () => void;
  onUpload: (file: File) => void;
  onDismissError: () => void;
}

export function UploadPanel({ disabled, backendOnline, maxUploadMb, error, onDemo, onUpload, onDismissError }: UploadPanelProps) {
  const inputId = useId();
  const inputRef = useRef<HTMLInputElement>(null);
  const [dragging, setDragging] = useState(false);
  const [file, setFile] = useState<File | null>(null);
  const [localError, setLocalError] = useState<string | null>(null);

  const selectFile = useCallback(
    (candidate: File | undefined) => {
      if (!candidate) return;
      const problem = validateCaptureFile(candidate, maxUploadMb);
      setLocalError(problem);
      setFile(problem ? null : candidate);
    },
    [maxUploadMb],
  );

  const onDrop = (event: DragEvent<HTMLDivElement>) => {
    event.preventDefault();
    setDragging(false);
    if (!disabled) selectFile(event.dataTransfer.files[0]);
  };

  const onKeyDown = (event: KeyboardEvent<HTMLDivElement>) => {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      inputRef.current?.click();
    }
  };

  const shownError = localError ?? error;

  return (
    <section className="panel" aria-labelledby="upload-title">
      <PanelHeader
        id="upload-title"
        title="Captura de rede"
        meta={<span className="font-mono">{ACCEPTED_EXTENSIONS.join(" ")} · até {maxUploadMb} MB</span>}
      />

      <div className="p-4">
        <input
          ref={inputRef}
          id={inputId}
          type="file"
          accept={ACCEPTED_EXTENSIONS.join(",")}
          className="sr-only"
          disabled={disabled}
          tabIndex={-1}
          aria-label="Arquivo de captura PCAP"
          onChange={(event) => {
            selectFile(event.target.files?.[0]);
            event.target.value = "";
          }}
        />
        <div
          role="button"
          tabIndex={disabled ? -1 : 0}
          aria-disabled={disabled}
          aria-label="Selecionar arquivo de captura PCAP"
          onKeyDown={onKeyDown}
          onClick={() => !disabled && inputRef.current?.click()}
          onDragOver={(event) => {
            event.preventDefault();
            if (!disabled) setDragging(true);
          }}
          onDragLeave={() => setDragging(false)}
          onDrop={onDrop}
          className={`grid cursor-pointer place-items-center rounded border border-dashed px-6 py-12 text-center transition-colors ${
            dragging ? "border-accent bg-accent/[0.06]" : "border-line-strong hover:border-fg-faint hover:bg-raised/40"
          }`}
        >
          <Upload className="mb-3 h-5 w-5 text-fg-muted" aria-hidden />
          <p className="text-[14px] font-medium text-fg">Arraste o arquivo de captura aqui</p>
          <p className="mt-1 text-[12px] text-fg-faint">ou clique para selecionar</p>
        </div>

        {file && (
          <div className="mt-3 flex items-center justify-between gap-3 rounded border border-line bg-raised/50 px-3 py-2">
            <div className="flex min-w-0 items-center gap-2.5">
              <FileText className="h-4 w-4 shrink-0 text-fg-muted" aria-hidden />
              <p className="truncate font-mono text-[13px] text-fg">{file.name}</p>
              <span className="shrink-0 text-[12px] text-fg-faint">{formatBytes(file.size)}</span>
            </div>
            <div className="flex shrink-0 items-center gap-2">
              <button type="button" onClick={() => setFile(null)} className="btn-icon" aria-label="Remover arquivo">
                <X className="h-4 w-4" aria-hidden />
              </button>
              <button type="button" disabled={disabled} onClick={() => onUpload(file)} className="btn-primary">
                Auditar
              </button>
            </div>
          </div>
        )}

        {!API_ENABLED && !shownError && (
          <p className="mt-3 flex items-start gap-2 text-[12px] leading-relaxed text-fg-faint">
            <span className="dot mt-1 bg-status-info" aria-hidden />
            Esta publicação não tem servidor de análise: o envio de capturas próprias funciona ao rodar o projeto localmente
            ou com o backend publicado. A demo funciona normalmente.
          </p>
        )}
        {API_ENABLED && !backendOnline && !shownError && (
          <p className="mt-3 flex items-start gap-2 text-[12px] leading-relaxed text-fg-faint">
            <span className="dot mt-1 bg-status-medium" aria-hidden />O servidor de análise roda em hospedagem gratuita
            e pode estar hibernando: o primeiro upload pode levar cerca de 1 minuto. A demo funciona imediatamente.
          </p>
        )}

        {shownError && (
          <div
            role="alert"
            className="mt-3 flex items-start gap-2.5 rounded border border-status-critical/50 bg-status-critical/[0.08] px-3 py-2.5 text-[13px] text-fg"
          >
            <TriangleAlert className="mt-0.5 h-4 w-4 shrink-0 text-status-critical" aria-hidden />
            <p className="flex-1">{shownError}</p>
            <button
              type="button"
              onClick={() => {
                setLocalError(null);
                onDismissError();
              }}
              className="text-fg-muted transition-colors hover:text-fg"
              aria-label="Fechar alerta"
            >
              <X className="h-4 w-4" aria-hidden />
            </button>
          </div>
        )}
      </div>

      <div className="flex flex-col gap-3 border-t border-line px-4 py-3 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <p className="text-[13px] font-medium text-fg">Sem captura em mãos?</p>
          <p className="mt-0.5 text-[12px] text-fg-muted">
            Rode a demo: SCADA, CLP Modbus, mestre não autorizado, OPC UA sem criptografia e vazamento SMB/Telnet.
          </p>
        </div>
        <button type="button" disabled={disabled} onClick={onDemo} className="btn-secondary shrink-0">
          <Play className="h-3.5 w-3.5" aria-hidden />
          Rodar demo
        </button>
      </div>

      <p className="flex items-center gap-1.5 border-t border-line px-4 py-2 text-[12px] text-fg-faint">
        <Lock className="h-3 w-3" aria-hidden />
        Arquivo gravado em um temporário isolado e apagado ao fim da análise.
      </p>
    </section>
  );
}
