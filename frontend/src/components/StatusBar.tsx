import type { HealthResponse } from "@/lib/types";

const ENGINE_LABELS: Record<HealthResponse["ai_provider"], string> = {
  anthropic: "Claude (Anthropic)",
  openai: "OpenAI",
  mock: "Motor especialista local",
};

interface StatusBarProps {
  health: HealthResponse | null;
  healthError: boolean;
}

function Item({ label, value }: { label: string; value: string }) {
  return (
    <span className="flex items-center gap-1.5 whitespace-nowrap">
      <span className="text-fg-faint">{label}</span>
      <span className="text-fg-muted">{value}</span>
    </span>
  );
}

export function StatusBar({ health, healthError }: StatusBarProps) {
  const state = healthError ? "hibernando · demo com laudo pré-gerado" : health ? "online" : "verificando";
  const dot = healthError ? "bg-status-medium" : health ? "bg-status-low" : "bg-fg-faint";

  return (
    <footer className="no-print sticky bottom-0 z-30 border-t border-line bg-panel">
      <div className="flex h-7 items-center gap-5 overflow-x-auto px-4 font-mono [scrollbar-width:none] text-[11px]">
        <span className="flex items-center gap-1.5 whitespace-nowrap">
          <span className={`dot ${dot}`} aria-hidden />
          <span className="text-fg-muted">API {state}</span>
        </span>
        {health && (
          <>
            <Item label="laudo" value={ENGINE_LABELS[health.ai_provider]} />
            <Item label="upload" value={`até ${health.max_upload_mb} MB`} />
          </>
        )}
        <Item label="retenção de PCAP" value="0 bytes" />
        <span className="ml-auto hidden whitespace-nowrap text-fg-faint sm:inline">
          ISA/IEC 62443-3-3{health ? ` · v${health.version}` : ""}
        </span>
      </div>
    </footer>
  );
}
