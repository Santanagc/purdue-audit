/**
 * Topologia da captura de demonstração organizada nos níveis do Modelo Purdue.
 * Linhas tracejadas animadas = conduítes violados detectados pelo motor; linha sólida = tráfego esperado.
 */

interface Band {
  label: string;
  top: number;
}

interface NodeSpec {
  id: string;
  x: number;
  y: number;
  ip: string;
  role: string;
  flagged: boolean;
}

type LinkTone = "ok" | "critical" | "high";

interface LinkSpec {
  d: string;
  tone: LinkTone;
  label: string;
  lx: number;
  ly: number;
  anchor?: "start" | "middle" | "end";
}

const BANDS: readonly Band[] = [
  { label: "INTERNET", top: 8 },
  { label: "NÍVEIS 3–4 · TI / ENGENHARIA", top: 98 },
  { label: "NÍVEL 2 · SUPERVISÃO", top: 198 },
  { label: "NÍVEL 1 · CONTROLE", top: 298 },
];
const BAND_HEIGHT = 88;
const NODE_W = 124;
const NODE_H = 40;

const NODES: readonly NodeSpec[] = [
  { id: "ext", x: 560, y: 52, ip: "203.0.113.77", role: "IP público", flagged: true },
  { id: "file", x: 170, y: 142, ip: "192.168.10.60", role: "Servidor SMB", flagged: true },
  { id: "ews", x: 360, y: 142, ip: "192.168.10.50", role: "Estação de engenharia", flagged: true },
  { id: "scada", x: 250, y: 242, ip: "192.168.10.5", role: "SCADA / HMI", flagged: false },
  { id: "rogue", x: 500, y: 242, ip: "192.168.10.99", role: "Mestre não autorizado", flagged: true },
  { id: "opc", x: 160, y: 342, ip: "192.168.10.20", role: "Servidor OPC UA", flagged: true },
  { id: "plc", x: 400, y: 342, ip: "192.168.10.10", role: "CLP Modbus", flagged: true },
];

const LINKS: readonly LinkSpec[] = [
  { d: "M250 262 L370 322", tone: "ok", label: "Modbus · leitura", lx: 296, ly: 300, anchor: "end" },
  { d: "M500 262 L432 322", tone: "critical", label: "escrita 0x06", lx: 478, ly: 302, anchor: "start" },
  { d: "M622 52 C 670 150, 662 300, 462 342", tone: "critical", label: "Internet → CLP", lx: 640, ly: 150, anchor: "end" },
  { d: "M372 162 L398 322", tone: "critical", label: "Telnet", lx: 392, ly: 238, anchor: "middle" },
  { d: "M298 142 L232 142", tone: "high", label: "SMB", lx: 265, ly: 132, anchor: "middle" },
  { d: "M232 262 L182 322", tone: "critical", label: "OPC UA #None", lx: 160, ly: 294, anchor: "middle" },
];

const LINK_STROKE: Record<LinkTone, string> = {
  ok: "stroke-fg-muted",
  critical: "stroke-status-critical",
  high: "stroke-status-high",
};

export function PurdueDiagram() {
  return (
    <div className="w-full">
      <svg
        viewBox="0 0 680 396"
        className="h-auto w-full"
        role="img"
        aria-labelledby="purdue-diagram-title purdue-diagram-desc"
      >
        <title id="purdue-diagram-title">Topologia da captura de demonstração no Modelo Purdue</title>
        <desc id="purdue-diagram-desc">
          Sete ativos distribuídos entre Internet, TI, supervisão e controle. Cinco conduítes violados: escrita Modbus
          por mestre não autorizado, CLP exposto à Internet, Telnet da estação de engenharia ao CLP, OPC UA sem
          criptografia e SMB na rede de controle.
        </desc>

        {BANDS.map((band, index) => (
          <g key={band.label}>
            <rect
              x={0}
              y={band.top}
              width={680}
              height={BAND_HEIGHT}
              rx={3}
              className={index % 2 === 0 ? "fill-band" : "fill-panel"}
            />
            <text x={12} y={band.top + 17} className="fill-fg-faint font-mono text-[9.5px] tracking-[0.08em]">
              {band.label}
            </text>
          </g>
        ))}

        {LINKS.map((link) => (
          <path
            key={link.label}
            d={link.d}
            fill="none"
            strokeWidth={link.tone === "ok" ? 2 : 1.75}
            strokeLinecap="round"
            strokeDasharray={link.tone === "ok" ? undefined : "6 6"}
            className={`${LINK_STROKE[link.tone]} ${link.tone === "ok" ? "" : "flow"}`}
          />
        ))}

        {NODES.map((node) => (
          <g key={node.id}>
            <rect
              x={node.x - NODE_W / 2}
              y={node.y - NODE_H / 2}
              width={NODE_W}
              height={NODE_H}
              rx={3}
              strokeWidth={1}
              className={`fill-panel ${node.flagged ? "stroke-status-critical/70" : "stroke-line-strong"}`}
            />
            {node.flagged && (
              <rect x={node.x - NODE_W / 2 + 9} y={node.y - 9} width={6} height={6} rx={3} className="fill-status-critical" />
            )}
            <text
              x={node.x - NODE_W / 2 + (node.flagged ? 21 : 10)}
              y={node.y - 2}
              className="fill-fg font-mono text-[11px]"
            >
              {node.ip}
            </text>
            <text x={node.x - NODE_W / 2 + 10} y={node.y + 12} className="fill-fg-muted text-[10px]">
              {node.role}
            </text>
          </g>
        ))}

        {LINKS.map((link) => (
          <text
            key={`${link.label}-label`}
            x={link.lx}
            y={link.ly}
            textAnchor={link.anchor ?? "middle"}
            paintOrder="stroke"
            strokeWidth={4}
            strokeLinejoin="round"
            className="fill-fg-muted stroke-panel text-[10.5px] font-medium"
          >
            {link.label}
          </text>
        ))}
      </svg>

      <p className="mt-4 flex flex-wrap gap-x-6 gap-y-1.5 text-[14px] text-fg-muted">
        <span className="flex items-center gap-2">
          <span className="h-[2px] w-5 bg-fg-muted" aria-hidden />
          Tráfego esperado
        </span>
        <span className="flex items-center gap-2">
          <span className="h-0 w-5 border-t-2 border-dashed border-status-critical" aria-hidden />
          Conduíte violado (crítico)
        </span>
        <span className="flex items-center gap-2">
          <span className="h-0 w-5 border-t-2 border-dashed border-status-high" aria-hidden />
          Conduíte violado (alto)
        </span>
      </p>
    </div>
  );
}
