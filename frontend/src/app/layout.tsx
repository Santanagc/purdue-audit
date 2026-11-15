import type { Metadata, Viewport } from "next";
import { IBM_Plex_Mono, Inter, Playfair_Display } from "next/font/google";
import type { ReactNode } from "react";

import "./globals.css";

const sans = Inter({ subsets: ["latin"], variable: "--font-sans", display: "swap" });
const display = Playfair_Display({
  subsets: ["latin"],
  weight: ["500", "600", "700"],
  variable: "--font-display",
  display: "swap",
});
const mono = IBM_Plex_Mono({ subsets: ["latin"], weight: ["400", "500"], variable: "--font-mono", display: "swap" });

export const metadata: Metadata = {
  title: "Purdue Audit — Auditoria Passiva de Redes Industriais (ISA/IEC 62443)",
  description:
    "Envie um PCAP da sua rede OT e receba um laudo de cibersegurança industrial alinhado à ISA/IEC 62443-3-3: Modbus TCP, OPC UA e segmentação do Modelo Purdue. Análise passiva e stateless.",
  keywords: ["IEC 62443", "OT Security", "Modbus", "OPC UA", "Modelo Purdue", "SCADA", "CLP", "PCAP"],
};

export const viewport: Viewport = {
  themeColor: "#edeade",
};

export default function RootLayout({ children }: Readonly<{ children: ReactNode }>) {
  return (
    <html lang="pt-BR" className={`${sans.variable} ${display.variable} ${mono.variable}`}>
      <body className="min-h-screen">
        {children}
      </body>
    </html>
  );
}
