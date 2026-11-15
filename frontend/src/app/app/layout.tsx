import type { Metadata } from "next";
import type { ReactNode } from "react";

export const metadata: Metadata = {
  title: "Ferramenta · Purdue Audit",
  description: "Envie uma captura .pcap/.pcapng e gere o laudo de auditoria passiva ISA/IEC 62443-3-3.",
};

export default function ToolLayout({ children }: Readonly<{ children: ReactNode }>) {
  return children;
}
