---
name: design-system-purdue-audit
description: Aplica o Purdue Audit Design System (areia + verde-petróleo, Inter Tight, Inter, IBM Plex Mono, cor só para severidade) ao criar ou alterar qualquer interface do Purdue Audit. Use ao escrever componentes, páginas, estilos ou revisar UI deste repositório.
license: MIT
---

# Purdue Audit Design System

## Mission
Interfaces que parecem um laudo técnico que um engenheiro assinaria: sóbrias, legíveis e baseadas em dados reais.
Fonte de verdade completa: `DESIGN.md` na raiz do repositório.

## Brand
- Produto: Purdue Audit — auditoria passiva de redes OT/ICS, laudo ISA/IEC 62443-3-3.
- Público: engenharia de automação, segurança OT, recrutadores técnicos.
- Superfícies: página de apresentação, ferramenta `/app`, laudo impresso A4.

## Style Foundations
- Visual: base TypeUI Enterprise — superfícies areia, verde-petróleo primário, títulos em Inter Tight (sem serifa, compacta), sem sombras.
- Tipografia: display = Inter Tight 700 (tracking −0,02em), h2/h3 = Inter Tight 600 (−0,01em), entrelinha 1; corpo = Inter 16 px/1,5; dados = IBM Plex Mono + `tabular-nums`.
- Escala: 12/14/16/20/24/32/40/64.
- Cores (tokens Tailwind): `canvas`, `band`, `panel`, `raised`, `line`, `line-strong`, `fg`, `fg-muted`, `fg-faint`,
  `accent` (#072c2c), `inverse-*`, `status-critical|high|medium|low|info`.
- Espaço: grade de 8 px; `.frame` 1200 px; `.section` 80/112 px.
- Raio: 4 px (controles), 6 px (blocos internos), 8 px (cartões); `rounded-full` só em `.dot` e medidores.
- Movimento: `transition-colors duration-150`; nenhuma outra animação além de `.flow`.

## Accessibility
WCAG 2.2 AA; contraste ≥ 4,5:1; foco 2 px `status-info`; alvos ≥ 44 px; severidade sempre com rótulo textual;
`prefers-reduced-motion` respeitado; sem rolagem horizontal da página a 390 px.

## Writing Tone
Técnico, conciso, verificável. Números reais com unidade. Sem jargão de marketing.

## Rules: Do
- must: usar as classes do sistema (`.display`, `.h-section`, `.lede`, `.eyebrow`, `.label`, `.num`, `.tag`, `.dot`, `.btn-*`, `.panel`, `.data-table`).
- must: abrir seções com `SectionHead` e alternar `canvas` ↔ `band`.
- must: 32 px entre título de exibição e o próximo elemento.
- should: acompanhar diagramas e laudos com `TitleBlock`.

## Rules: Don't
- must not: gradientes, sombras, glassmorphism, roxo/indigo, segunda cor de marca.
- must not: cor de severidade fora de alarme; ícones decorativos em caixas; três cartões idênticos.
- must not: texto de apoio < 14 px (exceto dados monoespaçados densos); `hover:scale`/`translate`.

## QA Checklist
- [ ] Tokens do sistema, sem hex soltos.
- [ ] Dados em `.num`; severidade = `.dot` + rótulo.
- [ ] Botões 44 px com foco visível.
- [ ] 390 px sem rolagem horizontal; PDF A4 sem tabelas cortadas.
- [ ] `npx tsc --noEmit` e `npm run build` limpos.
