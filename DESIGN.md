---
name: Purdue Audit Design System
description: Sistema visual do Purdue Audit — superfícies areia, verde-petróleo como cor primária, títulos em Inter Tight e dados em monoespaçada, com cor de status reservada a severidade de segurança.
colors:
  canvas: "#edeade"
  band: "#f5f3ea"
  panel: "#fbfaf6"
  raised: "#e3e0d3"
  line: "#d3d0bf"
  line-strong: "#a8a492"
  fg: "#111827"
  fg-muted: "#4b5563"
  fg-faint: "#5e636e"
  primary: "#072c2c"
  primary-hover: "#0f3d3b"
  inverse-raised: "#0e3a39"
  inverse-line: "#22504e"
  inverse-fg: "#f5f3ea"
  inverse-muted: "#a8beba"
  critical: "#b42318"
  high: "#c4520e"
  medium: "#b58400"
  low: "#047857"
  info: "#0c5cab"
typography:
  display:
    fontFamily: "Inter Tight"
    fontWeight: 700
    fontSize: "40px → 56px → 64px"
    lineHeight: 1
    letterSpacing: "-0.02em"
  h2:
    fontFamily: "Inter Tight"
    fontWeight: 600
    fontSize: "32px → 40px"
    lineHeight: 1
    letterSpacing: "-0.01em"
  body:
    fontFamily: "Inter"
    fontSize: 16px
    lineHeight: 1.5
  data:
    fontFamily: "IBM Plex Mono"
    fontFeature: "tabular-nums"
  sourceScale: "12/14/16/20/24/32/40/64"
rounded:
  sm: 4px
  md: 6px
  lg: 8px
  full: 9999px
spacing:
  base: 8px
  sourceScale: "4/8/12/16/24/32/40/56/80/112"
---

# Purdue Audit Design System

Design system próprio do Purdue Audit, construído a partir de três fontes:

| Fonte | O que foi aproveitado |
|---|---|
| Estilo **Enterprise** do registro TypeUI (prévia em `bergside/typeui/registry-examples`) | Paleta areia + verde-petróleo (os títulos em serifa da prévia foram trocados por Inter Tight a pedido do autor), faixa de anúncio, navegação com marca centralizada, linha de métricas, faixas alternadas |
| **Fundamentos TypeUI** (`skills/fundamentals`) | Entrelinha 1 e 32 px abaixo em títulos de exibição; corpo ≥ 16 px; texto de apoio ≥ 14 px; alvos de toque ≥ 44 px; WCAG 2.2 AA; `h4` em títulos de lista |
| **Domínio OT** (ISA-101 / ISA-18.2) | Cor apenas para anormalidade; severidade crítico → alto → médio → baixo, sempre com rótulo textual |

Implementação: tokens RGB em `frontend/src/app/globals.css`, mapeados em `frontend/tailwind.config.ts`.
Regras curtas para agentes: [`design-system/SKILL.md`](design-system/SKILL.md).

## 1. Missão

Fazer uma ferramenta técnica de auditoria parecer um documento que um engenheiro assinaria: sóbria, legível e
baseada em dados reais. A interface deve transmitir confiança institucional (laudo, norma, compliance) sem
perder a densidade de informação de uma ferramenta de engenharia.

- **Produto:** Purdue Audit — auditoria passiva de redes OT/ICS com laudo ISA/IEC 62443-3-3.
- **Público:** técnicos e engenheiros de automação, analistas de segurança OT, recrutadores técnicos.
- **Superfícies:** página de apresentação (`/`), ferramenta e laudo (`/app`), laudo impresso em A4 (PDF).

## 2. Fundamentos

### 2.1 Cor

| Token | Valor | Uso |
|---|---|---|
| `canvas` | `#edeade` | Fundo da página |
| `band` | `#f5f3ea` | Faixas alternadas, cabeçalho de tabela, barra de janela, ficha técnica |
| `panel` | `#fbfaf6` | Cartões, painéis, tabelas |
| `raised` | `#e3e0d3` | Botão secundário, trilho de medidor, hover |
| `line` / `line-strong` | `#d3d0bf` / `#a8a492` | Bordas de 1 px / bordas de destaque |
| `fg` | `#111827` | Títulos e valores |
| `fg-muted` | `#4b5563` | Texto corrido |
| `fg-faint` | `#5e636e` | Metadados e rótulos (≥ 4,5:1 inclusive sobre `raised`) |
| `accent` (primária) | `#072c2c` | Botão primário, faixa de anúncio, chamada final, rodapé, janela de código |
| `accent-hover` | `#0f3d3b` | Hover da primária |
| `inverse-*` | ver frontmatter | Texto e bordas sobre o verde-petróleo |

**Severidade (uso exclusivo):** `status-critical` `#b42318`, `status-high` `#c4520e`, `status-medium` `#b58400`,
`status-low` `#047857`. `status-info` `#0c5cab` é usado para informação neutra e para o anel de foco.

Regras:
- Cor de severidade **deve** aparecer só como lâmpada (`.dot`, 8 px), barra fina ou traço de diagrama, sempre ao lado
  de rótulo textual. Nunca em texto corrido, fundo de seção ou botão.
- A primária **não deve** ser usada em ícones decorativos ou textos longos; ela marca ação e superfícies institucionais.
- Superfícies alternam `canvas` ↔ `band` entre seções; nunca duas seções seguidas com a mesma superfície e borda.

### 2.2 Tipografia

| Papel | Família | Tamanho / peso / entrelinha | Classe |
|---|---|---|---|
| Título de página (h1) | Inter Tight | 40 → 56 → 64 px · 700 · 1 · −0,02em | `.display` |
| Abertura de seção (h2) | Inter Tight | 32 → 40 px · 600 · 1 · −0,01em | `.h-section` |
| Título de cartão (h3) | Inter Tight | 24 px · 600 · 1,25 | — |
| Rótulo de seção | Inter | 12 px · 600 · caixa alta · +0,14em | `.eyebrow` |
| Texto de apoio | Inter | 16 → 18 px · 400 · 1,6 | `.lede` |
| Corpo | Inter | 15–16 px · 400 · 1,5 | — |
| Rótulo técnico | IBM Plex Mono | 12 px · 500 · caixa alta | `.label` |
| Dado (IP, porta, ID, Function Code, métrica) | IBM Plex Mono | herdado · `tabular-nums` | `.num` |
| CTA de destaque | Inter Tight | 16 px · 600 | `.btn-lg` |

Regras (fundamentos TypeUI):
- `h1` e `h2` **devem** usar entrelinha 1 e 32 px até o próximo elemento (`mt-8` no texto de apoio).
- Corpo e rótulos de botão **devem** ter no mínimo 16 px; texto de apoio no mínimo 14 px. Exceções: dados
  monoespaçados densos (≥ 12 px) e o laudo impresso (8 pt nas tabelas).
- Títulos em caixa de frase. Caixa alta só em `.eyebrow`, `.label` e `.tag`.
- Títulos de colunas do rodapé e de listas usam `h4`.

### 2.3 Espaço, forma e profundidade

- Grade base de 8 px (meios-passos de 4 px para ajustes internos).
- Contêiner `.frame`: largura máxima 1200 px, margens laterais 16 / 32 / 48 px.
- Seções: `.section` = 80 px (mobile) / 112 px (desktop) de respiro vertical. Abertura → conteúdo: 56 px (`mt-14`).
- Raios: 4 px (botões, tags, campos), 6 px (blocos internos), 8 px (cartões, painéis, janelas). `rounded-full` só em
  lâmpadas de status e medidores.
- Sem sombras. Profundidade vem da troca `canvas → band → panel` e de bordas de 1 px.

### 2.4 Movimento

- Apenas `transition-colors duration-150` em hover/foco.
- A única animação contínua é o tracejado dos conduítes violados no diagrama Purdue (`.flow`), desligada sob
  `prefers-reduced-motion`.
- Proibido: `hover:scale`, `translate`, bounce, parallax, brilho.

## 3. Componentes

| Componente | Anatomia e regras | Estados |
|---|---|---|
| **Faixa de anúncio** (`AnnouncementBar`) | Fundo primária, texto 14 px `band`, link sublinhado. Altura mínima 44 px | hover do link: `inverse-muted` |
| **Navegação** (`LandingNav`) | 64 px; links à esquerda, marca centralizada, ações à direita; fixa no topo com `canvas/95` | link: hover `raised/70` |
| **Marca** (`Wordmark`) | Selo "OT" monoespaçado em caixa de 32 px + "Purdue Audit" em Inter Tight 19 px; variante `inverse` | — |
| **Botão primário** (`.btn-primary`) | 44 px (48 px em `.btn-lg`), raio 4 px, fundo primária, texto `band` | hover `accent-hover`; foco anel `info` 2 px; desabilitado 50 % |
| **Botão secundário** (`.btn-secondary`) | Fundo `raised`, texto `fg` | hover `line/60` |
| **Botão fantasma** (`.btn-ghost`) | Transparente, texto `fg-muted` | hover `raised` |
| **Tag** (`.tag`) | Plex Mono 11 px, caixa alta, borda `line`, raio 4 px. Textos longos usam `whitespace-normal break-words` | — |
| **Lâmpada** (`.dot`) | Círculo de 8 px com a cor de severidade + rótulo ao lado | — |
| **Abertura de seção** (`SectionHead`) | `.eyebrow` → `h2.h-section` → `.lede` (máx. 672 px). `align="center"` em seções institucionais | — |
| **Ficha técnica** (`TitleBlock`) | Grade 2/3 colunas separada por linhas de 1 px; rótulo 13 px + valor monoespaçado 14 px | valores longos truncam |
| **Cartão** (`Card`) | `panel`, borda `line`, raio 8 px, padding 24/32 px; código de regra no topo, título h3 em Inter Tight | — |
| **Tabela** (`.data-table`) | Cabeçalho `band` + `.label`; linhas 14 px separadas por `line`; contêiner com `overflow-x-auto` | linha: hover `band`. Impressão: 8 pt, sem largura mínima |
| **Janela de produto** (`ProductShowcase`) | Barra `band` com três pontos, URL monoespaçada; cartões flutuantes só em ≥ 1024 px | — |
| **Janela de código** (`ApiSection`) | Fundo primária, abas Plex Mono 13 px com 44 px de altura, realce em tons areia e âmbar para números | aba ativa: borda inferior `inverse-fg` |
| **Chamada final** (`CtaBand`) | Bloco primária com raio 8 px; botão invertido (`band` sobre verde) + botão contornado | — |
| **Rodapé** (`LandingFooter`) | Fundo primária, colunas com `h4` em caixa alta, links 15 px | hover `inverse-muted` |
| **Diagrama Purdue** (`PurdueDiagram`) | Bandas alternando `band`/`panel`; nós `panel` com borda de severidade; tracejado = conduíte violado. Em telas estreitas, rolagem horizontal com largura mínima de 620 px | — |

## 4. Acessibilidade (WCAG 2.2 AA)

- Contraste ≥ 4,5:1 para todo texto; `fg-faint` foi escolhido para passar inclusive sobre `raised`.
- Foco visível em todo elemento interativo: contorno 2 px `status-info`, deslocamento 2 px.
- Alvos de toque ≥ 44 × 44 px (botões, abas, faixa de anúncio).
- Severidade nunca depende só de cor: lâmpada + rótulo ("Crítico", "escrita não autorizada").
- Abas com `role="tablist"`, `aria-selected` e `aria-controls`; modal com `aria-modal`, Esc e devolução de foco.
- Movimento contínuo desligado com `prefers-reduced-motion`.
- Nenhuma rolagem horizontal da página a 390 px; tabelas, código e diagrama rolam dentro do próprio contêiner.

## 5. Conteúdo e tom

Conciso, técnico e verificável. Todo número exibido vem do laudo de demonstração ou do código.

- **Faça:** "Leitura pacote a pacote: cabeçalho MBAP do Modbus, OpenSecureChannel do OPC UA" · "3.823 B enviados à IA".
- **Não faça:** "Potencialize sua segurança", "Rápido, seguro e escalável", números redondos inventados.

## 6. Anti-padrões proibidos

- Gradientes, brilho, glassmorphism, sombras de cartão.
- Paletas indigo/violeta/roxo; segunda cor de marca.
- Ícones decorativos em caixas coloridas; emoji.
- Linha de três cartões idênticos com ícone + título + frase.
- Cor de severidade em elemento que não está em alarme.
- Texto de apoio abaixo de 14 px fora de dados monoespaçados.

## 7. Checklist de QA (revisão de código)

- [ ] Só tokens do sistema (nenhum hex solto, exceto o realce da janela de código).
- [ ] `h1`/`h2` com `.display`/`.h-section` e `mt-8` no texto seguinte.
- [ ] Dados em `.num`; severidade com `.dot` + rótulo.
- [ ] Botões com 44 px de altura e foco visível.
- [ ] `scrollWidth` = 390 a 390 px de largura; tabelas dentro de `overflow-x-auto`.
- [ ] Laudo impresso: nenhuma tabela cortada na largura A4.
- [ ] `npx tsc --noEmit` e `npm run build` sem erros.
