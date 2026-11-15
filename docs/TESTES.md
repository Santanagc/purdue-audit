# Relatório de testes — Purdue Audit

Executado em 2026-11-15, antes da divulgação. Tudo automatizado. A bateria de navegador roda o Chrome headless via DevTools Protocol, e a acessibilidade é verificada com axe-core 4.10.

| Camada | Onde | Resultado |
|---|---|---|
| Unitários + contrato (pytest) | `backend/tests` | **34/34** |
| Integração HTTP da API | uvicorn local, provedor de IA `mock` | **15/15** |
| Ponta a ponta no navegador | `localhost:3000` + API local | **34/34** |
| Ponta a ponta no site publicado | `purdue-audit.vercel.app` (somente demonstração) | **32/32** |

## Problemas encontrados e corrigidos por esta bateria

1. **Arquivo corrompido gerava laudo "nota 100 / risco baixo".** Um PCAP com cabeçalho válido seguido de lixo agora retorna 422 ("Nenhum host IP identificado…"). A correção vale para as duas edições e ganhou um teste de regressão.
2. **Campo de arquivo sem rótulo e aninhado no botão de envio** (axe: `label`, `nested-interactive`). O campo saiu do botão e ganhou `aria-label`.
3. **Áreas com rolagem horizontal não recebiam foco pelo teclado** (axe: `scrollable-region-focusable`): diagrama Purdue, exemplos de código e tabela de controles.

## Integração HTTP da API

| Teste | Resultado | Detalhe |
|---|---|---|
| GET /health | ✅ | 200, provedor=mock, limite=10 MB |
| POST /audit/demo | ✅ | 200, nota 17, 9 vulnerabilidades, 2114 ms |
| upload captura-ot.pcap | ✅ | 200, nota 17 (CRÍTICO), 7 ativos, 9 achados, payload IA 3827 B, 2140 ms |
| upload captura-ot.pcapng | ✅ | 200, nota 17 (CRÍTICO), 7 ativos, 9 achados, payload IA 3827 B, 2108 ms |
| upload so-ti.pcap | ✅ | 200, nota 100 (BAIXO), 3 ativos, 0 achados, payload IA 463 B, 2065 ms |
| upload notas.txt | ✅ | 400: Formato inválido: envie um arquivo .pcap ou .pcapng. |
| upload falso.pcap | ✅ | 400: O arquivo não possui assinatura PCAP/PCAPNG válida. |
| upload corrompido.pcap | ✅ | 422: Nenhum host IP identificado na captura: o arquivo pode estar corrompido ou não conter tráfego auditável. |
| upload vazio.pcap | ✅ | 400: Arquivo vazio. |
| upload grande.pcap | ✅ | 413: Arquivo excede o limite de 10 MB. |
| Nenhum PCAP retido no disco | ✅ | 0 arquivos temporários restantes |
| CORS bloqueia origem desconhecida | ✅ | sem cabeçalho ACAO |
| CORS permite o frontend | ✅ | http://localhost:3000 |
| Cabeçalhos de segurança na API | ✅ | x-content-type-options, x-frame-options, referrer-policy, permissions-policy, cross-origin-opener-policy, cross-origin-resource-policy, content-security-policy |
| Limite de requisições (10/min) | ✅ | respostas: [200, 429, 429, 429, 429, 429, 429, 429, 429, 429, 429, 429] |

## Ponta a ponta — local (backend + frontend)

| Grupo | Teste | Resultado | Detalhe |
|---|---|---|---|
| Landing | Título da aba | ✅ | Purdue Audit — Auditoria Passiva de Redes Industriais (ISA/IEC 62443) |
| Landing | Título principal (h1) | ✅ | Auditoria de redes industriais que a engenharia pode assinar. |
| Landing | Sem erros no console | ✅ | 0 erros |
| Landing | Imagens carregadas | ✅ | 0 imagens |
| Landing | Nenhuma requisição a terceiros (privacidade) | ✅ | só a própria origem |
| Pré-visualização LinkedIn | Tags og:title, og:image e twitter:card | ✅ | http://localhost:3000/opengraph-image.png?534db4ec47fb8b14 |
| Pré-visualização LinkedIn | Imagem do card acessível (1200×630) | ✅ | image/png, 75 KB |
| Pré-visualização LinkedIn | Favicon declarado | ✅ | /icon.svg?827b853ffd646d0a |
| Navegação | Âncoras internas apontam para seções existentes | ✅ | 7 âncoras |
| Navegação | Todos os links da landing respondem | ✅ | 3 destinos: localhost:3000/, localhost:3000/app, localhost:3000/app |
| Ferramenta | Barra de status indica "online" | ✅ | online |
| Ferramenta | Sem erros no console (/app) | ✅ | 0 erros |
| Validação | Arquivo .txt é recusado no navegador | ✅ | Formato não suportado. Envie um arquivo .pcap, .pcapng ou .cap. |
| Validação | Arquivo acima de 10 MB é recusado no navegador | ✅ | O arquivo excede o limite de 10 MB . |
| Upload real | Captura .pcap gera o laudo | ✅ | nota e risco exibidos |
| Upload real | Laudo traz resumo, Purdue, protocolos e vulnerabilidades | ✅ | #resumo · #purdue · #protocolos · #vulnerabilidades |
| Upload real | "Nova auditoria" volta à tela de envio | ✅ | http://localhost:3000/app |
| Upload real | Captura .pcapng também gera o laudo | ✅ |  |
| Upload real | Captura corrompida mostra erro (sem laudo falso) | ✅ | Nenhum host IP identificado na captura: o arquivo pode estar corrompido ou não conter tráfego auditável. |
| Demo | Botão "Rodar demo" abre o laudo | ✅ |  |
| Demo | Laudo de demo com nota 17 e risco CRÍTICO | ✅ |  |
| Demo | Sem erros no console durante a demo | ✅ | 0 erros |
| Demo | Link direto /app?demo abre o laudo | ✅ |  |
| Modal | "Sobre o projeto" abre um diálogo acessível | ✅ | role=dialog aria-modal=true |
| Modal | Esc fecha o diálogo | ✅ |  |
| PDF | Exportação gera o laudo em PDF | ✅ | 11 páginas, 542 KB |
| PDF | Botões e menus não aparecem no PDF | ✅ |  |
| Acessibilidade | WCAG 2.2 AA sem violações graves em / | ✅ | 0 violações |
| Acessibilidade | WCAG 2.2 AA sem violações graves em /app | ✅ | 0 violações |
| Acessibilidade | WCAG 2.2 AA sem violações graves em /app?demo | ✅ | 0 violações |
| Celular 390 px | Sem rolagem lateral em / | ✅ | largura 390px |
| Celular 390 px | Sem rolagem lateral em /app | ✅ | largura 390px |
| Celular 390 px | Sem rolagem lateral em /app?demo | ✅ | largura 390px |
| Erros | Página inexistente mostra 404 | ✅ | Purdue Audit — Auditoria Passiva de Redes Industriais (ISA/IEC 62443) |

## Ponta a ponta — site publicado

| Grupo | Teste | Resultado | Detalhe |
|---|---|---|---|
| Landing | Título da aba | ✅ | Purdue Audit — Auditoria Passiva de Redes Industriais (ISA/IEC 62443) |
| Landing | Título principal (h1) | ✅ | Auditoria de redes industriais que a engenharia pode assinar. |
| Landing | Sem erros no console | ✅ | 0 erros |
| Landing | Imagens carregadas | ✅ | 0 imagens |
| Landing | Nenhuma requisição a terceiros (privacidade) | ✅ | só a própria origem |
| Pré-visualização LinkedIn | Tags og:title, og:image e twitter:card | ✅ | https://purdue-audit.vercel.app/opengraph-image.png?534db4ec47fb8b14 |
| Pré-visualização LinkedIn | Imagem do card acessível (1200×630) | ✅ | image/png, 75 KB |
| Pré-visualização LinkedIn | Favicon declarado | ✅ | /icon.svg?827b853ffd646d0a |
| Navegação | Âncoras internas apontam para seções existentes | ✅ | 7 âncoras |
| Navegação | Todos os links da landing respondem | ✅ | 4 destinos: github.com/Santanagc/purdue-audit, purdue-audit.vercel.app/, purdue-audit.vercel.app/app, purdue-audit.vercel.app/app |
| Navegação | Links do GitHub apontam para o repositório novo | ✅ | ['https://github.com/Santanagc/purdue-audit'] |
| Ferramenta | Barra de status indica "somente demonstração" | ✅ | somente demonstração |
| Ferramenta | Sem erros no console (/app) | ✅ | 0 erros |
| Ferramenta | Não chama API nem o localhost do visitante | ✅ | nenhuma chamada |
| Validação | Arquivo .txt é recusado no navegador | ✅ | Formato não suportado. Envie um arquivo .pcap, .pcapng ou .cap. |
| Validação | Arquivo acima de 10 MB é recusado no navegador | ✅ | O arquivo excede o limite de 10 MB . |
| Upload real | Envio no site publicado explica que só há demonstração | ✅ | Esta publicação mostra apenas o laudo de demonstração: o servidor de análise não está configurado. |
| Demo | Botão "Rodar demo" abre o laudo | ✅ |  |
| Demo | Laudo de demo com nota 17 e risco CRÍTICO | ✅ |  |
| Demo | Sem erros no console durante a demo | ✅ | 0 erros |
| Demo | Link direto /app?demo abre o laudo | ✅ |  |
| Modal | "Sobre o projeto" abre um diálogo acessível | ✅ | role=dialog aria-modal=true |
| Modal | Esc fecha o diálogo | ✅ |  |
| PDF | Exportação gera o laudo em PDF | ✅ | 11 páginas, 542 KB |
| PDF | Botões e menus não aparecem no PDF | ✅ |  |
| Acessibilidade | WCAG 2.2 AA sem violações graves em / | ✅ | 0 violações |
| Acessibilidade | WCAG 2.2 AA sem violações graves em /app | ✅ | 0 violações |
| Acessibilidade | WCAG 2.2 AA sem violações graves em /app?demo | ✅ | 0 violações |
| Celular 390 px | Sem rolagem lateral em / | ✅ | largura 390px |
| Celular 390 px | Sem rolagem lateral em /app | ✅ | largura 390px |
| Celular 390 px | Sem rolagem lateral em /app?demo | ✅ | largura 390px |
| Erros | Página inexistente mostra 404 | ✅ | Purdue Audit — Auditoria Passiva de Redes Industriais (ISA/IEC 62443) |

## Verificação manual antes de publicar (cerca de 10 minutos)

- [ ] Abrir https://purdue-audit.vercel.app no celular (4G e Wi-Fi) e no computador.
- [ ] Clicar em **Abrir laudo de demonstração**, percorrer as seções e usar **Exportar laudo (PDF)**.
- [ ] Colar o link no [LinkedIn Post Inspector](https://www.linkedin.com/post-inspector/) e conferir imagem, título e descrição do card.
- [ ] Rodar localmente (`docker compose up` ou os comandos do README) e enviar uma captura real sua.
- [ ] Abrir o repositório deslogado (aba anônima) e conferir README, capturas de tela e o PDF de exemplo.
