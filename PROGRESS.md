# PROGRESS — Purdue Audit (edição portfólio)
**Estado:** pronto para publicar (2026-11-15) · derivado de `../ot-shield-ai` (versão SaaS completa, intacta)

## Diferenças em relação ao SaaS
- Removidos: auth Supabase/JWT, créditos, pagamentos (Stripe/AbacatePay), migração SQL, testes de integração
- Backend: rotas health · audit/upload · audit/demo; `MAX_UPLOAD_MB`; LLM padrão `mock` em deploy público
- Frontend: sem login/planos; modal "Sobre o projeto"; links via `NEXT_PUBLIC_AUTHOR_NAME/LINKEDIN_URL/REPO_URL`
- Demo resiliente: `frontend/public/demo-report.json` (gerado por `app.utils.export_demo_report`) quando a API hiberna
- Rotas: `/` landing estilo produto (hero + diagrama Purdue SVG, vitrine, bento, números, API, segurança) · `/app` ferramenta
- `/app?demo` abre o laudo direto (usado para gerar `docs/laudo-exemplo.pdf` via Chrome headless)
- Design system próprio: `DESIGN.md` + `design-system/SKILL.md` (base TypeUI Enterprise: areia + verde-petróleo, Inter Tight/Inter/Plex Mono)
- Motor: papel `External Host` para IPs públicos; OT-MODBUS-001 não marca o mestre primário; evidências com plural correto e ordem determinística

## Validação
- `pytest -q --tb=short` → 34 passed (inclui 413/422 sem temporário, PCAP com lixo após o cabeçalho, XFF forjado, contrato do snapshot)
- tsc + `next build` ok; testado no Chrome: demo offline (snapshot) e online (ao vivo), modal, PDF claro (11 págs)
- BUGs corrigidos (também no SaaS): PcapReader não fechava o arquivo com cabeçalho inválido; ordem de mestres empatados na evidência variava com o hash seed
- UI validada: 390 px sem rolagem horizontal; PDF A4 sem tabela cortada; "Nova auditoria" limpa `?demo`

## Ativos de portfólio
- `docs/screenshots/*.jpg` (7 telas, 1440×900, visual atual) · `docs/laudo-exemplo.pdf` · README com Mermaid

## Próximo passo (usuário)
- `git config user.name/email` → commit → criar repo público no GitHub → Vercel (Root Directory `frontend`)
- Opcional: Render via `render.yaml` (LLM_PROVIDER=mock) e `NEXT_PUBLIC_API_URL` na Vercel
