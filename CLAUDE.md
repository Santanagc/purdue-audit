# CLAUDE.md - Diretrizes do Projeto Purdue Audit

## Visão Geral do Projeto
O **Purdue Audit (edição portfólio)** é uma ferramenta de análise passiva de tráfego de redes industriais (OT/ICS) e auditoria de conformidade baseada na norma ISA/IEC 62443 e no Modelo Purdue.
O usuário faz upload de um arquivo `.pcap` ou `.pcapng`, o backend extrai metadados de protocolos industriais de forma determinística via Python (`scapy`), deleta o arquivo original imediatamente (arquitetura Stateless/Zero-Trust) e envia apenas o resumo JSON para um Agente LLM gerar o relatório executivo e o plano de mitigação.

## Stack Tecnológica
- **Backend:** Python 3.11+, FastAPI, Uvicorn, Scapy (puro, sem dependência de binários externos como `tshark` ou `wireshark`), Pydantic v2. Sem banco de dados, autenticação ou pagamentos nesta edição.
- **Motor de IA:** SDK da Anthropic (`anthropic`) ou OpenAI (`openai`) com Structured Outputs (JSON Schema) + Fallback em Modo Mock Inteligente local.
- **Frontend:** Next.js 15 (App Router), TypeScript estrito, Tailwind CSS (tokens sóbrios em `globals.css`), Lucide Icons. A demo cai no laudo pré-gerado `frontend/public/demo-report.json` quando o backend hiberna.
- **Infraestrutura:** Docker multi-stage leve (para deploy gratuito no Google Cloud Run ou Render) + Vercel (Frontend).

## Regras Críticas de Engenharia e Segurança (NUNCA VIOLE)
1. **Análise Estritamente Passiva e Defensiva:** O sistema NUNCA se conecta a redes reais ou CLPs. Ele apenas lê arquivos `.pcap` estáticos enviados via upload para fins de diagnóstico e auditoria defensiva.
2. **Processamento Stateless (Zero Retenção de PCAP):** Arquivos `.pcap` contêm dados sensíveis de plantas industriais. O backend deve processar o arquivo via `SpooledTemporaryFile` ou diretório `/tmp` isolado com bloco `try...finally` garantindo a remoção imediata (`os.remove`) assim que o JSON de metadados for extraído.
3. **Economia de Tokens na API do Produto:** NUNCA envie pacotes brutos ou dumps hexadecimais inteiros para a API do LLM auditor. O módulo `pcap_analyzer.py` deve agregar e comprimir 100.000 pacotes em um resumo JSON estatístico de no máximo 4 KB antes de chamar a IA.
4. **Código Completo e Tipado:** Use Type Hints em 100% das funções Python e TypeScript estrito no frontend. Não deixe funções com `pass`, `TODO` ou placeholders preguiçosos quando uma fase for solicitada.

## Protocolo de Economia de Tokens com Graphify e Engenharia de Contexto (OBRIGATÓRIO)
Você possui a ferramenta `graphify` instalada no ambiente local. Para minimizar o consumo de tokens da janela de contexto sem perder 1% sequer de qualidade técnica:
1. **Indexação Incremental com `graphify`:** Ao iniciar o projeto e ao concluir a criação de novos módulos (fim de cada Bloco), execute o `graphify` para atualizar o grafo arquitetural do repositório.
2. **Proibição de Releitura Bruta:** É ESTRITAMENTE PROIBIDO reler arquivos inteiros de código (`cat` ou `Read` completo) ou documentação repetidas vezes apenas para lembrar assinaturas de funções, classes ou schemas Pydantic.
3. **Consulta Direcionada via Grafo:** Sempre utilize o `graphify` para consultar a topologia de dependências, contratos de interface (`schemas.py` <-> Frontend TypeScript) e chamadas entre módulos (`pcap_analyzer.py`, `ai_auditor.py`, `main.py`). Quando precisar editar um arquivo existente, use a ferramenta `Edit` cirúrgica e leia apenas o intervalo de linhas exato (`offset`/`limit`) apontado pelo grafo.
4. **Comandos Silenciosos no Terminal (Zero Poluição de Logs):**
   - Ao instalar pacotes Python: use SEMPRE `pip install -q -r requirements.txt`.
   - Ao instalar pacotes Node: use SEMPRE `npm install --silent --no-audit --no-fund`.
   - Ao rodar testes: use SEMPRE `pytest -q --tb=short` (evita despejar tracebacks gigantes no histórico de conversa).
   - NUNCA leia arquivos listados no `.claudeignore` (`package-lock.json`, `node_modules/`, `.next/`, `.venv/`, `*.pcap`, `*.sqlite`).
5. **Delegação para Sub-Agentes (`Task` tool):** Sempre que precisar executar uma bateria de testes, depurar um erro de execução ou inicializar o boilerplate do Next.js, delegue a execução suja para um **Sub-agente (`Task`)**, instruindo-o a resolver o problema em seu próprio contexto isolado e retornar apenas um resumo executivo de até 5 linhas para a sessão principal.
6. **Memória Externa de Estado (`PROGRESS.md`):** Antes de parar em qualquer Checkpoint, atualize o arquivo `PROGRESS.md` na raiz (máximo de 30 linhas) registrando os arquivos concluídos, rotas da API criadas, status dos testes e próximo passo. Caso o usuário execute `/compact` entre os blocos, leia apenas o `PROGRESS.md` e consulte o `graphify` para retomar instantaneamente.

## Comandos Úteis de Desenvolvimento
- Regenerar o laudo de demonstração do frontend: `cd backend && python -m app.utils.export_demo_report`
- Iniciar Backend: `cd backend && uvicorn app.main:app --reload --port 8000`
- Rodar Testes de Dissecação (Silencioso): `cd backend && pytest -q --tb=short tests/`
- Gerar PCAP Sintético para Teste: `cd backend && python -m app.utils.generate_sample_pcap`
- Atualizar Grafo de Contexto: `graphify` (verificar flags com `graphify --help` se necessário)
- Iniciar Frontend: `cd frontend && npm run dev`

## Documentação de Referência Interna
Antes de implementar cada módulo na leitura inicial única, consulte obrigatoriamente:
- `docs/01_PROTOCOL_PARSING_SPEC.md`: Regras de bytes para Modbus TCP, OPC UA e desvios de zona IT/OT (Modelo Purdue).
- `docs/02_IEC62443_AI_SCHEMA.md`: Contratos JSON (Pydantic) entre o Scapy, a LLM e o Frontend.
## UI & Design Constraints — Purdue Audit Design System
Fonte de verdade: `DESIGN.md` (raiz) e `design-system/SKILL.md`. Leia antes de qualquer trabalho de UI. Resumo:
- Base TypeUI "Enterprise": superfícies areia (`canvas` #edeade, `band` #f5f3ea, `panel` #fbfaf6), primária verde-petróleo (`accent` #072c2c).
- Inter Tight (títulos, peso 600–700, tracking negativo, entrelinha 1, 32 px até o próximo elemento) + Inter (corpo ≥ 16 px, apoio ≥ 14 px) + IBM Plex Mono com `tabular-nums` (`.num`) para dados.
- Cor de status só para severidade, como `.dot` + rótulo textual. Sem sombras, gradientes, roxo/indigo ou segunda cor de marca.
- Raios 4/6/8 px; alvos de toque ≥ 44 px; foco 2 px `status-info`; WCAG 2.2 AA.
- Seções abrem com `SectionHead` e alternam `canvas` ↔ `band`; diagramas e laudos levam `TitleBlock`.
- Movimento só `transition-colors duration-150`. Copy técnica com dados reais do laudo de demonstração.
