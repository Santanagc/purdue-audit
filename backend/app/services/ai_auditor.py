"""Agente Auditor ISA/IEC 62443 (docs/02_IEC62443_AI_SCHEMA.md).

Recebe o NetworkAuditSummary determinístico, comprime para <= 4 KB e solicita ao LLM (Anthropic ou OpenAI)
um laudo estruturado `AuditReportOutput`. Sem chave de API configurada — ou em caso de falha do provedor —
gera um laudo técnico pelo Modo Mock Inteligente, derivado exclusivamente das descobertas reais do Scapy.
"""

from __future__ import annotations

import json
import logging
import math
from collections import Counter
from dataclasses import dataclass
from typing import Any, Literal

from app.config import Settings, get_settings
from app.models.schemas import (
    AuditReportOutput,
    DeterministicFinding,
    NetworkAuditSummary,
    RiskLevel,
    VulnerabilityItem,
    normalize_severity,
)
from app.services.pcap_analyzer import build_llm_payload, llm_payload_size

logger = logging.getLogger("otshield.ai_auditor")

ProviderLabel = Literal["anthropic", "openai", "mock", "mock-fallback"]

SYSTEM_PROMPT = """Você é um Auditor Líder de Cibersegurança Industrial certificado em ISA/IEC 62443 e especialista em Automação e Controle (Redes OT, SCADA, CLPs, Modbus TCP e OPC UA).
Sua função é analisar o resumo estruturado de tráfego de rede (JSON) extraído de uma planta industrial e produzir um Laudo Técnico de Auditoria focado em Continuidade Operacional e Segurança Cibernética.

REGRAS DE RESPOSTA:
1. Responda EXCLUSIVAMENTE em formato JSON válido seguindo o schema `AuditReportOutput`.
2. Mapeie cada vulnerabilidade encontrada para os Requisitos Fundamentais (FR) da norma IEC 62443-3-3 (ex: SR 1.1 Identificação e Autenticação, SR 3.1 Integridade de Comunicação, SR 4.1 Confidencialidade, SR 5.1 Segmentação de Rede / Zonas e Conduítes).
3. Nas recomendações de mitigação, seja prático para engenheiros de automação: nunca sugira "desligar o CLP" ou "bloquear a porta 502 indiscriminadamente" (o que pararia a planta). Recomende regras de firewall industrial por IP/MAC (whitelisting de mestre único SCADA), bloqueio de Function Codes de escrita para IPs de supervisão read-only, ativação de políticas Basic256Sha256 com certificados X.509 no servidor OPC UA e criação de VLANs separando tráfego de TI (SMB/RDP) do Nível 1/2 do Modelo Purdue.

DIRETRIZES ADICIONAIS:
- Escreva em português do Brasil, com linguagem técnica e objetiva.
- `executive_summary`: exatamente 2 parágrafos focados em risco operacional e risco de parada de planta.
- `purdue_segmentation_analysis`: análise de zonas e conduítes (Níveis 0-3 do Modelo Purdue, DMZ industrial), citando os IPs envolvidos.
- `overall_security_score`: inteiro de 0 (crítico) a 100 (excelente), coerente com a severidade das descobertas.
- `risk_level`: um de "BAIXO", "MÉDIO", "ALTO", "CRÍTICO".
- Cada item de `vulnerabilities` deve usar `severity` em "CRÍTICO", "ALTO", "MÉDIO" ou "BAIXO", citar a evidência técnica do JSON (IPs, Function Codes, políticas) e trazer de 3 a 6 passos de remediação executáveis em campo.
- Baseie-se SOMENTE nas evidências fornecidas; não invente ativos, IPs ou protocolos."""

OUTPUT_SCHEMA_HINT: dict[str, Any] = {
    "overall_security_score": "int 0-100",
    "risk_level": "BAIXO | MÉDIO | ALTO | CRÍTICO",
    "executive_summary": "str (2 parágrafos)",
    "purdue_segmentation_analysis": "str",
    "vulnerabilities": [
        {
            "id": "str",
            "title": "str",
            "severity": "CRÍTICO | ALTO | MÉDIO | BAIXO",
            "iec_62443_reference": "str (ex: IEC 62443-3-3 SR 3.1)",
            "technical_evidence": "str",
            "operational_impact": "str",
            "remediation_steps": ["str"],
        }
    ],
}

SEVERITY_WEIGHTS: dict[str, float] = {"CRITICAL": 20.0, "HIGH": 10.0, "MEDIUM": 5.0, "LOW": 2.0, "INFO": 0.0}
SCORE_DECAY = 80.0


@dataclass(frozen=True)
class AuditResult:
    report: AuditReportOutput
    provider: ProviderLabel
    llm_payload_bytes: int


@dataclass(frozen=True)
class _RuleKnowledge:
    reference: str
    impact: str
    remediation: tuple[str, ...]


RULE_KNOWLEDGE: dict[str, _RuleKnowledge] = {
    "OT-MODBUS-001": _RuleKnowledge(
        reference="IEC 62443-3-3 SR 1.1 / SR 2.1 / SR 3.1",
        impact=(
            "Qualquer host com alcance de rede pode alterar setpoints e estados do CLP {assets}. Um mestre não "
            "autorizado escrevendo em registradores de processo pode provocar manobras indevidas, disparo de "
            "intertravamentos, dano a equipamentos e parada não programada da planta."
        ),
        remediation=(
            "Identificar fisicamente os hosts não mapeados ({assets}) via tabela CAM do switch gerenciado e isolar a porta enquanto a origem é investigada.",
            "Configurar firewall industrial (DPI Modbus) na frente do CLP com whitelisting por IP/MAC permitindo somente o mestre SCADA oficial.",
            "Aplicar regra DPI bloqueando Function Codes de escrita (0x05, 0x06, 0x0F, 0x10) para qualquer origem diferente do SCADA primário.",
            "Habilitar no CLP a lista de IPs autorizados para Modbus (Access Control / IP filtering) suportada pelo firmware.",
            "Registrar escritas Modbus em um IDS industrial passivo (ex: alertas por novo mestre) com retenção de logs no historiador.",
        ),
    ),
    "OT-MODBUS-002": _RuleKnowledge(
        reference="IEC 62443-3-3 SR 1.1 / SR 2.1 / SR 3.1",
        impact=(
            "Escritas a partir de host diferente do mestre de supervisão ({assets}) indicam caminho de controle não "
            "documentado, permitindo alteração de lógica de processo sem rastreabilidade."
        ),
        remediation=(
            "Validar com a engenharia de automação se o host escritor é uma estação autorizada e documentá-lo no inventário de ativos.",
            "Restringir via firewall industrial os Function Codes de escrita apenas aos mestres autorizados.",
            "Separar estações de engenharia em zona dedicada com conduíte controlado até o Nível 1.",
            "Implantar monitoramento passivo com alerta para escritas fora da janela de manutenção.",
        ),
    ),
    "OT-MODBUS-003": _RuleKnowledge(
        reference="IEC 62443-3-3 SR 2.1 / SR 6.2 / SR 7.6",
        impact=(
            "Function Codes de diagnóstico/identificação (0x08, 0x11, 0x2B) revelam fabricante, modelo e firmware do "
            "CLP {assets}, etapa clássica de reconhecimento que antecede exploração de vulnerabilidades. O FC 0x08 "
            "pode ainda forçar reinício de comunicação (Listen Only Mode), interrompendo a supervisão."
        ),
        remediation=(
            "Bloquear no firewall industrial os FCs 0x08, 0x11 e 0x2B para todas as origens exceto a estação de engenharia autorizada.",
            "Investigar a origem das requisições de enumeração e preservar evidências (logs do switch e do IDS).",
            "Verificar boletins de segurança do fabricante para a versão de firmware exposta e planejar atualização na próxima parada.",
            "Desabilitar no CLP serviços de diagnóstico remoto que não sejam necessários para a operação.",
        ),
    ),
    "OT-MODBUS-004": _RuleKnowledge(
        reference="IEC 62443-3-3 SR 3.1 / SR 6.2",
        impact=(
            "A alta taxa de exceções (Illegal Data Address) caracteriza varredura de memória do CLP {assets}. Além do "
            "mapeamento de registradores para ataques direcionados, a varredura consome ciclo de comunicação e pode "
            "degradar o tempo de scan da supervisão."
        ),
        remediation=(
            "Isolar e investigar o host responsável pela varredura.",
            "Ativar no IDS industrial regra de alerta por taxa de exceções Modbus acima do baseline.",
            "Restringir o mapa de registradores acessíveis via firewall DPI (faixas de endereço permitidas por mestre).",
            "Revisar a configuração do driver SCADA para eliminar leituras a endereços inexistentes.",
        ),
    ),
    "OT-MODBUS-005": _RuleKnowledge(
        reference="IEC 62443-3-3 SR 1.2 / SR 3.1 / SR 4.1",
        impact=(
            "O Modbus TCP não possui autenticação nem integridade de mensagem: comandos e valores de processo de {assets} "
            "trafegam em texto claro, permitindo leitura, replay e injeção por qualquer host no segmento."
        ),
        remediation=(
            "Segmentar o tráfego Modbus em VLAN de controle dedicada (Nível 1/2) com conduíte único até o SCADA.",
            "Onde o hardware suportar, migrar para Modbus/TLS (porta 802) com certificados X.509 por dispositivo.",
            "Para CLPs legados, instalar gateway/firewall industrial com VPN IPsec ou túnel TLS até o centro de controle.",
            "Aplicar port security (MAC sticky) e desabilitar portas de switch não utilizadas no segmento de campo.",
        ),
    ),
    "OT-MODBUS-006": _RuleKnowledge(
        reference="IEC 62443-3-3 SR 2.1 / SR 5.1",
        impact="Múltiplos mestres consultando o CLP {assets} ampliam a superfície de ataque e dificultam a detecção de mestres não autorizados.",
        remediation=(
            "Documentar todos os mestres legítimos no inventário de ativos.",
            "Concentrar a aquisição de dados em um único servidor SCADA/OPC e distribuir via historiador na DMZ.",
            "Aplicar whitelisting por IP no firewall industrial.",
        ),
    ),
    "OT-MODBUS-008": _RuleKnowledge(
        reference="IEC 62443-3-3 SR 3.1 / SR 7.6",
        impact="Exceções esporádicas no CLP {assets} indicam configuração inconsistente do driver de comunicação.",
        remediation=(
            "Revisar a tabela de tags do SCADA contra o mapa de memória do CLP.",
            "Monitorar a taxa de exceções como indicador de integridade da comunicação.",
            "Registrar o baseline de exceções no IDS industrial.",
        ),
    ),
    "OT-OPCUA-001": _RuleKnowledge(
        reference="IEC 62443-3-3 SR 1.2 / SR 3.1 / SR 4.1",
        impact=(
            "Com SecurityPolicy#None, o canal OPC UA entre {assets} não é assinado nem criptografado: credenciais de "
            "sessão, valores de processo e chamadas de escrita podem ser interceptados e adulterados (man-in-the-middle)."
        ),
        remediation=(
            "Habilitar no servidor OPC UA o endpoint Basic256Sha256 (ou Aes128_Sha256_RsaOaep) com MessageSecurityMode SignAndEncrypt.",
            "Emitir certificados X.509 por aplicação (PKI interna) e configurar trust list explícita no servidor e nos clientes.",
            "Remover o endpoint SecurityPolicy#None da configuração do servidor após migrar todos os clientes.",
            "Exigir autenticação de usuário (certificado ou usuário/senha) em vez de sessão anônima.",
        ),
    ),
    "OT-OPCUA-002": _RuleKnowledge(
        reference="IEC 62443-3-3 SR 4.3 / SR 3.1",
        impact="Políticas Basic128Rsa15/Basic256 usam SHA-1 e RSA PKCS#1 v1.5, consideradas inseguras pela OPC Foundation, no canal entre {assets}.",
        remediation=(
            "Migrar os endpoints para Basic256Sha256 ou Aes256_Sha256_RsaPss.",
            "Reemitir certificados com chaves RSA de no mínimo 2048 bits e assinatura SHA-256.",
            "Desabilitar as políticas depreciadas no servidor após validação com todos os clientes.",
        ),
    ),
    "OT-OPCUA-004": _RuleKnowledge(
        reference="IEC 62443-3-3 SR 3.1",
        impact="Não foi possível confirmar a política de segurança do canal OPC UA entre {assets}.",
        remediation=(
            "Capturar o tráfego desde a abertura da sessão (mensagens HEL/OPN) para validar a política.",
            "Auditar a configuração de endpoints diretamente no servidor OPC UA.",
            "Garantir que apenas políticas Basic256Sha256 ou superiores estejam habilitadas.",
        ),
    ),
    "OT-PURDUE-001": _RuleKnowledge(
        reference="IEC 62443-3-3 SR 5.1 / SR 5.2 (IEC 62443-3-2 Zonas e Conduítes)",
        impact=(
            "Protocolos de TI (SMB/RDP/VNC) no segmento de controle entre {assets} são o principal vetor de propagação de "
            "ransomware para o chão de fábrica, podendo comprometer HMIs e estações de engenharia e parar a produção."
        ),
        remediation=(
            "Criar VLAN dedicada para Nível 1/2 do Modelo Purdue e mover estações de TI/servidores de arquivos para a zona corporativa (Nível 4).",
            "Implantar DMZ industrial (Nível 3.5) com servidor de transferência de arquivos intermediário, eliminando SMB direto até a rede de controle.",
            "Configurar firewall entre zonas negando SMB (445), RDP (3389) e VNC (5900) por padrão; permitir acesso remoto apenas via jump server com MFA.",
            "Aplicar hardening (desabilitar SMBv1, compartilhamentos administrativos) nas estações que permanecerem no segmento OT.",
        ),
    ),
    "OT-PURDUE-002": _RuleKnowledge(
        reference="IEC 62443-3-3 SR 1.1 / SR 4.1 / SR 5.1",
        impact=(
            "Protocolos legados em texto claro (Telnet/FTP/HTTP/SNMP v1-v2c) envolvendo {assets} expõem credenciais "
            "administrativas do equipamento de campo, permitindo alteração de configuração ou de firmware por qualquer "
            "host que capture o tráfego."
        ),
        remediation=(
            "Desabilitar Telnet/FTP/HTTP nos CLPs e switches; utilizar SSH, SFTP e HTTPS onde o firmware suportar.",
            "Migrar o monitoramento para SNMPv3 (authPriv) e trocar imediatamente communities/senhas expostas.",
            "Restringir o acesso de manutenção a uma estação de engenharia dedicada via firewall de conduíte.",
            "Rotacionar todas as credenciais observadas em texto claro na captura.",
        ),
    ),
    "OT-EXPOSURE-001": _RuleKnowledge(
        reference="IEC 62443-3-3 SR 5.1 / SR 5.2 / SR 1.13",
        impact=(
            "O CLP conversa diretamente com IP público ({assets}): o dispositivo de campo está alcançável a partir da "
            "Internet, cenário explorado por varreduras automatizadas (Shodan) e por ataques de sabotagem remota."
        ),
        remediation=(
            "Remover imediatamente regras NAT/port-forward que exponham a porta 502 ou outras portas de controle à Internet.",
            "Investigar a origem pública e verificar se houve escrita ou alteração de lógica (comparar programa do CLP com backup íntegro).",
            "Estabelecer acesso remoto somente via VPN com MFA terminando na DMZ industrial, nunca no Nível 1.",
            "Aplicar regra de firewall de borda negando tráfego de/para redes OT a partir de IPs não-RFC1918.",
        ),
    ),
    "OT-EXPOSURE-002": _RuleKnowledge(
        reference="IEC 62443-3-3 SR 5.1 / SR 5.2",
        impact="Estação de supervisão comunicando com IP público ({assets}) cria conduíte não controlado entre Internet e a zona de controle.",
        remediation=(
            "Bloquear acesso direto à Internet a partir de HMIs/SCADA.",
            "Centralizar atualizações e telemetria via proxy na DMZ industrial.",
            "Investigar o destino público e revisar regras de firewall de borda.",
        ),
    ),
    "OT-ICS-001": _RuleKnowledge(
        reference="IEC 62443-3-3 SR 1.2 / SR 3.1",
        impact="Protocolos de automação sem autenticação nativa entre {assets} permitem comandos não autorizados a partir do segmento.",
        remediation=(
            "Restringir o acesso aos servidores industriais por whitelisting de IP no firewall industrial.",
            "Avaliar variantes seguras (DNP3 Secure Authentication, CIP Security) suportadas pelo fabricante.",
            "Monitorar o tráfego com IDS industrial com dissectores específicos do protocolo.",
        ),
    ),
}

DEFAULT_KNOWLEDGE = _RuleKnowledge(
    reference="IEC 62443-3-3 SR 3.1 / SR 5.1",
    impact="Condição de segurança identificada envolvendo {assets} que reduz a resiliência da rede de controle.",
    remediation=(
        "Validar a evidência com a equipe de automação.",
        "Aplicar segmentação e whitelisting no firewall industrial.",
        "Monitorar continuamente com IDS industrial passivo.",
    ),
)


# ---------------------------------------------------------------------------
# Modo Mock Inteligente (determinístico, sem custo de API)
# ---------------------------------------------------------------------------


def compute_security_score(findings: list[DeterministicFinding]) -> int:
    penalty = sum(SEVERITY_WEIGHTS[f.severity] for f in findings)
    return max(0, min(100, int(round(100 * math.exp(-penalty / SCORE_DECAY)))))


def compute_risk_level(score: int, findings: list[DeterministicFinding]) -> RiskLevel:
    severities = {f.severity for f in findings}
    if "CRITICAL" in severities or score < 40:
        return "CRÍTICO"
    if "HIGH" in severities or score < 60:
        return "ALTO"
    if "MEDIUM" in severities or score < 80:
        return "MÉDIO"
    return "BAIXO"


def _plural(count: int, singular: str, plural: str) -> str:
    """Concordância numérica em PT-BR, evitando construções como "mestre(s)"."""
    return f"{count} {singular if count == 1 else plural}"


def _fmt_assets(assets: list[str], limit: int = 4) -> str:
    if not assets:
        return "os ativos do segmento"
    shown = ", ".join(assets[:limit])
    return shown + (f" e mais {len(assets) - limit}" if len(assets) > limit else "")


def _build_vulnerabilities(findings: list[DeterministicFinding]) -> list[VulnerabilityItem]:
    vulns: list[VulnerabilityItem] = []
    seen: Counter[str] = Counter()
    for f in findings:
        if f.severity == "INFO":
            continue
        seen[f.rule_id] += 1
        vuln_id = f.rule_id if seen[f.rule_id] == 1 else f"{f.rule_id}-{seen[f.rule_id]}"
        kb = RULE_KNOWLEDGE.get(f.rule_id, DEFAULT_KNOWLEDGE)
        assets = _fmt_assets(f.affected_assets)
        vulns.append(
            VulnerabilityItem(
                id=vuln_id,
                title=f.title,
                severity=normalize_severity(f.severity),
                iec_62443_reference=kb.reference,
                technical_evidence=f.evidence,
                operational_impact=kb.impact.format(assets=assets),
                remediation_steps=[step.format(assets=assets) for step in kb.remediation],
            )
        )
    return vulns


def _executive_summary(summary: NetworkAuditSummary, score: int, risk: RiskLevel) -> str:
    meta = summary.capture_metadata
    counts = Counter(f.severity for f in summary.deterministic_findings)
    roles = Counter(a.inferred_role for a in summary.assets)
    plcs = [a.ip for a in summary.assets if a.inferred_role == "PLC / Field Slave"]
    ot_protocols = [p for p in meta.protocols_detected if p in {"ModbusTCP", "OPCUA", "S7comm", "DNP3", "EtherNet/IP", "IEC-104", "BACnet", "ModbusTLS"}]

    externals = roles.get("External Host", 0)
    external_txt = f", além de {_plural(externals, 'host externo', 'hosts externos')} na Internet" if externals else ""
    p1 = (
        f"A análise passiva de {meta.total_packets} pacotes ({meta.duration_seconds:.1f} s de captura) identificou "
        f"{len(summary.assets)} ativos, sendo "
        f"{_plural(roles.get('PLC / Field Slave', 0), 'dispositivo de campo industrial', 'dispositivos de campo industriais')} "
        f"({_fmt_assets(plcs)}) e {_plural(roles.get('HMI / SCADA Master', 0), 'mestre SCADA/HMI', 'mestres SCADA/HMI')}"
        f"{external_txt}, comunicando via "
        f"{', '.join(ot_protocols) if ot_protocols else 'protocolos não industriais'}. O índice de segurança calculado é "
        f"{score}/100, classificando o ambiente com risco {risk}: foram registradas "
        f"{_plural(counts.get('CRITICAL', 0), 'descoberta crítica', 'descobertas críticas')}, "
        f"{_plural(counts.get('HIGH', 0), 'alta', 'altas')} e {_plural(counts.get('MEDIUM', 0), 'média', 'médias')}."
    )

    risks: list[str] = []
    rule_ids = {f.rule_id for f in summary.deterministic_findings}
    if {"OT-MODBUS-001", "OT-MODBUS-002"} & rule_ids:
        risks.append("comandos de escrita Modbus de origens não autorizadas, com potencial de alterar setpoints e provocar parada não programada")
    if "OT-MODBUS-003" in rule_ids or "OT-MODBUS-004" in rule_ids:
        risks.append("atividade de reconhecimento e varredura de registradores contra CLPs, típica da fase preparatória de um ataque")
    if "OT-OPCUA-001" in rule_ids:
        risks.append("canal OPC UA sem assinatura nem criptografia (SecurityPolicy#None), sujeito a interceptação e adulteração")
    if summary.security_flags.it_ot_convergence_detected:
        risks.append("convergência TI/OT com protocolos corporativos e legados no segmento de controle, principal vetor de propagação de ransomware")
    if summary.security_flags.external_exposure_detected:
        risks.append("exposição de ativos de controle a endereços públicos da Internet")
    if not risks:
        risks.append("ausência de controles de autenticação e integridade nativos nos protocolos industriais observados")

    p2 = (
        "Do ponto de vista de continuidade operacional, os riscos prioritários são: "
        + "; ".join(risks)
        + ". Recomenda-se tratar primeiro as descobertas críticas com controles compensatórios que não exigem parada de "
        "planta — whitelisting de mestre único no firewall industrial, bloqueio de Function Codes de escrita/diagnóstico "
        "por origem e segmentação em zonas e conduítes conforme IEC 62443-3-2 — seguidos da migração para protocolos "
        "seguros (Modbus/TLS, OPC UA Basic256Sha256) na próxima janela de manutenção."
    )
    return f"{p1}\n\n{p2}"


def _purdue_analysis(summary: NetworkAuditSummary) -> str:
    plcs = [a.ip for a in summary.assets if a.inferred_role == "PLC / Field Slave"]
    masters = [a.ip for a in summary.assets if a.inferred_role == "HMI / SCADA Master"]
    it_hosts = [a.ip for a in summary.assets if a.inferred_role == "Engineering Workstation / IT Host"]
    externals = [a.ip for a in summary.assets if a.inferred_role == "External Host"]
    purdue = [f for f in summary.deterministic_findings if f.category in ("PURDUE", "EXPOSURE")]

    parts: list[str] = [
        f"Nível 1 (controle básico): {_fmt_assets(plcs, 6) if plcs else 'nenhum dispositivo de campo identificado'}. "
        f"Nível 2 (supervisão): {_fmt_assets(masters, 6) if masters else 'nenhum mestre SCADA identificado'}. "
        f"Hosts com perfil de TI/engenharia no mesmo domínio de broadcast: {_fmt_assets(it_hosts, 6) if it_hosts else 'nenhum'}."
        + (f" Endereços externos (Internet) em contato com a planta: {_fmt_assets(externals, 6)}." if externals else "")
    ]
    if purdue:
        violations = "; ".join(f"{f.title} ({normalize_severity(f.severity)})" for f in purdue)
        parts.append(
            f"Foram identificadas {_plural(len(purdue), 'violação', 'violações')} do isolamento de zonas: {violations}. "
            "Não há evidência de conduíte controlado (firewall/DMZ industrial) entre a zona de TI e a zona de controle — "
            "protocolos corporativos alcançam diretamente o segmento dos CLPs, contrariando os requisitos SR 5.1 "
            "(segmentação de rede) e SR 5.2 (proteção de fronteira de zona) da IEC 62443-3-3."
        )
        parts.append(
            "Arquitetura-alvo recomendada: VLAN dedicada para Níveis 1/2, DMZ industrial (Nível 3.5) concentrando "
            "historiador, servidor de arquivos e jump server com MFA, e firewall industrial com DPI entre a supervisão e o "
            "campo permitindo somente os fluxos SCADA documentados."
        )
    else:
        parts.append(
            "Nenhum protocolo de TI corporativa ou exposição externa foi observado no segmento de controle durante a "
            "captura; manter a segmentação atual e validar periodicamente as regras de conduíte."
        )
    return " ".join(parts)


def generate_mock_report(summary: NetworkAuditSummary) -> AuditReportOutput:
    findings = summary.deterministic_findings
    score = compute_security_score(findings)
    risk = compute_risk_level(score, findings)
    return AuditReportOutput(
        overall_security_score=score,
        risk_level=risk,
        executive_summary=_executive_summary(summary, score, risk),
        purdue_segmentation_analysis=_purdue_analysis(summary),
        vulnerabilities=_build_vulnerabilities(findings),
    )


# ---------------------------------------------------------------------------
# Provedores LLM
# ---------------------------------------------------------------------------


def _user_message(payload: dict[str, Any]) -> str:
    return (
        "Resumo JSON determinístico extraído da captura de tráfego OT (sem payloads brutos):\n"
        + json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
        + "\n\nGere o laudo `AuditReportOutput` em JSON."
    )


def _call_anthropic(payload: dict[str, Any], settings: Settings) -> AuditReportOutput:
    import anthropic

    client = anthropic.Anthropic(api_key=settings.anthropic_api_key, timeout=settings.llm_timeout_seconds, max_retries=2)
    response = client.messages.parse(
        model=settings.anthropic_model,
        max_tokens=16000,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": _user_message(payload)}],
        output_format=AuditReportOutput,
    )
    if response.stop_reason == "refusal":
        raise RuntimeError("Anthropic recusou a solicitação (stop_reason=refusal).")
    if response.stop_reason == "max_tokens":
        raise RuntimeError("Resposta Anthropic truncada (stop_reason=max_tokens).")
    parsed = response.parsed_output
    if parsed is None:
        raise RuntimeError("Resposta Anthropic sem saída estruturada.")
    return parsed


def _call_openai(payload: dict[str, Any], settings: Settings) -> AuditReportOutput:
    import openai

    client = openai.OpenAI(api_key=settings.openai_api_key, timeout=settings.llm_timeout_seconds, max_retries=2)
    completion = client.chat.completions.create(
        model=settings.openai_model,
        response_format={"type": "json_object"},
        messages=[
            {
                "role": "system",
                "content": SYSTEM_PROMPT
                + "\n\nFormato obrigatório do JSON de saída:\n"
                + json.dumps(OUTPUT_SCHEMA_HINT, ensure_ascii=False),
            },
            {"role": "user", "content": _user_message(payload)},
        ],
    )
    content = completion.choices[0].message.content
    if not content:
        raise RuntimeError("Resposta OpenAI vazia.")
    return AuditReportOutput.model_validate_json(content)


def generate_audit_report(summary: NetworkAuditSummary, settings: Settings | None = None) -> AuditResult:
    """Gera o laudo IEC 62443. Nunca falha: erros do provedor caem no Modo Mock Inteligente."""
    settings = settings or get_settings()
    payload = build_llm_payload(summary)
    payload_bytes = llm_payload_size(payload)
    provider = settings.resolved_llm_provider

    if provider == "mock":
        return AuditResult(report=generate_mock_report(summary), provider="mock", llm_payload_bytes=payload_bytes)

    try:
        report = _call_anthropic(payload, settings) if provider == "anthropic" else _call_openai(payload, settings)
        return AuditResult(report=report, provider=provider, llm_payload_bytes=payload_bytes)
    except Exception as exc:
        logger.warning("Falha no provedor LLM %s (%s); usando Modo Mock Inteligente.", provider, type(exc).__name__)
        return AuditResult(report=generate_mock_report(summary), provider="mock-fallback", llm_payload_bytes=payload_bytes)
