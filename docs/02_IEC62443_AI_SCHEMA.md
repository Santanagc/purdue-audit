# Contratos de Dados (JSON Schema) e Prompt do Agente Auditor

## 1. JSON de Entrada para o LLM (`NetworkAuditSummary`)
Saída gerada pelo `pcap_analyzer.py` que será enviada ao modelo de IA:

```json
{
  "capture_metadata": {
    "total_packets": 14520,
    "duration_seconds": 312.5,
    "protocols_detected": ["ModbusTCP", "OPCUA", "SMB", "ARP"]
  },
  "assets": [
    {
      "ip": "192.168.10.10",
      "mac": "00:80:F4:0A:12:34",
      "inferred_role": "PLC / Field Slave",
      "open_ports": [502, 80]
    }
  ],
  "deterministic_findings": [
    {
      "rule_id": "OT-MODBUS-001",
      "severity": "CRITICAL",
      "title": "Comandos de Escrita Modbus TCP a partir de Múltiplos Mestres",
      "evidence": "O CLP 192.168.10.10 recebeu Function Code 0x06 (Write Single Register) do SCADA oficial (192.168.10.5) e também de um host desconhecido (192.168.10.99)."
    },
    {
      "rule_id": "OT-OPCUA-002",
      "severity": "HIGH",
      "title": "Sessão OPC UA negociada com SecurityPolicy#None",
      "evidence": "Conexão entre 192.168.10.5 e 192.168.10.20:4840 sem assinatura ou criptografia de canal."
    }
  ]
}
```

## 2. System Prompt do Agente Auditor (`ai_auditor.py`)

```text
Você é um Auditor Líder de Cibersegurança Industrial certificado em ISA/IEC 62443 e especialista em Automação e Controle (Redes OT, SCADA, CLPs, Modbus TCP e OPC UA).
Sua função é analisar o resumo estruturado de tráfego de rede (JSON) extraído de uma planta industrial e produzir um Laudo Técnico de Auditoria focado em Continuidade Operacional e Segurança Cibernética.

REGRAS DE RESPOSTA:
1. Responda EXCLUSIVAMENTE em formato JSON válido seguindo o schema `AuditReportOutput`.
2. Mapeie cada vulnerabilidade encontrada para os Requisitos Fundamentais (FR) da norma IEC 62443-3-3 (ex: SR 1.1 Identificação e Autenticação, SR 3.1 Integridade de Comunicação, SR 4.1 Confidencialidade, SR 5.1 Segmentação de Rede / Zonas e Conduítes).
3. Nas recomendações de mitigação, seja prático para engenheiros de automação: nunca sugira "desligar o CLP" ou "bloquear a porta 502 indiscriminadamente" (o que pararia a planta). Recomende regras de firewall industrial por IP/MAC (whitelisting de mestre único SCADA), bloqueio de Function Codes de escrita para IPs de supervisão read-only, ativação de políticas Basic256Sha256 com certificados X.509 no servidor OPC UA e criação de VLANs separando tráfego de TI (SMB/RDP) do Nível 1/2 do Modelo Purdue.
```

## 3. JSON de Saída do LLM (`AuditReportOutput` - Pydantic)
O LLM deve retornar exatamente esta estrutura para popular o Dashboard e o gerador de PDF:
- `overall_security_score` (int, 0 a 100)
- `risk_level` (Literal["BAIXO", "MÉDIO", "ALTO", "CRÍTICO"])
- `executive_summary` (str - 2 parágrafos focados em risco operacional e parada de planta)
- `purdue_segmentation_analysis` (str - análise de zonas e conduítes)
- `vulnerabilities` (List[VulnerabilityItem]):
  - `id` (str)
  - `title` (str)
  - `severity` (str)
  - `iec_62443_reference` (str - ex: "IEC 62443-3-3 SR 3.1")
  - `technical_evidence` (str)
  - `operational_impact` (str)
  - `remediation_steps` (List[str])