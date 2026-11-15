"""Contratos de dados Pydantic v2 (docs/02_IEC62443_AI_SCHEMA.md).

Fluxo: pcap_analyzer -> NetworkAuditSummary -> ai_auditor -> AuditReportOutput -> AuditResponse (API/Frontend).
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

InferredRole = Literal[
    "PLC / Field Slave",
    "HMI / SCADA Master",
    "Engineering Workstation / IT Host",
    "External Host",
    "Unknown",
]
FindingSeverity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
RiskLevel = Literal["BAIXO", "MÉDIO", "ALTO", "CRÍTICO"]
VulnSeverity = Literal["CRÍTICO", "ALTO", "MÉDIO", "BAIXO"]
FindingCategory = Literal["MODBUS", "OPCUA", "PURDUE", "ICS_PROTOCOL", "EXPOSURE"]
OpcUaPolicyRisk = Literal["CRITICAL", "DEPRECATED", "SECURE", "UNKNOWN"]

_SEVERITY_ALIASES: dict[str, VulnSeverity] = {
    "CRITICAL": "CRÍTICO",
    "CRITICO": "CRÍTICO",
    "CRÍTICO": "CRÍTICO",
    "HIGH": "ALTO",
    "ALTO": "ALTO",
    "MEDIUM": "MÉDIO",
    "MEDIO": "MÉDIO",
    "MÉDIO": "MÉDIO",
    "LOW": "BAIXO",
    "BAIXO": "BAIXO",
    "INFO": "BAIXO",
}


def normalize_severity(value: str) -> VulnSeverity:
    """Normaliza severidades em inglês/português (com ou sem acento) para o padrão do laudo."""
    key = value.strip().upper()
    if key not in _SEVERITY_ALIASES:
        raise ValueError(f"Severidade desconhecida: {value!r}")
    return _SEVERITY_ALIASES[key]


# ---------------------------------------------------------------------------
# Saída determinística do motor Scapy
# ---------------------------------------------------------------------------


class CaptureMetadata(BaseModel):
    total_packets: int = Field(ge=0)
    duration_seconds: float = Field(ge=0)
    protocols_detected: list[str]
    capture_start: datetime | None = None
    capture_end: datetime | None = None
    analysis_truncated: bool = False


class AssetInventoryItem(BaseModel):
    ip: str
    mac: str | None = None
    inferred_role: InferredRole
    open_ports: list[int] = Field(default_factory=list)
    packets_sent: int = Field(default=0, ge=0)
    packets_received: int = Field(default=0, ge=0)
    protocols: list[str] = Field(default_factory=list)


class DeterministicFinding(BaseModel):
    rule_id: str
    severity: FindingSeverity
    category: FindingCategory
    title: str
    evidence: str
    affected_assets: list[str] = Field(default_factory=list)


class ModbusSlaveProfile(BaseModel):
    slave_ip: str
    masters: list[str]
    writers: list[str]
    primary_master: str | None = None
    read_requests: int = Field(default=0, ge=0)
    write_requests: int = Field(default=0, ge=0)
    diagnostic_requests: int = Field(default=0, ge=0)
    exception_responses: int = Field(default=0, ge=0)


class ModbusAnalysis(BaseModel):
    total_requests: int = Field(ge=0)
    total_responses: int = Field(ge=0)
    exception_responses: int = Field(ge=0)
    function_code_histogram: dict[str, int]
    slaves: list[ModbusSlaveProfile]


class OpcUaChannel(BaseModel):
    client_ip: str
    server_ip: str
    server_port: int
    security_policy: str
    policy_risk: OpcUaPolicyRisk


class SecurityFlags(BaseModel):
    unencrypted_cleartext_protocol: bool = False
    lack_of_authentication: bool = False
    it_ot_convergence_detected: bool = False
    external_exposure_detected: bool = False


class NetworkAuditSummary(BaseModel):
    """Resumo estatístico enviado (compactado) ao LLM. Nunca contém payloads brutos."""

    capture_metadata: CaptureMetadata
    assets: list[AssetInventoryItem]
    deterministic_findings: list[DeterministicFinding]
    modbus_analysis: ModbusAnalysis | None = None
    opcua_channels: list[OpcUaChannel] = Field(default_factory=list)
    security_flags: SecurityFlags = Field(default_factory=SecurityFlags)


# ---------------------------------------------------------------------------
# Saída do Agente Auditor IEC 62443
# ---------------------------------------------------------------------------


class VulnerabilityItem(BaseModel):
    id: str
    title: str
    severity: VulnSeverity
    iec_62443_reference: str
    technical_evidence: str
    operational_impact: str
    remediation_steps: list[str]

    @field_validator("severity", mode="before")
    @classmethod
    def _normalize(cls, value: str) -> VulnSeverity:
        return normalize_severity(str(value))


class AuditReportOutput(BaseModel):
    overall_security_score: int = Field(ge=0, le=100)
    risk_level: RiskLevel
    executive_summary: str
    purdue_segmentation_analysis: str
    vulnerabilities: list[VulnerabilityItem]

    @field_validator("risk_level", mode="before")
    @classmethod
    def _normalize_risk(cls, value: str) -> RiskLevel:
        return normalize_severity(str(value))

    @field_validator("overall_security_score", mode="before")
    @classmethod
    def _clamp_score(cls, value: int | float | str) -> int:
        return max(0, min(100, int(round(float(value)))))


# ---------------------------------------------------------------------------
# Envelope da API
# ---------------------------------------------------------------------------


class AuditResponse(BaseModel):
    model_config = ConfigDict(protected_namespaces=())

    audit_id: str
    generated_at: datetime
    source: Literal["upload", "demo"]
    file_name: str
    ai_provider: Literal["anthropic", "openai", "mock", "mock-fallback"]
    processing_time_ms: int = Field(ge=0)
    llm_payload_bytes: int = Field(ge=0)
    report: AuditReportOutput
    network_summary: NetworkAuditSummary


class HealthResponse(BaseModel):
    status: Literal["ok"]
    version: str
    ai_provider: Literal["anthropic", "openai", "mock"]
    sample_pcap_available: bool
    max_upload_mb: int


class ErrorResponse(BaseModel):
    detail: str
