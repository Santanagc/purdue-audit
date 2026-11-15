/** Contratos espelhados de backend/app/models/schemas.py (Pydantic v2). */

export type InferredRole =
  | "PLC / Field Slave"
  | "HMI / SCADA Master"
  | "Engineering Workstation / IT Host"
  | "External Host"
  | "Unknown";

export type FindingSeverity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
export type RiskLevel = "BAIXO" | "MÉDIO" | "ALTO" | "CRÍTICO";
export type VulnSeverity = RiskLevel;
export type FindingCategory = "MODBUS" | "OPCUA" | "PURDUE" | "ICS_PROTOCOL" | "EXPOSURE";
export type OpcUaPolicyRisk = "CRITICAL" | "DEPRECATED" | "SECURE" | "UNKNOWN";
export type AiProvider = "anthropic" | "openai" | "mock" | "mock-fallback";

export interface CaptureMetadata {
  total_packets: number;
  duration_seconds: number;
  protocols_detected: string[];
  capture_start: string | null;
  capture_end: string | null;
  analysis_truncated: boolean;
}

export interface AssetInventoryItem {
  ip: string;
  mac: string | null;
  inferred_role: InferredRole;
  open_ports: number[];
  packets_sent: number;
  packets_received: number;
  protocols: string[];
}

export interface DeterministicFinding {
  rule_id: string;
  severity: FindingSeverity;
  category: FindingCategory;
  title: string;
  evidence: string;
  affected_assets: string[];
}

export interface ModbusSlaveProfile {
  slave_ip: string;
  masters: string[];
  writers: string[];
  primary_master: string | null;
  read_requests: number;
  write_requests: number;
  diagnostic_requests: number;
  exception_responses: number;
}

export interface ModbusAnalysis {
  total_requests: number;
  total_responses: number;
  exception_responses: number;
  function_code_histogram: Record<string, number>;
  slaves: ModbusSlaveProfile[];
}

export interface OpcUaChannel {
  client_ip: string;
  server_ip: string;
  server_port: number;
  security_policy: string;
  policy_risk: OpcUaPolicyRisk;
}

export interface SecurityFlags {
  unencrypted_cleartext_protocol: boolean;
  lack_of_authentication: boolean;
  it_ot_convergence_detected: boolean;
  external_exposure_detected: boolean;
}

export interface NetworkAuditSummary {
  capture_metadata: CaptureMetadata;
  assets: AssetInventoryItem[];
  deterministic_findings: DeterministicFinding[];
  modbus_analysis: ModbusAnalysis | null;
  opcua_channels: OpcUaChannel[];
  security_flags: SecurityFlags;
}

export interface VulnerabilityItem {
  id: string;
  title: string;
  severity: VulnSeverity;
  iec_62443_reference: string;
  technical_evidence: string;
  operational_impact: string;
  remediation_steps: string[];
}

export interface AuditReportOutput {
  overall_security_score: number;
  risk_level: RiskLevel;
  executive_summary: string;
  purdue_segmentation_analysis: string;
  vulnerabilities: VulnerabilityItem[];
}

export interface AuditResponse {
  audit_id: string;
  generated_at: string;
  source: "upload" | "demo";
  file_name: string;
  ai_provider: AiProvider;
  processing_time_ms: number;
  llm_payload_bytes: number;
  report: AuditReportOutput;
  network_summary: NetworkAuditSummary;
}

export interface HealthResponse {
  status: "ok";
  version: string;
  ai_provider: "anthropic" | "openai" | "mock";
  sample_pcap_available: boolean;
  max_upload_mb: number;
}
