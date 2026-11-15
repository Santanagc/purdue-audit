"""Validação do motor determinístico, do auditor IEC 62443 (modo mock) e da API stateless."""

from __future__ import annotations

import glob
import os
import struct
import tempfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.models.schemas import AuditReportOutput, NetworkAuditSummary
from app.services.ai_auditor import compute_security_score, generate_audit_report, generate_mock_report
from app.services.pcap_analyzer import (
    LLM_PAYLOAD_MAX_BYTES,
    PcapAnalysisError,
    analyze_pcap,
    build_llm_payload,
    classify_opcua_policy,
    is_public_ip,
    llm_payload_size,
    parse_modbus_adus,
    parse_opcua_security_policy,
    parse_snmp_version,
)
from app.utils.generate_sample_pcap import mbap, mb_write_multiple_registers_req, opcua_open_secure_channel

SCADA, PLC, ROGUE, OPCUA, EWS, FILESRV, PUBLIC = (
    "192.168.10.5",
    "192.168.10.10",
    "192.168.10.99",
    "192.168.10.20",
    "192.168.10.50",
    "192.168.10.60",
    "203.0.113.77",
)


def _rules(summary: NetworkAuditSummary) -> dict[str, list[str]]:
    rules: dict[str, list[str]] = {}
    for f in summary.deterministic_findings:
        rules.setdefault(f.rule_id, []).append(f.severity)
    return rules


# ---------------------------------------------------------------------------
# Dissectores unitários
# ---------------------------------------------------------------------------


def test_parse_modbus_multiple_adus_in_segment() -> None:
    payload = mbap(1, 1, struct.pack(">BHH", 0x03, 0, 10)) + mbap(2, 1, mb_write_multiple_registers_req(20, [1, 2]))
    assert parse_modbus_adus(payload) == [(1, 1, 0x03), (2, 1, 0x10)]


def test_parse_modbus_rejects_non_modbus_protocol_id() -> None:
    assert parse_modbus_adus(b"\x00\x01\x00\x05\x00\x06\x01\x03") == []


@pytest.mark.parametrize(
    ("policy", "risk"),
    [
        ("None", "CRITICAL"),
        ("Basic128Rsa15", "DEPRECATED"),
        ("Basic256", "DEPRECATED"),
        ("Basic256Sha256", "SECURE"),
        ("Aes128_Sha256_RsaOaep", "SECURE"),
    ],
)
def test_opcua_policy_parsing_and_classification(policy: str, risk: str) -> None:
    parsed = parse_opcua_security_policy(opcua_open_secure_channel(policy, 0, request=True))
    assert parsed == policy
    assert classify_opcua_policy(parsed) == risk


def test_snmp_version_detection() -> None:
    assert parse_snmp_version(b"\x30\x10\x02\x01\x01\x04\x06public") == 1
    assert parse_snmp_version(b"\x30\x10\x02\x01\x03") == 3
    assert parse_snmp_version(b"\x00\x01") is None


def test_public_ip_classification() -> None:
    assert is_public_ip("203.0.113.77")
    assert is_public_ip("8.8.8.8")
    assert not is_public_ip("192.168.10.10")
    assert not is_public_ip("172.20.0.1")
    assert not is_public_ip("224.0.0.1")


# ---------------------------------------------------------------------------
# Análise do PCAP sintético
# ---------------------------------------------------------------------------


def test_capture_metadata(summary: NetworkAuditSummary) -> None:
    meta = summary.capture_metadata
    assert meta.total_packets > 100
    assert meta.duration_seconds > 0
    assert {"ModbusTCP", "OPCUA", "SMB", "Telnet", "ARP"} <= set(meta.protocols_detected)
    assert not meta.analysis_truncated


def test_asset_inventory_roles_and_macs(summary: NetworkAuditSummary) -> None:
    assets = {a.ip: a for a in summary.assets}
    assert assets[PLC].inferred_role == "PLC / Field Slave"
    assert assets[PLC].mac == "00:80:F4:0A:12:34"
    assert 502 in assets[PLC].open_ports
    assert assets[OPCUA].inferred_role == "PLC / Field Slave"
    assert 4840 in assets[OPCUA].open_ports
    assert assets[SCADA].inferred_role == "HMI / SCADA Master"
    assert assets[ROGUE].inferred_role == "HMI / SCADA Master"
    assert assets[EWS].inferred_role == "Engineering Workstation / IT Host"
    assert assets[FILESRV].inferred_role == "Engineering Workstation / IT Host"
    assert assets[PUBLIC].inferred_role == "External Host"
    assert assets[PUBLIC].mac is None
    assert all(a.packets_sent + a.packets_received > 0 for a in summary.assets)


def test_modbus_multi_master_write_detected(summary: NetworkAuditSummary) -> None:
    finding = next(f for f in summary.deterministic_findings if f.rule_id == "OT-MODBUS-001")
    assert finding.severity == "CRITICAL"
    assert {PLC, ROGUE} <= set(finding.affected_assets)
    # O mestre primário legítimo aparece na evidência, mas não é marcado como ativo comprometido.
    assert SCADA not in finding.affected_assets and SCADA in finding.evidence
    assert "0x06" in finding.evidence and "0x10" in finding.evidence


def test_modbus_diagnostics_scan_and_cleartext(summary: NetworkAuditSummary) -> None:
    rules = _rules(summary)
    assert rules["OT-MODBUS-003"] == ["CRITICAL"]
    assert rules["OT-MODBUS-004"] == ["HIGH"]
    assert rules["OT-MODBUS-005"] == ["HIGH"]
    diag = next(f for f in summary.deterministic_findings if f.rule_id == "OT-MODBUS-003")
    assert "0x2B" in diag.evidence and ROGUE in diag.affected_assets

    modbus = summary.modbus_analysis
    assert modbus is not None
    slave = next(s for s in modbus.slaves if s.slave_ip == PLC)
    assert slave.primary_master == SCADA
    assert set(slave.writers) == {SCADA, ROGUE}
    assert slave.exception_responses == 6
    assert modbus.function_code_histogram["0x83"] == 6
    assert summary.security_flags.unencrypted_cleartext_protocol
    assert summary.security_flags.lack_of_authentication


def test_opcua_security_policy_none_detected(summary: NetworkAuditSummary) -> None:
    assert len(summary.opcua_channels) == 1
    channel = summary.opcua_channels[0]
    assert (channel.client_ip, channel.server_ip, channel.server_port) == (SCADA, OPCUA, 4840)
    assert channel.security_policy == "None" and channel.policy_risk == "CRITICAL"
    assert _rules(summary)["OT-OPCUA-001"] == ["CRITICAL"]


def test_purdue_violations_detected(summary: NetworkAuditSummary) -> None:
    by_title = {f.title: f for f in summary.deterministic_findings if f.category == "PURDUE"}
    smb = next(f for t, f in by_title.items() if "SMB" in t)
    telnet = next(f for t, f in by_title.items() if "Telnet" in t)
    snmp = next(f for t, f in by_title.items() if "SNMP" in t)
    assert smb.rule_id == "OT-PURDUE-001" and smb.severity == "HIGH"
    assert telnet.rule_id == "OT-PURDUE-002" and telnet.severity == "CRITICAL"
    assert snmp.severity == "HIGH"
    assert summary.security_flags.it_ot_convergence_detected


def test_external_exposure_detected(summary: NetworkAuditSummary) -> None:
    exposure = next(f for f in summary.deterministic_findings if f.rule_id == "OT-EXPOSURE-001")
    assert exposure.severity == "CRITICAL" and PUBLIC in exposure.affected_assets
    assert summary.security_flags.external_exposure_detected


def test_findings_sorted_by_severity(summary: NetworkAuditSummary) -> None:
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    ranks = [order[f.severity] for f in summary.deterministic_findings]
    assert ranks == sorted(ranks)


def test_llm_payload_is_compact(summary: NetworkAuditSummary) -> None:
    payload = build_llm_payload(summary)
    assert llm_payload_size(payload) <= LLM_PAYLOAD_MAX_BYTES
    assert payload["findings"] and payload["flags"]["external_exposure_detected"]


def test_invalid_file_raises(tmp_path: Path) -> None:
    bogus = tmp_path / "bogus.pcap"
    bogus.write_bytes(b"not a pcap file at all")
    with pytest.raises(PcapAnalysisError):
        analyze_pcap(bogus)


# ---------------------------------------------------------------------------
# Auditor IEC 62443 (Modo Mock Inteligente)
# ---------------------------------------------------------------------------


def test_mock_report_is_rich_and_consistent(summary: NetworkAuditSummary) -> None:
    report = generate_mock_report(summary)
    assert isinstance(report, AuditReportOutput)
    assert report.risk_level == "CRÍTICO"
    assert 0 <= report.overall_security_score < 40
    assert report.overall_security_score == compute_security_score(summary.deterministic_findings)
    assert report.executive_summary.count("\n\n") == 1
    assert PLC in report.purdue_segmentation_analysis
    ids = [v.id for v in report.vulnerabilities]
    assert len(ids) == len(set(ids))
    assert {"OT-MODBUS-001", "OT-OPCUA-001", "OT-PURDUE-001", "OT-EXPOSURE-001"} <= set(ids)
    for vuln in report.vulnerabilities:
        assert vuln.iec_62443_reference.startswith("IEC 62443-3-3 SR")
        assert len(vuln.remediation_steps) >= 3
        assert vuln.severity in {"CRÍTICO", "ALTO", "MÉDIO", "BAIXO"}
        assert "desligar o CLP" not in " ".join(vuln.remediation_steps).lower()


def test_generate_audit_report_uses_mock_without_keys(summary: NetworkAuditSummary) -> None:
    result = generate_audit_report(summary)
    assert result.provider == "mock"
    assert 0 < result.llm_payload_bytes <= LLM_PAYLOAD_MAX_BYTES


def test_clean_capture_scores_high() -> None:
    empty = NetworkAuditSummary.model_validate(
        {
            "capture_metadata": {"total_packets": 10, "duration_seconds": 1.0, "protocols_detected": ["ARP"]},
            "assets": [],
            "deterministic_findings": [],
        }
    )
    report = generate_mock_report(empty)
    assert report.overall_security_score == 100 and report.risk_level == "BAIXO"
    assert report.vulnerabilities == []


# ---------------------------------------------------------------------------
# API FastAPI (stateless)
# ---------------------------------------------------------------------------


@pytest.fixture()
def client() -> TestClient:
    return TestClient(app)


def _leftover_temp_files() -> set[str]:
    return set(glob.glob(os.path.join(tempfile.gettempdir(), "purdueaudit_*")))


def test_health(client: TestClient) -> None:
    body = client.get("/api/v1/health").json()
    assert body["status"] == "ok" and body["ai_provider"] == "mock"


def test_demo_endpoint(client: TestClient, sample_pcap: Path) -> None:
    response = client.post("/api/v1/audit/demo")
    assert response.status_code == 200
    body = response.json()
    assert body["source"] == "demo" and body["ai_provider"] == "mock"
    assert body["report"]["risk_level"] == "CRÍTICO"
    assert len(body["network_summary"]["assets"]) == 7


def test_upload_endpoint_is_stateless(client: TestClient, sample_pcap: Path) -> None:
    before = _leftover_temp_files()
    with sample_pcap.open("rb") as handle:
        response = client.post(
            "/api/v1/audit/upload", files={"file": ("planta.pcap", handle, "application/vnd.tcpdump.pcap")}
        )
    assert response.status_code == 200
    body = response.json()
    assert body["source"] == "upload" and body["file_name"] == "planta.pcap"
    assert any(f["rule_id"] == "OT-MODBUS-001" for f in body["network_summary"]["deterministic_findings"])
    assert _leftover_temp_files() == before


def test_upload_rejects_bad_extension(client: TestClient) -> None:
    response = client.post("/api/v1/audit/upload", files={"file": ("x.txt", b"hello", "text/plain")})
    assert response.status_code == 400


def test_upload_rejects_bad_magic_and_cleans_up(client: TestClient) -> None:
    before = _leftover_temp_files()
    response = client.post("/api/v1/audit/upload", files={"file": ("fake.pcap", b"\x00" * 64, "application/octet-stream")})
    assert response.status_code == 400
    assert _leftover_temp_files() == before


def test_upload_corrupt_pcap_returns_422_and_cleans_up(client: TestClient) -> None:
    before = _leftover_temp_files()
    truncated = b"\xd4\xc3\xb2\xa1\x02\x00"
    response = client.post("/api/v1/audit/upload", files={"file": ("cortado.pcap", truncated, "application/octet-stream")})
    assert response.status_code == 422
    assert _leftover_temp_files() == before


def test_upload_garbage_after_valid_header_returns_422(client: TestClient) -> None:
    before = _leftover_temp_files()
    header = bytes.fromhex("d4c3b2a1" "02000400" "00000000" "00000000" "ffff0000" "01000000")  # pcap LE, linktype Ethernet
    garbage = header + bytes(range(256)) * 20
    response = client.post("/api/v1/audit/upload", files={"file": ("lixo.pcap", garbage, "application/octet-stream")})
    assert response.status_code == 422
    assert "Nenhum host IP" in response.json()["detail"]
    assert _leftover_temp_files() == before


def test_upload_size_limit_returns_413(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    from app import main

    monkeypatch.setattr(main.settings, "max_upload_mb", 1)
    before = _leftover_temp_files()
    big = b"\xd4\xc3\xb2\xa1" + b"\x00" * (1024 * 1024 + 16)
    response = client.post("/api/v1/audit/upload", files={"file": ("grande.pcap", big, "application/octet-stream")})
    assert response.status_code == 413
    assert _leftover_temp_files() == before


def test_security_headers_present(client: TestClient) -> None:
    response = client.get("/api/v1/health")
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert "default-src 'none'" in response.headers["Content-Security-Policy"]
    assert response.headers["Cache-Control"] == "no-store"


def test_rate_limiter_window() -> None:
    from app.security import SlidingWindowRateLimiter

    limiter = SlidingWindowRateLimiter(limit=2, window_seconds=60)
    assert limiter.allow("ip", now=0.0) and limiter.allow("ip", now=1.0)
    assert not limiter.allow("ip", now=2.0)
    assert limiter.allow("ip", now=61.5)
    assert limiter.allow("outro-ip", now=2.0)


def test_spoofed_forwarded_for_does_not_bypass_rate_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    """Entradas à esquerda do X-Forwarded-For são do cliente; o IP confiável é o último salto do proxy."""
    from app import main
    from app.security import SlidingWindowRateLimiter

    monkeypatch.setattr(main.settings, "trust_proxy_headers", True)
    monkeypatch.setattr(main.settings, "trusted_proxy_hops", 1)
    monkeypatch.setattr(main, "audit_limiter", SlidingWindowRateLimiter(limit=3))
    client = TestClient(main.app)
    codes = [
        client.post("/api/v1/audit/demo", headers={"X-Forwarded-For": f"10.0.0.{i}, 198.51.100.7"}).status_code
        for i in range(5)
    ]
    assert codes == [200, 200, 200, 429, 429]



def test_committed_demo_snapshot_matches_api_schema(tmp_path: Path) -> None:
    """O laudo pré-gerado do frontend deve seguir o contrato atual e ser reproduzível pelo exportador."""
    from app.models.schemas import AuditResponse
    from app.utils.export_demo_report import DEFAULT_OUTPUT, export_demo_report

    committed = AuditResponse.model_validate_json(DEFAULT_OUTPUT.read_text(encoding="utf-8"))
    fresh = AuditResponse.model_validate_json(export_demo_report(tmp_path / "demo.json").read_text(encoding="utf-8"))
    assert committed.source == "demo" and committed.ai_provider == "mock"
    assert committed.report == fresh.report
    assert committed.network_summary.deterministic_findings == fresh.network_summary.deterministic_findings
