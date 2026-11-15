"""Motor determinístico de dissecação passiva de tráfego OT (docs/01_PROTOCOL_PARSING_SPEC.md).

Lê arquivos .pcap/.pcapng em streaming com `PcapReader` (baixo consumo de RAM), extrai inventário
de ativos, inspeciona Modbus TCP / OPC UA byte a byte e detecta violações do Modelo Purdue.
Nunca transmite ou injeta pacotes: análise 100% offline.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

for _scapy_logger in ("scapy", "scapy.runtime", "scapy.loading"):
    logging.getLogger(_scapy_logger).setLevel(logging.ERROR)

from scapy.config import conf  # noqa: E402  (logger silenciado antes do import do scapy)
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Packet
from scapy.utils import PcapReader

from app.models.schemas import (
    AssetInventoryItem,
    CaptureMetadata,
    DeterministicFinding,
    FindingCategory,
    FindingSeverity,
    InferredRole,
    ModbusAnalysis,
    ModbusSlaveProfile,
    NetworkAuditSummary,
    OpcUaChannel,
    OpcUaPolicyRisk,
    SecurityFlags,
)

conf.verb = 0

# ---------------------------------------------------------------------------
# Constantes de protocolo
# ---------------------------------------------------------------------------

MODBUS_PORT = 502
MODBUS_TLS_PORT = 802
OPCUA_PORTS: frozenset[int] = frozenset({4840})

KNOWN_TCP_SERVICES: dict[int, str] = {
    502: "ModbusTCP",
    802: "ModbusTLS",
    4840: "OPCUA",
    4843: "OPCUA-TLS",
    102: "S7comm",
    44818: "EtherNet/IP",
    20000: "DNP3",
    2404: "IEC-104",
    445: "SMB",
    139: "NetBIOS-SSN",
    135: "MSRPC",
    3389: "RDP",
    5900: "VNC",
    23: "Telnet",
    21: "FTP",
    22: "SSH",
    80: "HTTP",
    443: "HTTPS",
    53: "DNS",
}
KNOWN_UDP_SERVICES: dict[int, str] = {
    161: "SNMP",
    162: "SNMP-Trap",
    53: "DNS",
    123: "NTP",
    69: "TFTP",
    47808: "BACnet",
    2222: "EtherNet/IP-IO",
    44818: "EtherNet/IP",
    20000: "DNP3",
}

INDUSTRIAL_SERVER_PORTS: frozenset[int] = frozenset({502, 802, 4840, 4843, 102, 44818, 20000, 2404, 47808, 2222})
IT_MANAGEMENT_PORTS: frozenset[int] = frozenset({21, 22, 23, 80, 135, 139, 161, 443, 445, 3389, 5900})
LEGACY_ICS_SERVICES: frozenset[str] = frozenset({"S7comm", "EtherNet/IP", "EtherNet/IP-IO", "DNP3", "IEC-104", "BACnet"})

LATERAL_MOVEMENT_PORTS: dict[int, str] = {445: "SMB", 3389: "RDP", 5900: "VNC"}
LEGACY_INSECURE_PORTS: dict[int, str] = {23: "Telnet", 21: "FTP", 80: "HTTP", 161: "SNMP v1/v2c"}

RFC1918_NETWORKS: tuple[ipaddress.IPv4Network, ...] = (
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
)

MODBUS_READ_FCS: frozenset[int] = frozenset({0x01, 0x02, 0x03, 0x04})
MODBUS_WRITE_FCS: frozenset[int] = frozenset({0x05, 0x06, 0x0F, 0x10})
MODBUS_DIAG_FCS: frozenset[int] = frozenset({0x08, 0x11, 0x2B})
MODBUS_FC_NAMES: dict[int, str] = {
    0x01: "Read Coils",
    0x02: "Read Discrete Inputs",
    0x03: "Read Holding Registers",
    0x04: "Read Input Registers",
    0x05: "Write Single Coil",
    0x06: "Write Single Register",
    0x08: "Diagnostics",
    0x0F: "Write Multiple Coils",
    0x10: "Write Multiple Registers",
    0x11: "Report Server ID",
    0x17: "Read/Write Multiple Registers",
    0x2B: "Read Device Identification (MEI)",
}

OPCUA_POLICY_PREFIX = "http://opcfoundation.org/UA/SecurityPolicy#"
OPCUA_POLICY_REGEX = re.compile(rb"http://opcfoundation\.org/UA/SecurityPolicy#([A-Za-z0-9_]+)")
OPCUA_CRITICAL_POLICIES: frozenset[str] = frozenset({"None"})
OPCUA_DEPRECATED_POLICIES: frozenset[str] = frozenset({"Basic128Rsa15", "Basic256"})
OPCUA_SECURE_POLICIES: frozenset[str] = frozenset({"Basic256Sha256", "Aes128_Sha256_RsaOaep", "Aes256_Sha256_RsaPss"})
OPCUA_MESSAGE_TYPES: frozenset[bytes] = frozenset({b"HEL", b"ACK", b"OPN", b"MSG", b"CLO", b"ERR", b"RHE"})

SEVERITY_ORDER: dict[str, int] = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

DEFAULT_MAX_PACKETS = 2_000_000
LLM_PAYLOAD_MAX_BYTES = 4096


class PcapAnalysisError(Exception):
    """Arquivo inválido, corrompido ou em formato não suportado."""


# ---------------------------------------------------------------------------
# Estado interno de agregação
# ---------------------------------------------------------------------------


@dataclass
class _AssetState:
    ip: str
    mac: str | None = None
    packets_sent: int = 0
    packets_received: int = 0
    open_ports: set[int] = field(default_factory=set)
    initiated_ports: set[int] = field(default_factory=set)
    services: set[str] = field(default_factory=set)


@dataclass
class _ModbusSlaveState:
    reads: Counter[str] = field(default_factory=Counter)
    writes: Counter[str] = field(default_factory=Counter)
    diags: Counter[str] = field(default_factory=Counter)
    requests: Counter[str] = field(default_factory=Counter)
    write_fcs: dict[str, set[int]] = field(default_factory=lambda: defaultdict(set))
    diag_fcs: dict[str, set[int]] = field(default_factory=lambda: defaultdict(set))
    responses_to: Counter[str] = field(default_factory=Counter)
    exceptions_to: Counter[str] = field(default_factory=Counter)
    exception_codes: Counter[int] = field(default_factory=Counter)


@dataclass(frozen=True)
class _Flow:
    client: str
    server: str
    port: int
    transport: str


@dataclass
class _AnalyzerState:
    total_packets: int = 0
    first_ts: float | None = None
    last_ts: float | None = None
    truncated: bool = False
    protocols: set[str] = field(default_factory=set)
    assets: dict[str, _AssetState] = field(default_factory=dict)
    flows: Counter[_Flow] = field(default_factory=Counter)
    conversations: set[tuple[str, str]] = field(default_factory=set)
    modbus_slaves: dict[str, _ModbusSlaveState] = field(default_factory=lambda: defaultdict(_ModbusSlaveState))
    modbus_fc_histogram: Counter[str] = field(default_factory=Counter)
    modbus_requests: int = 0
    modbus_responses: int = 0
    modbus_exceptions: int = 0
    modbus_tls_servers: set[str] = field(default_factory=set)
    opcua_channels: dict[tuple[str, str, int], str] = field(default_factory=dict)
    snmp_insecure_flows: set[_Flow] = field(default_factory=set)

    def asset(self, ip: str) -> _AssetState:
        state = self.assets.get(ip)
        if state is None:
            state = _AssetState(ip=ip)
            self.assets[ip] = state
        return state


# ---------------------------------------------------------------------------
# Helpers de endereçamento
# ---------------------------------------------------------------------------


def is_rfc1918(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return isinstance(addr, ipaddress.IPv4Address) and any(addr in net for net in RFC1918_NETWORKS)


def is_public_ip(ip: str) -> bool:
    """IP roteável na Internet: fora da RFC 1918 e não especial (loopback, multicast, link-local...)."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if addr.is_multicast or addr.is_loopback or addr.is_link_local or addr.is_unspecified or addr.is_reserved:
        return False
    if isinstance(addr, ipaddress.IPv4Address):
        if addr == ipaddress.IPv4Address("255.255.255.255"):
            return False
        return not any(addr in net for net in RFC1918_NETWORKS)
    return addr.is_global


def _is_trackable_host(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if addr.is_multicast or addr.is_unspecified or addr.is_loopback:
        return False
    if isinstance(addr, ipaddress.IPv4Address):
        return addr != ipaddress.IPv4Address("255.255.255.255") and not str(addr).endswith(".255")
    return True


def _plural(count: int, singular: str, plural: str) -> str:
    """Concordância numérica em PT-BR nas evidências ("1 escrita", "2 escritas")."""
    return f"{count} {singular if count == 1 else plural}"


def _fc_label(fc: int) -> str:
    return f"0x{fc:02X} ({MODBUS_FC_NAMES.get(fc, 'Função não padronizada')})"


def _fmt_hosts(counter: Counter[str], unit: str) -> str:
    return ", ".join(f"{ip} ({n} {unit})" for ip, n in counter.most_common())


# ---------------------------------------------------------------------------
# Dissectores de payload
# ---------------------------------------------------------------------------


def parse_modbus_adus(payload: bytes) -> list[tuple[int, int, int]]:
    """Extrai (transaction_id, unit_id, function_code) de um ou mais ADUs Modbus TCP no segmento.

    MBAP: bytes 0..1 TransactionId, 2..3 ProtocolId (0x0000), 4..5 Length, 6 UnitId, 7 FunctionCode.
    """
    adus: list[tuple[int, int, int]] = []
    offset = 0
    while len(payload) - offset >= 8:
        transaction_id = int.from_bytes(payload[offset : offset + 2], "big")
        protocol_id = int.from_bytes(payload[offset + 2 : offset + 4], "big")
        length = int.from_bytes(payload[offset + 4 : offset + 6], "big")
        if protocol_id != 0x0000 or length < 2 or length > 254:
            break
        unit_id = payload[offset + 6]
        function_code = payload[offset + 7]
        adus.append((transaction_id, unit_id, function_code))
        offset += 6 + length
    return adus


def parse_opcua_security_policy(payload: bytes) -> str | None:
    """Retorna o nome da SecurityPolicy de uma mensagem OPN (OpenSecureChannel), ou None.

    Layout: MessageType(3) ChunkType(1) MessageSize(4) SecureChannelId(4) SecurityPolicyUri(UA String).
    """
    if len(payload) < 16 or payload[:3] != b"OPN":
        return None
    uri_len = int.from_bytes(payload[12:16], "little", signed=True)
    if 0 < uri_len <= 256 and len(payload) >= 16 + uri_len:
        uri = payload[16 : 16 + uri_len].decode("ascii", errors="replace")
        if uri.startswith(OPCUA_POLICY_PREFIX):
            return uri[len(OPCUA_POLICY_PREFIX) :]
    match = OPCUA_POLICY_REGEX.search(payload)
    return match.group(1).decode("ascii") if match else None


def classify_opcua_policy(policy: str) -> OpcUaPolicyRisk:
    if policy in OPCUA_CRITICAL_POLICIES:
        return "CRITICAL"
    if policy in OPCUA_DEPRECATED_POLICIES:
        return "DEPRECATED"
    if policy in OPCUA_SECURE_POLICIES:
        return "SECURE"
    return "UNKNOWN"


def _looks_like_opcua(payload: bytes) -> bool:
    if len(payload) < 8 or payload[:3] not in OPCUA_MESSAGE_TYPES or payload[3:4] not in (b"F", b"C", b"A"):
        return False
    return int.from_bytes(payload[4:8], "little") == len(payload)


def parse_snmp_version(payload: bytes) -> int | None:
    """Lê a versão SNMP do cabeçalho BER (0 = v1, 1 = v2c, 3 = v3)."""
    if len(payload) < 5 or payload[0] != 0x30:
        return None
    idx = 2
    if payload[1] & 0x80:
        idx = 2 + (payload[1] & 0x7F)
    if len(payload) < idx + 3 or payload[idx] != 0x02 or payload[idx + 1] != 0x01:
        return None
    return payload[idx + 2]


# ---------------------------------------------------------------------------
# Processamento por pacote
# ---------------------------------------------------------------------------


def _process_packet(pkt: Packet, state: _AnalyzerState) -> None:
    src_mac: str | None = pkt[Ether].src.upper() if pkt.haslayer(Ether) else None

    if pkt.haslayer(ARP):
        state.protocols.add("ARP")
        arp = pkt[ARP]
        if arp.psrc and _is_trackable_host(arp.psrc) and is_rfc1918(arp.psrc) and arp.psrc != "0.0.0.0":
            asset = state.asset(arp.psrc)
            asset.mac = asset.mac or str(arp.hwsrc).upper()
        return

    if pkt.haslayer(IP):
        ip_layer = pkt[IP]
    elif pkt.haslayer(IPv6):
        ip_layer = pkt[IPv6]
    else:
        state.protocols.add("L2-Other")
        return

    src: str = ip_layer.src
    dst: str = ip_layer.dst
    src_ok = _is_trackable_host(src)
    dst_ok = _is_trackable_host(dst)
    if src_ok:
        sender = state.asset(src)
        sender.packets_sent += 1
        if src_mac and not sender.mac and not is_public_ip(src):
            sender.mac = src_mac
    if dst_ok:
        state.asset(dst).packets_received += 1
    if src_ok and dst_ok:
        state.conversations.add((src, dst) if src < dst else (dst, src))

    if pkt.haslayer(TCP):
        _process_tcp(pkt[TCP], src, dst, src_ok, dst_ok, state)
    elif pkt.haslayer(UDP):
        _process_udp(pkt[UDP], src, dst, src_ok, dst_ok, state)
    elif pkt.haslayer(ICMP):
        state.protocols.add("ICMP")
    else:
        state.protocols.add("IP-Other")


def _register_flow(
    state: _AnalyzerState,
    client: str,
    server: str,
    port: int,
    transport: str,
    service: str,
    client_ok: bool,
    server_ok: bool,
) -> _Flow:
    flow = _Flow(client=client, server=server, port=port, transport=transport)
    state.flows[flow] += 1
    state.protocols.add(service)
    if server_ok:
        srv = state.asset(server)
        srv.open_ports.add(port)
        srv.services.add(service)
    if client_ok:
        cli = state.asset(client)
        cli.initiated_ports.add(port)
        cli.services.add(service)
    return flow


def _process_tcp(tcp: TCP, src: str, dst: str, src_ok: bool, dst_ok: bool, state: _AnalyzerState) -> None:
    flags = int(tcp.flags)
    syn = bool(flags & 0x02)
    ack = bool(flags & 0x10)
    sport: int = int(tcp.sport)
    dport: int = int(tcp.dport)
    payload: bytes = bytes(tcp.payload)

    client: str | None = None
    server: str | None = None
    port: int | None = None
    if syn and not ack:
        client, server, port = src, dst, dport
    elif syn and ack:
        client, server, port = dst, src, sport
    elif dport in KNOWN_TCP_SERVICES:
        client, server, port = src, dst, dport
    elif sport in KNOWN_TCP_SERVICES:
        client, server, port = dst, src, sport

    if client is not None and server is not None and port is not None:
        service = KNOWN_TCP_SERVICES.get(port, f"TCP/{port}")
        c_ok, s_ok = (src_ok, dst_ok) if client == src else (dst_ok, src_ok)
        _register_flow(state, client, server, port, "tcp", service, c_ok, s_ok)
    else:
        state.protocols.add("TCP-Other")

    if not payload:
        return

    if MODBUS_PORT in (sport, dport):
        _inspect_modbus(payload, src, dst, is_request=dport == MODBUS_PORT, state=state)
    if MODBUS_TLS_PORT in (sport, dport):
        state.modbus_tls_servers.add(dst if dport == MODBUS_TLS_PORT else src)
    if sport in OPCUA_PORTS or dport in OPCUA_PORTS or _looks_like_opcua(payload):
        _inspect_opcua(payload, src, dst, sport, dport, state)


def _process_udp(udp: UDP, src: str, dst: str, src_ok: bool, dst_ok: bool, state: _AnalyzerState) -> None:
    sport: int = int(udp.sport)
    dport: int = int(udp.dport)
    if dport in KNOWN_UDP_SERVICES:
        client, server, port = src, dst, dport
        c_ok, s_ok = src_ok, dst_ok
    elif sport in KNOWN_UDP_SERVICES:
        client, server, port = dst, src, sport
        c_ok, s_ok = dst_ok, src_ok
    else:
        state.protocols.add("UDP-Other")
        return
    service = KNOWN_UDP_SERVICES[port]
    flow = _register_flow(state, client, server, port, "udp", service, c_ok, s_ok)
    if port == 161:
        version = parse_snmp_version(bytes(udp.payload))
        if version in (0, 1):
            state.snmp_insecure_flows.add(flow)


def _inspect_modbus(payload: bytes, src: str, dst: str, is_request: bool, state: _AnalyzerState) -> None:
    for _tid, _unit, fc in parse_modbus_adus(payload):
        if is_request:
            master, slave = src, dst
            slave_state = state.modbus_slaves[slave]
            state.modbus_requests += 1
            state.modbus_fc_histogram[f"0x{fc:02X}"] += 1
            slave_state.requests[master] += 1
            if fc in MODBUS_READ_FCS:
                slave_state.reads[master] += 1
            elif fc in MODBUS_WRITE_FCS:
                slave_state.writes[master] += 1
                slave_state.write_fcs[master].add(fc)
            elif fc in MODBUS_DIAG_FCS:
                slave_state.diags[master] += 1
                slave_state.diag_fcs[master].add(fc)
        else:
            slave, master = src, dst
            slave_state = state.modbus_slaves[slave]
            state.modbus_responses += 1
            slave_state.responses_to[master] += 1
            if fc >= 0x80:
                state.modbus_exceptions += 1
                state.modbus_fc_histogram[f"0x{fc:02X}"] += 1
                slave_state.exceptions_to[master] += 1
                slave_state.exception_codes[fc] += 1


def _inspect_opcua(payload: bytes, src: str, dst: str, sport: int, dport: int, state: _AnalyzerState) -> None:
    msg_type = payload[:3]
    if msg_type not in OPCUA_MESSAGE_TYPES:
        return
    state.protocols.add("OPCUA")
    if dport in OPCUA_PORTS or (sport not in OPCUA_PORTS and msg_type in (b"HEL", b"OPN")):
        client, server, port = src, dst, dport
    else:
        client, server, port = dst, src, sport
    key = (client, server, port)
    if msg_type == b"OPN":
        policy = parse_opcua_security_policy(payload)
        if policy:
            state.opcua_channels[key] = policy
            return
    state.opcua_channels.setdefault(key, "")


# ---------------------------------------------------------------------------
# Inferência de papéis e geração de findings
# ---------------------------------------------------------------------------


def _infer_role(asset: _AssetState) -> InferredRole:
    serves_ics = bool(asset.open_ports & INDUSTRIAL_SERVER_PORTS)
    initiates_ics = bool(asset.initiated_ports & INDUSTRIAL_SERVER_PORTS)
    initiates_it = bool(asset.initiated_ports & IT_MANAGEMENT_PORTS)
    if serves_ics:
        return "PLC / Field Slave"
    # Endereço roteável na Internet que não serve protocolo industrial: origem externa, nunca um mestre SCADA da planta.
    if is_public_ip(asset.ip):
        return "External Host"
    if initiates_ics and not initiates_it:
        return "HMI / SCADA Master"
    if initiates_ics or initiates_it or asset.open_ports & IT_MANAGEMENT_PORTS or len(asset.services) >= 3:
        return "Engineering Workstation / IT Host"
    return "Unknown"


def _finding(
    rule_id: str,
    severity: FindingSeverity,
    category: FindingCategory,
    title: str,
    evidence: str,
    affected: Iterable[str],
) -> DeterministicFinding:
    return DeterministicFinding(
        rule_id=rule_id,
        severity=severity,
        category=category,
        title=title,
        evidence=evidence,
        affected_assets=sorted(set(affected)),
    )


def _modbus_findings(state: _AnalyzerState, flags: SecurityFlags) -> tuple[list[DeterministicFinding], ModbusAnalysis | None]:
    if not state.modbus_slaves:
        return [], None

    findings: list[DeterministicFinding] = []
    profiles: list[ModbusSlaveProfile] = []

    for slave_ip in sorted(state.modbus_slaves):
        s = state.modbus_slaves[slave_ip]
        masters = set(s.requests)
        primary: str | None = None
        if s.reads:
            primary = s.reads.most_common(1)[0][0]
        elif s.requests:
            primary = s.requests.most_common(1)[0][0]
        writers = set(s.writes)

        profiles.append(
            ModbusSlaveProfile(
                slave_ip=slave_ip,
                masters=sorted(masters),
                writers=sorted(writers),
                primary_master=primary,
                read_requests=sum(s.reads.values()),
                write_requests=sum(s.writes.values()),
                diagnostic_requests=sum(s.diags.values()),
                exception_responses=sum(s.exceptions_to.values()),
            )
        )

        if len(writers) >= 2:
            detail = "; ".join(
                f"{w} enviou {_plural(s.writes[w], 'escrita', 'escritas')} [{', '.join(_fc_label(fc) for fc in sorted(s.write_fcs[w]))}]"
                for w in sorted(writers, key=lambda x: (-s.writes[x], x))
            )
            findings.append(
                _finding(
                    "OT-MODBUS-001",
                    "CRITICAL",
                    "MODBUS",
                    "Comandos de Escrita Modbus TCP a partir de Múltiplos Mestres",
                    f"O CLP {slave_ip} recebeu comandos de escrita de {len(writers)} origens distintas: {detail}. "
                    f"Mestre primário inferido (maior volume de leituras): {primary or 'indeterminado'}.",
                    # O mestre primário é citado na evidência, mas não é marcado como ativo comprometido.
                    [slave_ip, *sorted(writers - {primary})],
                )
            )
        elif len(writers) == 1 and primary is not None and next(iter(writers)) != primary:
            writer = next(iter(writers))
            findings.append(
                _finding(
                    "OT-MODBUS-002",
                    "HIGH",
                    "MODBUS",
                    "Escrita Modbus TCP a partir de Host Diferente do Mestre SCADA",
                    f"O CLP {slave_ip} recebeu {_plural(s.writes[writer], 'escrita', 'escritas')} "
                    f"[{', '.join(_fc_label(fc) for fc in sorted(s.write_fcs[writer]))}] de {writer}, "
                    f"enquanto o mestre de supervisão inferido é {primary}.",
                    [slave_ip, writer],
                )
            )
        elif len(masters) >= 2:
            findings.append(
                _finding(
                    "OT-MODBUS-006",
                    "MEDIUM",
                    "MODBUS",
                    "Múltiplos Mestres Modbus Consultando o Mesmo CLP",
                    f"O CLP {slave_ip} atende {len(masters)} mestres: {_fmt_hosts(s.requests, 'requisições')}.",
                    [slave_ip, *masters],
                )
            )

        if s.diags:
            detail = "; ".join(
                f"{m}: {_plural(s.diags[m], 'requisição', 'requisições')} [{', '.join(_fc_label(fc) for fc in sorted(s.diag_fcs[m]))}]"
                for m in sorted(s.diags, key=lambda x: (-s.diags[x], x))
            )
            findings.append(
                _finding(
                    "OT-MODBUS-003",
                    "CRITICAL",
                    "MODBUS",
                    "Reconhecimento / Enumeração Modbus via Function Codes de Diagnóstico",
                    f"O CLP {slave_ip} recebeu requisições de diagnóstico/identificação de dispositivo: {detail}.",
                    [slave_ip, *s.diags],
                )
            )

        for master, exc in s.exceptions_to.items():
            responses = s.responses_to[master]
            ratio = exc / responses if responses else 0.0
            codes = ", ".join(f"0x{c:02X}" for c in sorted(s.exception_codes))
            if exc >= 5 and ratio >= 0.3:
                findings.append(
                    _finding(
                        "OT-MODBUS-004",
                        "HIGH",
                        "MODBUS",
                        "Alta Taxa de Exceções Modbus (Possível Varredura de Registradores)",
                        f"{exc} de {responses} respostas ({ratio:.0%}) do CLP {slave_ip} para {master} foram exceções "
                        f"({codes}), padrão compatível com varredura de endereços de memória.",
                        [slave_ip, master],
                    )
                )
            elif exc > 0:
                findings.append(
                    _finding(
                        "OT-MODBUS-008",
                        "LOW",
                        "MODBUS",
                        "Respostas de Exceção Modbus Observadas",
                        f"{_plural(exc, 'exceção', 'exceções')} ({codes}) do CLP {slave_ip} para {master} em {responses} respostas "
                        f"({ratio:.0%}); verificar configuração do driver SCADA.",
                        [slave_ip, master],
                    )
                )

    flags.unencrypted_cleartext_protocol = True
    flags.lack_of_authentication = True
    slaves_list = sorted(state.modbus_slaves)
    findings.append(
        _finding(
            "OT-MODBUS-005",
            "HIGH",
            "MODBUS",
            "Modbus TCP em Texto Claro sem Autenticação",
            f"{state.modbus_requests} requisições Modbus TCP na porta 502 sem criptografia nem autenticação "
            f"(unencrypted_cleartext_protocol=True, lack_of_authentication=True). CLPs afetados: {', '.join(slaves_list)}.",
            slaves_list,
        )
    )

    if state.modbus_tls_servers:
        findings.append(
            _finding(
                "OT-MODBUS-007",
                "INFO",
                "MODBUS",
                "Modbus/TLS (porta 802) em Uso",
                f"Servidores com Modbus/TLS observados: {', '.join(sorted(state.modbus_tls_servers))}.",
                state.modbus_tls_servers,
            )
        )

    analysis = ModbusAnalysis(
        total_requests=state.modbus_requests,
        total_responses=state.modbus_responses,
        exception_responses=state.modbus_exceptions,
        function_code_histogram=dict(sorted(state.modbus_fc_histogram.items())),
        slaves=profiles,
    )
    return findings, analysis


def _opcua_findings(state: _AnalyzerState, flags: SecurityFlags) -> tuple[list[DeterministicFinding], list[OpcUaChannel]]:
    channels: list[OpcUaChannel] = []
    by_risk: dict[OpcUaPolicyRisk, list[OpcUaChannel]] = defaultdict(list)
    for (client, server, port), policy in sorted(state.opcua_channels.items()):
        policy_name = policy or "Não capturado (handshake OPN ausente)"
        risk: OpcUaPolicyRisk = classify_opcua_policy(policy) if policy else "UNKNOWN"
        channel = OpcUaChannel(
            client_ip=client, server_ip=server, server_port=port, security_policy=policy_name, policy_risk=risk
        )
        channels.append(channel)
        by_risk[risk].append(channel)

    def _describe(items: list[OpcUaChannel]) -> str:
        return "; ".join(f"{c.client_ip} -> {c.server_ip}:{c.server_port} (SecurityPolicy#{c.security_policy})" for c in items)

    def _hosts(items: list[OpcUaChannel]) -> list[str]:
        return [h for c in items for h in (c.client_ip, c.server_ip)]

    findings: list[DeterministicFinding] = []
    if by_risk.get("CRITICAL"):
        items = by_risk["CRITICAL"]
        flags.unencrypted_cleartext_protocol = True
        findings.append(
            _finding(
                "OT-OPCUA-001",
                "CRITICAL",
                "OPCUA",
                "Sessão OPC UA Negociada com SecurityPolicy#None",
                f"Canal(is) OpenSecureChannel sem assinatura nem criptografia: {_describe(items)}.",
                _hosts(items),
            )
        )
    if by_risk.get("DEPRECATED"):
        items = by_risk["DEPRECATED"]
        findings.append(
            _finding(
                "OT-OPCUA-002",
                "MEDIUM",
                "OPCUA",
                "Política Criptográfica OPC UA Depreciada",
                f"Políticas depreciadas pela OPC Foundation (SHA-1/RSA-PKCS#1 v1.5) em uso: {_describe(items)}.",
                _hosts(items),
            )
        )
    if by_risk.get("UNKNOWN"):
        items = by_risk["UNKNOWN"]
        findings.append(
            _finding(
                "OT-OPCUA-004",
                "LOW",
                "OPCUA",
                "Canal OPC UA com Política de Segurança Não Determinada",
                f"Tráfego OPC UA sem mensagem OPN legível na captura: {_describe(items)}.",
                _hosts(items),
            )
        )
    if by_risk.get("SECURE"):
        items = by_risk["SECURE"]
        findings.append(
            _finding(
                "OT-OPCUA-003",
                "INFO",
                "OPCUA",
                "Canal OPC UA com Política Criptográfica Segura",
                f"Políticas recomendadas em uso: {_describe(items)}.",
                _hosts(items),
            )
        )
    return findings, channels


def _purdue_findings(
    state: _AnalyzerState, roles: dict[str, InferredRole], flags: SecurityFlags
) -> list[DeterministicFinding]:
    plcs = {ip for ip, role in roles.items() if role == "PLC / Field Slave"}
    masters = {ip for ip, role in roles.items() if role == "HMI / SCADA Master"}
    control_subnets: set[ipaddress.IPv4Network] = set()
    for plc in plcs:
        try:
            addr = ipaddress.ip_address(plc)
        except ValueError:
            continue
        if isinstance(addr, ipaddress.IPv4Address):
            control_subnets.add(ipaddress.IPv4Network(f"{plc}/24", strict=False))

    def in_control_segment(ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return isinstance(addr, ipaddress.IPv4Address) and any(addr in net for net in control_subnets)

    findings: list[DeterministicFinding] = []
    lateral: dict[str, list[tuple[_Flow, FindingSeverity]]] = defaultdict(list)
    legacy: dict[str, list[tuple[_Flow, FindingSeverity]]] = defaultdict(list)

    for flow in state.flows:
        involves_plc = flow.client in plcs or flow.server in plcs
        in_control = in_control_segment(flow.client) or in_control_segment(flow.server)
        if not (involves_plc or in_control):
            continue
        if flow.transport == "tcp" and flow.port in LATERAL_MOVEMENT_PORTS:
            sev: FindingSeverity = "CRITICAL" if involves_plc else "HIGH"
            lateral[LATERAL_MOVEMENT_PORTS[flow.port]].append((flow, sev))
        elif (flow.transport == "tcp" and flow.port in (21, 23, 80)) or (
            flow.transport == "udp" and flow.port == 161 and flow in state.snmp_insecure_flows
        ):
            name = LEGACY_INSECURE_PORTS[flow.port]
            if involves_plc:
                sev = "CRITICAL" if flow.port in (21, 23) else "HIGH"
            else:
                sev = "MEDIUM"
            legacy[name].append((flow, sev))

    def _emit(rule_id: str, groups: dict[str, list[tuple[_Flow, FindingSeverity]]], title_tpl: str, why: str) -> None:
        for service, items in sorted(groups.items()):
            worst = min((sev for _, sev in items), key=lambda s: SEVERITY_ORDER[s])
            flows_desc = "; ".join(
                f"{f.client} -> {f.server}:{f.port}/{f.transport} ({state.flows[f]} pkts)"
                + (" [alvo é CLP]" if f.server in plcs or f.client in plcs else "")
                for f, _ in sorted(items, key=lambda x: (SEVERITY_ORDER[x[1]], -state.flows[x[0]]))[:5]
            )
            findings.append(
                _finding(
                    rule_id,
                    worst,
                    "PURDUE",
                    title_tpl.format(service=service),
                    f"{why} Fluxos no segmento de controle: {flows_desc}.",
                    [h for f, _ in items for h in (f.client, f.server)],
                )
            )

    _emit(
        "OT-PURDUE-001",
        lateral,
        "Vetor de Movimentação Lateral de TI ({service}) na Rede de Controle",
        "Protocolo de TI corporativa trafegando no mesmo segmento dos CLPs (violação de zonas e conduítes IEC 62443-3-2).",
    )
    _emit(
        "OT-PURDUE-002",
        legacy,
        "Protocolo Legado Inseguro ({service}) no Segmento OT",
        "Protocolo em texto claro com credenciais expostas trafegando no segmento de controle.",
    )
    if lateral or legacy:
        flags.it_ot_convergence_detected = True
        flags.unencrypted_cleartext_protocol = flags.unencrypted_cleartext_protocol or bool(legacy)

    exposed_plc: list[tuple[str, str]] = []
    exposed_master: list[tuple[str, str]] = []
    for a, b in state.conversations:
        for internal, external in ((a, b), (b, a)):
            if not is_public_ip(external):
                continue
            if internal in plcs:
                exposed_plc.append((internal, external))
            elif internal in masters:
                exposed_master.append((internal, external))
    if exposed_plc:
        flags.external_exposure_detected = True
        findings.append(
            _finding(
                "OT-EXPOSURE-001",
                "CRITICAL",
                "EXPOSURE",
                "CLP Comunicando Diretamente com IP Público (Exposição Externa)",
                "Conversas entre ativos de campo e endereços fora da RFC 1918: "
                + "; ".join(f"CLP {i} <-> {e}" for i, e in sorted(exposed_plc)[:6])
                + ".",
                [h for pair in exposed_plc for h in pair],
            )
        )
    if exposed_master:
        flags.external_exposure_detected = True
        findings.append(
            _finding(
                "OT-EXPOSURE-002",
                "HIGH",
                "EXPOSURE",
                "Estação SCADA/HMI Comunicando com IP Público",
                "Conversas entre mestres SCADA e endereços fora da RFC 1918: "
                + "; ".join(f"{i} <-> {e}" for i, e in sorted(exposed_master)[:6])
                + ".",
                [h for pair in exposed_master for h in pair],
            )
        )
    return findings


def _ics_protocol_findings(state: _AnalyzerState, flags: SecurityFlags) -> list[DeterministicFinding]:
    servers: dict[str, set[str]] = defaultdict(set)
    for flow in state.flows:
        service = (KNOWN_TCP_SERVICES if flow.transport == "tcp" else KNOWN_UDP_SERVICES).get(flow.port, "")
        if service in LEGACY_ICS_SERVICES:
            servers[service].add(flow.server)
    if not servers:
        return []
    flags.unencrypted_cleartext_protocol = True
    flags.lack_of_authentication = True
    desc = "; ".join(f"{svc}: {', '.join(sorted(hosts))}" for svc, hosts in sorted(servers.items()))
    return [
        _finding(
            "OT-ICS-001",
            "MEDIUM",
            "ICS_PROTOCOL",
            "Protocolos Industriais Legados sem Autenticação Nativa",
            f"Protocolos de automação sem criptografia/autenticação de mensagens observados: {desc}.",
            [h for hosts in servers.values() for h in hosts],
        )
    ]


# ---------------------------------------------------------------------------
# API pública
# ---------------------------------------------------------------------------


def _consume_packets(reader: Iterable[Packet], state: _AnalyzerState, max_packets: int) -> None:
    """Percorre a captura em streaming; capturas truncadas são analisadas até o último pacote íntegro."""
    try:
        for pkt in reader:
            if state.total_packets >= max_packets:
                state.truncated = True
                break
            state.total_packets += 1
            ts = float(pkt.time)
            if state.first_ts is None or ts < state.first_ts:
                state.first_ts = ts
            if state.last_ts is None or ts > state.last_ts:
                state.last_ts = ts
            try:
                _process_packet(pkt, state)
            except (IndexError, ValueError, TypeError, AttributeError):
                state.protocols.add("Malformed")
    except EOFError:
        state.protocols.add("Truncated-Capture")
    except Exception as exc:
        if state.total_packets == 0:
            raise PcapAnalysisError("Falha ao ler pacotes da captura.") from exc
        state.protocols.add("Truncated-Capture")


def analyze_pcap(file_path: str | Path, max_packets: int = DEFAULT_MAX_PACKETS) -> NetworkAuditSummary:
    """Analisa passivamente um .pcap/.pcapng e retorna o resumo determinístico."""
    path = Path(file_path)
    if not path.is_file():
        raise PcapAnalysisError(f"Arquivo não encontrado: {path.name}")

    state = _AnalyzerState()
    # O handle é nosso (e não do Scapy) para que o arquivo seja SEMPRE fechado, mesmo quando o cabeçalho é
    # inválido; caso contrário o arquivo temporário não pode ser removido (Windows) e o descritor vaza.
    with path.open("rb") as handle:
        try:
            reader = PcapReader(handle)
        except Exception as exc:  # scapy levanta Scapy_Exception/struct.error para formatos inválidos
            raise PcapAnalysisError("Arquivo não é um PCAP/PCAPNG válido.") from exc
        _consume_packets(reader, state, max_packets)

    if state.total_packets == 0:
        raise PcapAnalysisError("Captura vazia: nenhum pacote encontrado.")

    roles: dict[str, InferredRole] = {ip: _infer_role(a) for ip, a in state.assets.items()}
    flags = SecurityFlags()

    modbus_findings, modbus_analysis = _modbus_findings(state, flags)
    opcua_findings, opcua_channels = _opcua_findings(state, flags)
    findings = [
        *modbus_findings,
        *opcua_findings,
        *_purdue_findings(state, roles, flags),
        *_ics_protocol_findings(state, flags),
    ]
    findings.sort(key=lambda f: (SEVERITY_ORDER[f.severity], f.rule_id))

    role_priority = {
        "PLC / Field Slave": 0,
        "HMI / SCADA Master": 1,
        "Engineering Workstation / IT Host": 2,
        "External Host": 3,
        "Unknown": 4,
    }
    assets = sorted(
        (
            AssetInventoryItem(
                ip=a.ip,
                mac=a.mac,
                inferred_role=roles[a.ip],
                open_ports=sorted(a.open_ports),
                packets_sent=a.packets_sent,
                packets_received=a.packets_received,
                protocols=sorted(a.services),
            )
            for a in state.assets.values()
        ),
        key=lambda x: (role_priority[x.inferred_role], -(x.packets_sent + x.packets_received), x.ip),
    )

    first, last = state.first_ts or 0.0, state.last_ts or 0.0
    metadata = CaptureMetadata(
        total_packets=state.total_packets,
        duration_seconds=round(max(0.0, last - first), 3),
        protocols_detected=sorted(state.protocols),
        capture_start=datetime.fromtimestamp(first, tz=timezone.utc) if state.first_ts is not None else None,
        capture_end=datetime.fromtimestamp(last, tz=timezone.utc) if state.last_ts is not None else None,
        analysis_truncated=state.truncated,
    )
    return NetworkAuditSummary(
        capture_metadata=metadata,
        assets=assets,
        deterministic_findings=findings,
        modbus_analysis=modbus_analysis,
        opcua_channels=opcua_channels,
        security_flags=flags,
    )


def _truncate(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[: max(0, limit - 1)] + "…"


def _payload_size(payload: dict[str, Any]) -> int:
    return len(json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))


def build_llm_payload(summary: NetworkAuditSummary, max_bytes: int = LLM_PAYLOAD_MAX_BYTES) -> dict[str, Any]:
    """Comprime o resumo em um JSON estatístico <= max_bytes para envio ao LLM (sem payloads brutos)."""
    role_counts = Counter(a.inferred_role for a in summary.assets)
    ot_assets = [a for a in summary.assets if a.inferred_role != "Unknown"]

    def _build(max_assets: int, evidence_len: int, include_low: bool, max_slaves: int) -> dict[str, Any]:
        findings = [
            f for f in summary.deterministic_findings if include_low or f.severity in ("CRITICAL", "HIGH", "MEDIUM")
        ]
        payload: dict[str, Any] = {
            "capture": {
                "packets": summary.capture_metadata.total_packets,
                "duration_s": summary.capture_metadata.duration_seconds,
                "protocols": summary.capture_metadata.protocols_detected,
            },
            "flags": summary.security_flags.model_dump(),
            "asset_counts": dict(role_counts),
            "assets": [
                {"ip": a.ip, "role": a.inferred_role, "ports": a.open_ports[:8]} for a in ot_assets[:max_assets]
            ],
            "findings": [
                {"id": f.rule_id, "sev": f.severity, "title": f.title, "evidence": _truncate(f.evidence, evidence_len)}
                for f in findings
            ],
        }
        if summary.modbus_analysis:
            payload["modbus"] = {
                "req": summary.modbus_analysis.total_requests,
                "exc": summary.modbus_analysis.exception_responses,
                "fc": summary.modbus_analysis.function_code_histogram,
                "slaves": [
                    {"ip": s.slave_ip, "primary": s.primary_master, "writers": s.writers[:5], "diag": s.diagnostic_requests}
                    for s in summary.modbus_analysis.slaves[:max_slaves]
                ],
            }
        if summary.opcua_channels:
            payload["opcua"] = [
                {"c": c.client_ip, "s": f"{c.server_ip}:{c.server_port}", "policy": c.security_policy}
                for c in summary.opcua_channels[:6]
            ]
        return payload

    attempts: list[tuple[int, int, bool, int]] = [
        (20, 320, True, 8),
        (15, 240, True, 6),
        (12, 200, False, 5),
        (8, 160, False, 4),
        (6, 120, False, 3),
        (4, 90, False, 2),
        (2, 60, False, 1),
    ]
    payload: dict[str, Any] = {}
    for max_assets, evidence_len, include_low, max_slaves in attempts:
        payload = _build(max_assets, evidence_len, include_low, max_slaves)
        if _payload_size(payload) <= max_bytes:
            return payload

    while payload["findings"] and _payload_size(payload) > max_bytes:
        payload["findings"].pop()
    payload["assets"] = payload["assets"][:2] if _payload_size(payload) > max_bytes else payload["assets"]
    return payload


def llm_payload_size(payload: dict[str, Any]) -> int:
    return _payload_size(payload)
