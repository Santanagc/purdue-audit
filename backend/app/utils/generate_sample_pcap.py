"""Gerador de PCAP sintético de uma subestação/planta de laboratório (apenas grava arquivo, nunca transmite).

Cenário (sub-rede de controle 192.168.10.0/24):
- SCADA oficial 192.168.10.5 faz polling Modbus (FC 0x03/0x01) e escritas pontuais (0x06) no CLP 192.168.10.10:502.
- Host não mapeado 192.168.10.99 injeta escritas (0x06, 0x10), enumeração (0x2B, 0x11) e varre registradores
  inválidos gerando exceções (0x83).
- SCADA abre sessão OPC UA com 192.168.10.20:4840 negociando SecurityPolicy#None.
- Estação 192.168.10.50 abre SMB (445) com 192.168.10.60 e Telnet (23) direto no CLP.
- IP público 203.0.113.77 consulta o CLP via Modbus (exposição externa).

Uso: cd backend && python -m app.utils.generate_sample_pcap [caminho_saida]
"""

from __future__ import annotations

import struct
import sys
from dataclasses import dataclass, field
from pathlib import Path

from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Packet, Raw
from scapy.utils import wrpcap

from app.config import SAMPLE_PCAP_PATH

BASE_TIME = 1_731_600_000.0
GATEWAY_MAC = "00:1A:2B:3C:4D:01"

SCADA_IP, SCADA_MAC = "192.168.10.5", "00:0C:29:AA:00:05"
PLC_IP, PLC_MAC = "192.168.10.10", "00:80:F4:0A:12:34"
ROGUE_IP, ROGUE_MAC = "192.168.10.99", "00:0C:29:DE:AD:99"
OPCUA_IP, OPCUA_MAC = "192.168.10.20", "00:1B:1B:20:00:20"
EWS_IP, EWS_MAC = "192.168.10.50", "00:0C:29:EE:00:50"
FILESRV_IP, FILESRV_MAC = "192.168.10.60", "00:0C:29:FF:00:60"
PUBLIC_IP = "203.0.113.77"


@dataclass
class _Clock:
    now: float = BASE_TIME

    def tick(self, delta: float = 0.01) -> float:
        self.now += delta
        return self.now


@dataclass
class TcpSession:
    """Sessão TCP sintética com handshake e números de sequência coerentes."""

    client_ip: str
    client_mac: str
    server_ip: str
    server_mac: str
    sport: int
    dport: int
    clock: _Clock
    packets: list[Packet] = field(default_factory=list)
    c_seq: int = 1000
    s_seq: int = 5000

    def _emit(self, pkt: Packet, delta: float) -> None:
        pkt.time = self.clock.tick(delta)
        self.packets.append(pkt)

    def _c2s(self, flags: str, payload: bytes = b"") -> Packet:
        pkt = (
            Ether(src=self.client_mac, dst=self.server_mac)
            / IP(src=self.client_ip, dst=self.server_ip)
            / TCP(sport=self.sport, dport=self.dport, flags=flags, seq=self.c_seq, ack=self.s_seq)
        )
        return pkt / Raw(load=payload) if payload else pkt

    def _s2c(self, flags: str, payload: bytes = b"") -> Packet:
        pkt = (
            Ether(src=self.server_mac, dst=self.client_mac)
            / IP(src=self.server_ip, dst=self.client_ip)
            / TCP(sport=self.dport, dport=self.sport, flags=flags, seq=self.s_seq, ack=self.c_seq)
        )
        return pkt / Raw(load=payload) if payload else pkt

    def handshake(self) -> TcpSession:
        self._emit(self._c2s("S"), 0.05)
        self.c_seq += 1
        self._emit(self._s2c("SA"), 0.001)
        self.s_seq += 1
        self._emit(self._c2s("A"), 0.001)
        return self

    def client_send(self, payload: bytes, delta: float = 0.05) -> None:
        self._emit(self._c2s("PA", payload), delta)
        self.c_seq += len(payload)

    def server_send(self, payload: bytes, delta: float = 0.004) -> None:
        self._emit(self._s2c("PA", payload), delta)
        self.s_seq += len(payload)

    def close(self) -> None:
        self._emit(self._c2s("FA"), 0.01)
        self.c_seq += 1
        self._emit(self._s2c("FA"), 0.001)
        self.s_seq += 1
        self._emit(self._c2s("A"), 0.001)


# ---------------------------------------------------------------------------
# Construtores de PDU Modbus TCP (MBAP + PDU)
# ---------------------------------------------------------------------------


def mbap(transaction_id: int, unit_id: int, pdu: bytes) -> bytes:
    return struct.pack(">HHHB", transaction_id, 0x0000, len(pdu) + 1, unit_id) + pdu


def mb_read_req(fc: int, address: int, quantity: int) -> bytes:
    return struct.pack(">BHH", fc, address, quantity)


def mb_read_holding_resp(values: list[int]) -> bytes:
    return struct.pack(">BB", 0x03, len(values) * 2) + b"".join(struct.pack(">H", v) for v in values)


def mb_read_coils_resp(byte_values: bytes) -> bytes:
    return struct.pack(">BB", 0x01, len(byte_values)) + byte_values


def mb_write_single_register(address: int, value: int) -> bytes:
    return struct.pack(">BHH", 0x06, address, value)


def mb_write_multiple_registers_req(address: int, values: list[int]) -> bytes:
    body = b"".join(struct.pack(">H", v) for v in values)
    return struct.pack(">BHHB", 0x10, address, len(values), len(body)) + body


def mb_write_multiple_registers_resp(address: int, quantity: int) -> bytes:
    return struct.pack(">BHH", 0x10, address, quantity)


def mb_exception(fc: int, code: int) -> bytes:
    return struct.pack(">BB", fc | 0x80, code)


def mb_read_device_id_req() -> bytes:
    return struct.pack(">BBBB", 0x2B, 0x0E, 0x01, 0x00)


def mb_read_device_id_resp() -> bytes:
    objects = [(0x00, b"Schneider Electric"), (0x01, b"BMX P34 2020"), (0x02, b"v3.20")]
    body = b"".join(struct.pack(">BB", oid, len(val)) + val for oid, val in objects)
    return struct.pack(">BBBBBBB", 0x2B, 0x0E, 0x01, 0x01, 0x00, 0x00, len(objects)) + body


def mb_report_server_id_req() -> bytes:
    return struct.pack(">B", 0x11)


def mb_report_server_id_resp() -> bytes:
    data = b"\x0a\xff" + b"M340-LAB"
    return struct.pack(">BB", 0x11, len(data)) + data


# ---------------------------------------------------------------------------
# Construtores OPC UA Binary (UA-TCP)
# ---------------------------------------------------------------------------


def ua_string(value: str) -> bytes:
    raw = value.encode("utf-8")
    return struct.pack("<i", len(raw)) + raw


def ua_chunk(message_type: bytes, body: bytes) -> bytes:
    return message_type + b"F" + struct.pack("<I", len(body) + 8) + body


def opcua_hello(endpoint: str) -> bytes:
    body = struct.pack("<IIIII", 0, 65535, 65535, 0, 0) + ua_string(endpoint)
    return ua_chunk(b"HEL", body)


def opcua_ack() -> bytes:
    return ua_chunk(b"ACK", struct.pack("<IIIII", 0, 65535, 65535, 16_777_216, 5000))


def opcua_open_secure_channel(policy: str, channel_id: int, request: bool) -> bytes:
    asym_header = (
        struct.pack("<I", channel_id)
        + ua_string(f"http://opcfoundation.org/UA/SecurityPolicy#{policy}")
        + struct.pack("<i", -1)
        + struct.pack("<i", -1)
    )
    seq_header = struct.pack("<II", 51, 1)
    node_id = struct.pack("<BBH", 0x01, 0x00, 446 if request else 449)
    if request:
        body = node_id + struct.pack("<IIiB", 0, 0, 0, 0) + struct.pack("<IIi", 0, 0, -1) + struct.pack("<I", 3600000)
    else:
        body = node_id + struct.pack("<qIIBB", 0, 1, 0, 0, 0) + struct.pack("<IIqI", 0, channel_id, 0, 3600000)
    return ua_chunk(b"OPN", asym_header + seq_header + body)


def opcua_msg(channel_id: int, token_id: int, seq: int, payload: bytes) -> bytes:
    body = struct.pack("<III", channel_id, token_id, seq) + struct.pack("<I", seq) + payload
    return b"MSGF" + struct.pack("<I", len(body) + 8) + body


# ---------------------------------------------------------------------------
# Montagem do cenário
# ---------------------------------------------------------------------------


def _arp_packets(clock: _Clock) -> list[Packet]:
    pkts: list[Packet] = []
    for asker_ip, asker_mac, target_ip, target_mac in (
        (SCADA_IP, SCADA_MAC, PLC_IP, PLC_MAC),
        (SCADA_IP, SCADA_MAC, OPCUA_IP, OPCUA_MAC),
        (ROGUE_IP, ROGUE_MAC, PLC_IP, PLC_MAC),
        (EWS_IP, EWS_MAC, FILESRV_IP, FILESRV_MAC),
    ):
        req = Ether(src=asker_mac, dst="ff:ff:ff:ff:ff:ff") / ARP(
            op=1, hwsrc=asker_mac, psrc=asker_ip, pdst=target_ip
        )
        req.time = clock.tick(0.02)
        rep = Ether(src=target_mac, dst=asker_mac) / ARP(
            op=2, hwsrc=target_mac, psrc=target_ip, hwdst=asker_mac, pdst=asker_ip
        )
        rep.time = clock.tick(0.001)
        pkts.extend([req, rep])
    return pkts


def _scada_polling(clock: _Clock) -> list[Packet]:
    s = TcpSession(SCADA_IP, SCADA_MAC, PLC_IP, PLC_MAC, 49152, 502, clock).handshake()
    tid = 1
    for cycle in range(20):
        s.client_send(mbap(tid, 1, mb_read_req(0x03, 0, 10)), delta=0.5)
        s.server_send(mbap(tid, 1, mb_read_holding_resp([1200 + cycle, 345, 67, 0, 1, 0, 220, 221, 219, 50])))
        tid += 1
        if cycle % 4 == 0:
            s.client_send(mbap(tid, 1, mb_read_req(0x01, 0, 16)))
            s.server_send(mbap(tid, 1, mb_read_coils_resp(b"\x5a\x01")))
            tid += 1
        if cycle in (7, 15):
            req = mb_write_single_register(10, 1500 + cycle)
            s.client_send(mbap(tid, 1, req))
            s.server_send(mbap(tid, 1, req))
            tid += 1
    s.close()
    return s.packets


def _rogue_master(clock: _Clock) -> list[Packet]:
    s = TcpSession(ROGUE_IP, ROGUE_MAC, PLC_IP, PLC_MAC, 51515, 502, clock).handshake()
    tid = 0x0100
    s.client_send(mbap(tid, 1, mb_read_device_id_req()), delta=0.2)
    s.server_send(mbap(tid, 1, mb_read_device_id_resp()))
    tid += 1
    s.client_send(mbap(tid, 1, mb_report_server_id_req()))
    s.server_send(mbap(tid, 1, mb_report_server_id_resp()))
    tid += 1
    for address in (9000, 9100, 9200, 9300, 9400, 9500):
        s.client_send(mbap(tid, 1, mb_read_req(0x03, address, 1)), delta=0.02)
        s.server_send(mbap(tid, 1, mb_exception(0x03, 0x02)))
        tid += 1
    req = mb_write_single_register(10, 0)
    s.client_send(mbap(tid, 1, req), delta=0.3)
    s.server_send(mbap(tid, 1, req))
    tid += 1
    s.client_send(mbap(tid, 1, mb_write_multiple_registers_req(20, [0, 0, 9999, 9999])))
    s.server_send(mbap(tid, 1, mb_write_multiple_registers_resp(20, 4)))
    s.close()
    return s.packets


def _opcua_session(clock: _Clock) -> list[Packet]:
    s = TcpSession(SCADA_IP, SCADA_MAC, OPCUA_IP, OPCUA_MAC, 50211, 4840, clock).handshake()
    s.client_send(opcua_hello(f"opc.tcp://{OPCUA_IP}:4840/LabServer"), delta=0.1)
    s.server_send(opcua_ack())
    s.client_send(opcua_open_secure_channel("None", 0, request=True))
    s.server_send(opcua_open_secure_channel("None", 7, request=False))
    for seq in range(2, 6):
        s.client_send(opcua_msg(7, 1, seq, b"\x01\x00\x77\x02" + b"\x00" * 24))
        s.server_send(opcua_msg(7, 1, seq, b"\x01\x00\x7a\x02" + b"\x00" * 32))
    s.close()
    return s.packets


def _smb_session(clock: _Clock) -> list[Packet]:
    s = TcpSession(EWS_IP, EWS_MAC, FILESRV_IP, FILESRV_MAC, 52001, 445, clock).handshake()
    smb2_header = b"\xfeSMB" + struct.pack("<HHIHHI", 64, 0, 0, 0, 0, 0) + b"\x00" * 44
    s.client_send(struct.pack(">I", len(smb2_header) + 36) + smb2_header + b"\x24\x00" + b"\x00" * 34, delta=0.3)
    s.server_send(struct.pack(">I", len(smb2_header) + 64) + smb2_header + b"\x41\x00" + b"\x00" * 62)
    s.close()
    return s.packets


def _telnet_session(clock: _Clock) -> list[Packet]:
    s = TcpSession(EWS_IP, EWS_MAC, PLC_IP, PLC_MAC, 52002, 23, clock).handshake()
    s.server_send(b"\xff\xfd\x18\xff\xfd\x20login: ", delta=0.05)
    s.client_send(b"admin\r\n")
    s.server_send(b"Password: ")
    s.client_send(b"schneider\r\n")
    s.server_send(b"\r\nM340> ")
    s.close()
    return s.packets


def _external_probe(clock: _Clock) -> list[Packet]:
    s = TcpSession(PUBLIC_IP, GATEWAY_MAC, PLC_IP, PLC_MAC, 40404, 502, clock).handshake()
    s.client_send(mbap(1, 1, mb_read_req(0x03, 0, 4)), delta=0.2)
    s.server_send(mbap(1, 1, mb_read_holding_resp([1210, 345, 67, 0])))
    s.close()
    return s.packets


def _snmp_query(clock: _Clock) -> list[Packet]:
    community = b"public"
    pdu = b"\xa0\x1c\x02\x04\x12\x34\x56\x78\x02\x01\x00\x02\x01\x00\x30\x0e\x30\x0c\x06\x08\x2b\x06\x01\x02\x01\x01\x01\x00\x05\x00"
    body = b"\x02\x01\x01" + b"\x04" + bytes([len(community)]) + community + pdu
    msg = b"\x30" + bytes([len(body)]) + body
    pkt = Ether(src=EWS_MAC, dst=PLC_MAC) / IP(src=EWS_IP, dst=PLC_IP) / UDP(sport=53000, dport=161) / Raw(load=msg)
    pkt.time = clock.tick(0.4)
    return [pkt]


def build_sample_packets() -> list[Packet]:
    clock = _Clock()
    packets: list[Packet] = []
    packets += _arp_packets(clock)
    packets += _scada_polling(clock)
    packets += _opcua_session(clock)
    packets += _rogue_master(clock)
    packets += _smb_session(clock)
    packets += _telnet_session(clock)
    packets += _snmp_query(clock)
    packets += _external_probe(clock)
    packets.sort(key=lambda p: float(p.time))
    return packets


def generate_sample_pcap(output_path: Path = SAMPLE_PCAP_PATH) -> Path:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    packets = build_sample_packets()
    wrpcap(str(output_path), packets)
    return output_path


if __name__ == "__main__":
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else SAMPLE_PCAP_PATH
    path = generate_sample_pcap(target)
    print(f"PCAP sintético gerado: {path} ({path.stat().st_size} bytes)")
