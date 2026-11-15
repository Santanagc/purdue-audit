# Especificação do Motor Determinístico de Dissecação (`pcap_analyzer.py`)

O módulo de análise em Python deve usar `scapy.all.PcapReader` (leitura em streaming iterativo para não estourar a memória RAM do container) e extrair três categorias de informações.

## 1. Inventário de Ativos e Topologia Inferida
Agrupar por endereço IP (e MAC correspondente):
- **Papel Inferido (`inferred_role`):**
  - `PLC / Field Slave`: Recebe conexões de destino nas portas 502 (Modbus), 4840 (OPC UA), 102 (S7comm), 44818 (EtherNet/IP) ou 20000 (DNP3).
  - `HMI / SCADA Master`: Inicia conexões TCP (`SYN`) em direção às portas industriais acima.
  - `Engineering Workstation / IT Host`: Inicia tráfego de gerenciamento (SSH, RDP, SMB, HTTP) ou múltiplos protocolos simultâneos.
- Contabilizar volume de pacotes enviados/recebidos e lista de portas abertas observadas.

## 2. Regras de Inspeção Profunda de Protocolos Industriais

### A. Modbus TCP (Porta TCP 502)
Estrutura do payload TCP para Modbus (MBAP Header de 7 bytes + PDU):
- Bytes `0..1`: Transaction Identifier
- Bytes `2..3`: Protocol Identifier (`0x0000` = Modbus)
- Bytes `4..5`: Length
- Byte `6`: Unit Identifier (Slave ID)
- Byte `7`: **Function Code (FC)**

**Classificação de Risco por Function Code (Byte 7):**
- **Leitura (Operação Normal - Risco Baixo, mas mapear frequência):**
  - `0x01` (Read Coils), `0x02` (Read Discrete Inputs), `0x03` (Read Holding Registers), `0x04` (Read Input Registers).
- **Escrita / Controle Direto (Risco Alto se vier de IP não-SCADA ou múltiplas origens):**
  - `0x05` (Write Single Coil)
  - `0x06` (Write Single Register)
  - `0x0F` (Write Multiple Coils - 15)
  - `0x10` (Write Multiple Registers - 16)
- **Diagnóstico e Reconhecimento (Risco Crítico de Enumeração/Manutenção):**
  - `0x08` (Diagnostics), `0x11` (Report Server ID - 17), `0x2B` (Read Device Identification / MEI - 43).
- **Respostas de Exceção (`FC >= 0x80`):**
  - Alta taxa de exceções (`0x81`, `0x82`, `0x83`, `0x84`) indica varredura de registradores (fuzzing/scanning de endereços de memória) ou falha de configuração de driver SCADA.

*Nota de Segurança:* Todo tráfego na porta 502 padrão deve gerar automaticamente a flag `unencrypted_cleartext_protocol = True` e `lack_of_authentication = True` (a menos que encapsulado em TLS na porta 802 - Modbus/TLS).

### B. OPC UA (Porta TCP 4840)
Inspecionar o payload TCP de abertura de canal (`HEL`, `ACK`, `OPN` - *OpenSecureChannel*):
- Buscar strings ASCII no payload da mensagem `OPN`:
  - Se contiver `http://opcfoundation.org/UA/SecurityPolicy#None`: Marcar vulnerabilidade **CRÍTICA** (`OPCUA_SECURITY_POLICY_NONE` - tráfego sem criptografia e sem assinatura).
  - Se contiver `#Basic128Rsa15` ou `#Basic256`: Marcar alerta **MÉDIO** (Políticas criptográficas depreciadas pela OPC Foundation).
  - Se contiver `#Basic256Sha256` ou `#Aes128_Sha256_RsaOaep`: Marcar como **SEGURO**.

### C. Higiene de Rede e Violação do Modelo Purdue (IT/OT Convergence)
Detectar fluxos dentro do mesmo segmento de rede dos CLPs que violem o isolamento de zonas (IEC 62443-3-2):
- **Protocolos Legados Inseguros:** Telnet (TCP 23), FTP (TCP 21), HTTP plano (TCP 80), SNMP v1/v2c (UDP 161).
- **Vetores de Movimentação Lateral de TI em Rede OT:** SMB (TCP 445), RDP (TCP 3389), VNC (TCP 5900).
- **Exposição Externa:** Qualquer pacote cujo IP de origem ou destino seja público (não pertencente às faixas RFC 1918: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) conversando diretamente com um ativo classificado como `PLC / Field Slave`.