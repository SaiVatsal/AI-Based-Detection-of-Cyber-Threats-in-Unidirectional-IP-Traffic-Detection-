"""
CampusShield AI — PCAP Parser
===============================
Parse PCAP/PCAPNG files using scapy and extract per-packet metadata.

CRITICAL DESIGN CONSTRAINT:
    Every field extracted here is observable from ONE direction only.
    We never correlate with return traffic, never check for SYN-ACK,
    never reconstruct bidirectional sessions. Each packet stands alone.
"""

import logging
from pathlib import Path
from typing import Optional

from backend.config import MAX_UPLOAD_SIZE_BYTES, ALLOWED_EXTENSIONS

logger = logging.getLogger(__name__)


# PCAP magic bytes for file validation
PCAP_MAGIC = {
    b"\xd4\xc3\xb2\xa1",  # Little-endian PCAP
    b"\xa1\xb2\xc3\xd4",  # Big-endian PCAP
    b"\x0a\x0d\x0d\x0a",  # PCAPNG
}


def validate_pcap_file(file_path: Path) -> tuple[bool, str]:
    """
    Validate that a file is a legitimate PCAP/PCAPNG file.
    Returns (is_valid, error_message).
    """
    if not file_path.exists():
        return False, "File does not exist"

    if file_path.suffix.lower() not in ALLOWED_EXTENSIONS:
        return False, f"Invalid extension '{file_path.suffix}'. Allowed: {ALLOWED_EXTENSIONS}"

    size = file_path.stat().st_size
    if size == 0:
        return False, "File is empty"
    if size > MAX_UPLOAD_SIZE_BYTES:
        return False, f"File too large ({size / 1024 / 1024:.1f} MB > {MAX_UPLOAD_SIZE_BYTES / 1024 / 1024:.0f} MB limit)"

    # Check magic bytes
    with open(file_path, "rb") as f:
        magic = f.read(4)
    if magic not in PCAP_MAGIC:
        return False, "Invalid PCAP file (magic bytes mismatch)"

    return True, ""


def parse_pcap(file_path: Path) -> list[dict]:
    """
    Parse a PCAP file and extract per-packet metadata.

    Each packet is processed INDEPENDENTLY — this is the unidirectional
    guarantee. We extract only what's visible in a single packet header.

    Returns a list of packet dictionaries with fields:
        - timestamp (float): epoch time
        - src_ip (str): source IP
        - dst_ip (str): destination IP
        - src_port (int|None): source port (TCP/UDP only)
        - dst_port (int|None): destination port (TCP/UDP only)
        - protocol (str): "TCP", "UDP", "ICMP", or protocol number
        - size (int): total packet size in bytes
        - ip_len (int): IP payload length
        - ttl (int|None): Time to Live
        - tcp_flags (str|None): TCP flags string (e.g., "S", "SA", "PA")
        - payload_size (int): application-layer payload bytes
        - payload_bytes (bytes|None): first 256 bytes of payload for entropy
    """
    try:
        # Lazy import: scapy is heavy and may not be installed in test env
        from scapy.all import rdpcap, IP, IPv6, TCP, UDP, ICMP, Raw
    except ImportError:
        logger.error("scapy not installed — cannot parse PCAP files")
        return []

    packets_data = []

    try:
        packets = rdpcap(str(file_path))
    except Exception as e:
        logger.error(f"Failed to read PCAP file {file_path}: {e}")
        return []

    for i, pkt in enumerate(packets):
        record = {
            "index": i,
            "timestamp": float(pkt.time),
            "size": len(pkt),
            "src_ip": None,
            "dst_ip": None,
            "src_port": None,
            "dst_port": None,
            "protocol": "OTHER",
            "ip_len": 0,
            "ttl": None,
            "tcp_flags": None,
            "payload_size": 0,
            "payload_bytes": None,
        }

        # --- Layer 3: IP ---
        if pkt.haslayer(IP):
            ip_layer = pkt[IP]
            record["src_ip"] = ip_layer.src
            record["dst_ip"] = ip_layer.dst
            record["ip_len"] = ip_layer.len
            record["ttl"] = ip_layer.ttl
        elif pkt.haslayer(IPv6):
            ip_layer = pkt[IPv6]
            record["src_ip"] = ip_layer.src
            record["dst_ip"] = ip_layer.dst
            record["ip_len"] = ip_layer.plen
            # IPv6 has hop_limit instead of TTL
            record["ttl"] = ip_layer.hlim
        else:
            # Non-IP packet — still record size and timestamp
            packets_data.append(record)
            continue

        # --- Layer 4: TCP/UDP/ICMP ---
        if pkt.haslayer(TCP):
            tcp_layer = pkt[TCP]
            record["protocol"] = "TCP"
            record["src_port"] = tcp_layer.sport
            record["dst_port"] = tcp_layer.dport
            record["tcp_flags"] = str(tcp_layer.flags)
        elif pkt.haslayer(UDP):
            udp_layer = pkt[UDP]
            record["protocol"] = "UDP"
            record["src_port"] = udp_layer.sport
            record["dst_port"] = udp_layer.dport
        elif pkt.haslayer(ICMP):
            record["protocol"] = "ICMP"
        else:
            # Known IP but unknown L4 — use IP protocol number
            if pkt.haslayer(IP):
                record["protocol"] = f"PROTO_{pkt[IP].proto}"

        # --- Payload ---
        if pkt.haslayer(Raw):
            raw = pkt[Raw].load
            record["payload_size"] = len(raw)
            # Keep first 256 bytes for entropy calculation
            record["payload_bytes"] = raw[:256]

        packets_data.append(record)

    logger.info(f"Parsed {len(packets_data)} packets from {file_path.name}")
    return packets_data
