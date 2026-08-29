"""
CampusShield AI — URL / Host Traffic Inspector
================================================
Inspects, generates, and analyzes unidirectional traffic telemetry for any
target website, domain, or localhost URL.

Supports testing standard visitor traffic vs various threat vectors (stress spikes,
port/path sweeps, protocol anomalies, exfiltration).
"""

import math
import random
import socket
import time
import urllib.parse
from typing import Literal

from backend.config import SIMULATION_PACKET_COUNT


def parse_target_url(url: str) -> dict:
    """
    Parse a given URL/endpoint into structured network components.
    Defaults to HTTP/80 or HTTPS/443 if not explicitly specified.
    """
    cleaned_url = url.strip()
    if not cleaned_url.startswith(("http://", "https://")):
        cleaned_url = "http://" + cleaned_url

    parsed = urllib.parse.urlparse(cleaned_url)
    hostname = parsed.hostname or "localhost"
    
    # Determine port
    if parsed.port:
        port = parsed.port
    elif parsed.scheme == "https":
        port = 443
    else:
        port = 80

    # Resolve IP if possible, fallback to standard localhost or synthetic IP
    resolved_ip = "127.0.0.1"
    is_live = False
    try:
        if hostname in ("localhost", "127.0.0.1", "0.0.0.0"):
            resolved_ip = "127.0.0.1"
        else:
            resolved_ip = socket.gethostbyname(hostname)
        is_live = True
    except Exception:
        # Generate stable synthetic IP for unresolvable host
        hash_val = sum(ord(c) for c in hostname)
        resolved_ip = f"198.51.100.{(hash_val % 250) + 1}"

    return {
        "original_url": url,
        "normalized_url": cleaned_url,
        "scheme": parsed.scheme,
        "hostname": hostname,
        "port": port,
        "path": parsed.path or "/",
        "resolved_ip": resolved_ip,
        "is_resolvable": is_live,
    }


def generate_url_traffic(
    target_info: dict,
    traffic_profile: Literal["standard", "stress_spike", "sweep_probe", "payload_anomaly", "exfil_probe"] = "standard",
    packet_count: int = 1500,
) -> list[dict]:
    """
    Generate unidirectional packet telemetry targeting the parsed URL.
    """
    rng = random.Random(hash(target_info["normalized_url"] + traffic_profile) & 0xFFFFFFFF)
    packets = []
    current_time = time.time() - (packet_count * 0.005)

    dst_ip = target_info["resolved_ip"]
    dst_port = target_info["port"]

    if traffic_profile == "standard":
        # Normal web browsing traffic to the target URL
        for i in range(packet_count):
            iat = rng.expovariate(1.0 / 0.008)  # ~125 packets/sec
            current_time += iat

            # Mix of request sizes (GET, POST, small ACKs/SYNs)
            pkt_size = rng.choice([64, 128, 256, 512, 1024, 1420])
            src_port = rng.randint(40000, 65000)
            src_ip = f"10.{rng.randint(1, 10)}.{rng.randint(1, 254)}.{rng.randint(1, 254)}"

            payload_bytes = f"GET {target_info['path']} HTTP/1.1\r\nHost: {target_info['hostname']}\r\n\r\n".encode()[:pkt_size]

            packets.append({
                "index": i,
                "timestamp": current_time,
                "size": pkt_size,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": "TCP",
                "ip_len": pkt_size - 14,
                "ttl": 64,
                "tcp_flags": "PA",
                "payload_size": len(payload_bytes),
                "payload_bytes": payload_bytes,
            })

    elif traffic_profile == "stress_spike":
        # Volumetric spike targeting the URL (DDoS-like request flood)
        for i in range(packet_count):
            # Extremely high rate: 1000-2000 packets/sec
            iat = rng.uniform(0.0001, 0.0008)
            current_time += iat

            pkt_size = rng.choice([60, 64, 120])  # Minimal flood frames
            src_ip = f"198.{rng.randint(1, 254)}.{rng.randint(1, 254)}.{rng.randint(1, 254)}"
            src_port = rng.randint(1024, 65535)

            payload_bytes = b"GET / HTTP/1.1\r\nHost: " + target_info["hostname"].encode() + b"\r\n\r\n"

            packets.append({
                "index": i,
                "timestamp": current_time,
                "size": pkt_size,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": "TCP",
                "ip_len": pkt_size - 14,
                "ttl": rng.choice([32, 64, 128]),
                "tcp_flags": "S",  # SYN flood
                "payload_size": len(payload_bytes),
                "payload_bytes": payload_bytes,
            })

    elif traffic_profile == "sweep_probe":
        # Scanning multiple ports and sensitive endpoints on the target host
        common_scan_ports = [dst_port, 21, 22, 23, 25, 53, 80, 443, 8080, 8443, 3000, 3306, 5432, 6379, 27017]
        for i in range(packet_count):
            iat = rng.uniform(0.001, 0.005)
            current_time += iat

            target_port = common_scan_ports[i % len(common_scan_ports)] if i % 2 == 0 else rng.randint(1000, 9000)
            pkt_size = rng.choice([40, 54, 60])
            src_ip = "192.168.1.105"
            src_port = 45000 + (i % 1000)

            packets.append({
                "index": i,
                "timestamp": current_time,
                "size": pkt_size,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": target_port,
                "protocol": "TCP",
                "ip_len": pkt_size - 14,
                "ttl": 58,
                "tcp_flags": "S",
                "payload_size": 0,
                "payload_bytes": b"",
            })

    elif traffic_profile == "payload_anomaly":
        # Protocol & high entropy injection targeting the URL
        for i in range(packet_count):
            iat = rng.uniform(0.002, 0.010)
            current_time += iat

            proto = rng.choice(["TCP", "UDP", "ICMP", "RAW_IP"])
            pkt_size = rng.randint(300, 1400)
            src_ip = f"172.16.{rng.randint(1, 50)}.{rng.randint(1, 254)}"
            src_port = rng.randint(10000, 60000)

            # Generate high entropy payload bytes
            payload_bytes = bytes(rng.getrandbits(8) for _ in range(min(pkt_size, 256)))

            packets.append({
                "index": i,
                "timestamp": current_time,
                "size": pkt_size,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port if proto != "ICMP" else None,
                "protocol": proto,
                "ip_len": pkt_size - 14,
                "ttl": rng.randint(40, 64),
                "tcp_flags": "PA" if proto == "TCP" else None,
                "payload_size": len(payload_bytes),
                "payload_bytes": payload_bytes,
            })

    elif traffic_profile == "exfil_probe":
        # Outbound heavy data flow to/from target
        for i in range(packet_count):
            iat = rng.uniform(0.001, 0.004)
            current_time += iat

            pkt_size = rng.randint(1380, 1514)  # MTU full packets
            src_ip = f"10.0.0.{rng.randint(10, 20)}"
            src_port = 52000

            payload_bytes = bytes(rng.getrandbits(8) for _ in range(256))

            packets.append({
                "index": i,
                "timestamp": current_time,
                "size": pkt_size,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": "TCP",
                "ip_len": pkt_size - 14,
                "ttl": 64,
                "tcp_flags": "PA",
                "payload_size": len(payload_bytes),
                "payload_bytes": payload_bytes,
            })

    return packets
