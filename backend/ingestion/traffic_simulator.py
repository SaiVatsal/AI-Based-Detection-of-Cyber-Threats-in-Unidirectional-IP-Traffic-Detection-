"""
CampusShield AI — Traffic Simulator
=====================================
Generate synthetic traffic telemetry for 5 demo scenarios.

This produces packet-level records IDENTICAL in schema to what the
PCAP parser outputs — so the downstream pipeline (feature extraction,
detection, scoring) works identically on real and simulated data.

IMPORTANT: This simulates telemetry, NOT real network attacks. No
actual malicious traffic is generated or transmitted.
"""

import random
import time
import math
import logging
from typing import Generator

from backend.config import SIMULATION_PACKET_COUNT

logger = logging.getLogger(__name__)

# Reproducible but distinct per-scenario
_SCENARIO_SEEDS = {
    "normal": 42,
    "ddos": 1337,
    "scan": 7777,
    "protocol_anomaly": 9999,
    "exfiltration": 5555,
}

# Common web ports
_COMMON_PORTS = [80, 443, 8080, 8443, 53, 22, 25, 110, 143, 993, 995]


def _random_ip(rng: random.Random) -> str:
    """Generate a plausible private/campus IP."""
    return f"10.{rng.randint(0, 255)}.{rng.randint(1, 254)}.{rng.randint(1, 254)}"


def _random_external_ip(rng: random.Random) -> str:
    """Generate a plausible external IP."""
    first = rng.choice([203, 198, 192, 172, 185, 104, 52, 34, 151, 216])
    return f"{first}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"


def _generate_payload_bytes(
    rng: random.Random, size: int, high_entropy: bool = False
) -> bytes:
    """
    Generate synthetic payload bytes.
    high_entropy=True produces near-random bytes (simulating encryption/compression).
    high_entropy=False produces structured/repetitive bytes (normal text-like).
    """
    if high_entropy:
        return bytes(rng.getrandbits(8) for _ in range(min(size, 256)))
    else:
        # Simulate HTTP-like payload with repeated patterns
        pattern = b"GET /page HTTP/1.1\r\nHost: campus.edu\r\n\r\n"
        repeated = (pattern * ((size // len(pattern)) + 1))[:size]
        return repeated[:256]


def simulate_normal(
    packet_count: int = SIMULATION_PACKET_COUNT,
) -> list[dict]:
    """
    Scenario 1: Normal campus traffic.

    Characteristics:
    - Mix of TCP (70%), UDP (25%), ICMP (5%)
    - Packet sizes: 64-1500 bytes, clustered around 200-600
    - Regular inter-arrival times with slight jitter
    - Common destination ports (80, 443, 53, 22)
    - Low payload entropy
    """
    rng = random.Random(_SCENARIO_SEEDS["normal"])
    base_time = time.time()
    packets = []

    src_ips = [_random_ip(rng) for _ in range(20)]
    dst_ips = [_random_external_ip(rng) for _ in range(30)]

    for i in range(packet_count):
        # Regular timing with Poisson-like jitter
        iat = rng.expovariate(100)  # ~100 pps average
        base_time += iat

        proto_roll = rng.random()
        if proto_roll < 0.70:
            protocol = "TCP"
            dst_port = rng.choice([80, 443, 8080, 8443])
            size = int(rng.gauss(400, 150))
        elif proto_roll < 0.95:
            protocol = "UDP"
            dst_port = rng.choice([53, 123, 5353])
            size = int(rng.gauss(120, 40))
        else:
            protocol = "ICMP"
            dst_port = None
            size = 64

        size = max(64, min(1500, size))
        payload_size = max(0, size - 40)

        packets.append({
            "index": i,
            "timestamp": base_time,
            "src_ip": rng.choice(src_ips),
            "dst_ip": rng.choice(dst_ips),
            "src_port": rng.randint(1024, 65535),
            "dst_port": dst_port,
            "protocol": protocol,
            "size": size,
            "ip_len": size - 14,  # minus ethernet header
            "ttl": rng.choice([64, 128, 255]),
            "tcp_flags": rng.choice(["PA", "A", "PA"]) if protocol == "TCP" else None,
            "payload_size": payload_size,
            "payload_bytes": _generate_payload_bytes(rng, payload_size, high_entropy=False),
        })

    return packets


def simulate_ddos(
    packet_count: int = SIMULATION_PACKET_COUNT,
) -> list[dict]:
    """
    Scenario 2: Volumetric / DDoS-like traffic.

    Characteristics:
    - Massive spike in packet rate (10x-50x normal)
    - Many source IPs (spoofed flood pattern)
    - Uniform small-ish packets (SYN flood style)
    - Single or few destination IPs/ports
    - Very short inter-arrival times
    """
    rng = random.Random(_SCENARIO_SEEDS["ddos"])
    base_time = time.time()
    packets = []

    # Many attackers, few targets
    src_ips = [_random_ip(rng) for _ in range(500)]
    target_ip = "10.0.1.100"
    target_port = 80

    # Start with normal traffic, then spike
    normal_count = packet_count // 5
    attack_count = packet_count - normal_count

    # Phase 1: Normal baseline
    for i in range(normal_count):
        base_time += rng.expovariate(100)
        size = int(rng.gauss(400, 150))
        size = max(64, min(1500, size))

        packets.append({
            "index": i,
            "timestamp": base_time,
            "src_ip": rng.choice(src_ips[:20]),
            "dst_ip": rng.choice([target_ip, _random_external_ip(rng)]),
            "src_port": rng.randint(1024, 65535),
            "dst_port": rng.choice(_COMMON_PORTS),
            "protocol": "TCP",
            "size": size,
            "ip_len": size - 14,
            "ttl": rng.choice([64, 128]),
            "tcp_flags": "PA",
            "payload_size": max(0, size - 40),
            "payload_bytes": _generate_payload_bytes(rng, max(0, size - 40)),
        })

    # Phase 2: Volumetric attack
    for i in range(attack_count):
        # 10x-50x packet rate
        base_time += rng.expovariate(5000)
        size = rng.choice([40, 44, 48, 60, 64])  # small SYN-like packets

        packets.append({
            "index": normal_count + i,
            "timestamp": base_time,
            "src_ip": rng.choice(src_ips),
            "dst_ip": target_ip,
            "src_port": rng.randint(1024, 65535),
            "dst_port": target_port,
            "protocol": "TCP",
            "size": size,
            "ip_len": size - 14,
            "ttl": rng.randint(1, 255),  # varied TTL from spoofed sources
            "tcp_flags": "S",  # SYN flood
            "payload_size": 0,
            "payload_bytes": b"",
        })

    return packets


def simulate_scan(
    packet_count: int = SIMULATION_PACKET_COUNT,
) -> list[dict]:
    """
    Scenario 3: Port scan / reconnaissance.

    Characteristics:
    - Rapid small packets to MANY distinct destination ports
    - Single or few source IPs scanning systematically
    - Very small packet sizes (SYN probes or bare headers)
    - Sequential or semi-random port sweep
    - High destination port entropy
    """
    rng = random.Random(_SCENARIO_SEEDS["scan"])
    base_time = time.time()
    packets = []

    scanner_ip = "10.10.10.42"
    target_ip = "10.0.1.50"

    # Normal traffic first
    normal_count = packet_count // 4
    scan_count = packet_count - normal_count

    for i in range(normal_count):
        base_time += rng.expovariate(80)
        size = int(rng.gauss(350, 120))
        size = max(64, min(1500, size))

        packets.append({
            "index": i,
            "timestamp": base_time,
            "src_ip": _random_ip(rng),
            "dst_ip": _random_external_ip(rng),
            "src_port": rng.randint(1024, 65535),
            "dst_port": rng.choice(_COMMON_PORTS),
            "protocol": rng.choice(["TCP", "UDP"]),
            "size": size,
            "ip_len": size - 14,
            "ttl": 64,
            "tcp_flags": "PA",
            "payload_size": max(0, size - 40),
            "payload_bytes": _generate_payload_bytes(rng, max(0, size - 40)),
        })

    # Port scan phase: systematic port sweep
    port_list = list(range(1, 1025)) + [
        1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 27017
    ]
    rng.shuffle(port_list)

    for i in range(scan_count):
        base_time += rng.expovariate(2000)  # fast scanning
        port = port_list[i % len(port_list)]

        packets.append({
            "index": normal_count + i,
            "timestamp": base_time,
            "src_ip": scanner_ip,
            "dst_ip": target_ip,
            "src_port": rng.randint(40000, 65535),
            "dst_port": port,
            "protocol": "TCP",
            "size": rng.choice([40, 44, 54, 60]),  # bare SYN probes
            "ip_len": 40,
            "ttl": 64,
            "tcp_flags": "S",
            "payload_size": 0,
            "payload_bytes": b"",
        })

    return packets


def simulate_protocol_anomaly(
    packet_count: int = SIMULATION_PACKET_COUNT,
) -> list[dict]:
    """
    Scenario 4: Protocol anomaly.

    Characteristics:
    - Unusual protocol distribution (lots of ICMP, GRE, unknown protos)
    - Unexpected packet sizes for the protocol
    - Large ICMP packets (potential tunneling)
    - Mixed exotic protocols
    """
    rng = random.Random(_SCENARIO_SEEDS["protocol_anomaly"])
    base_time = time.time()
    packets = []

    src_ips = [_random_ip(rng) for _ in range(15)]
    dst_ips = [_random_external_ip(rng) for _ in range(15)]

    normal_count = packet_count // 3
    anomaly_count = packet_count - normal_count

    # Normal phase
    for i in range(normal_count):
        base_time += rng.expovariate(90)
        size = int(rng.gauss(400, 120))
        size = max(64, min(1500, size))

        packets.append({
            "index": i,
            "timestamp": base_time,
            "src_ip": rng.choice(src_ips),
            "dst_ip": rng.choice(dst_ips),
            "src_port": rng.randint(1024, 65535),
            "dst_port": rng.choice([80, 443]),
            "protocol": "TCP",
            "size": size,
            "ip_len": size - 14,
            "ttl": 64,
            "tcp_flags": "PA",
            "payload_size": max(0, size - 40),
            "payload_bytes": _generate_payload_bytes(rng, max(0, size - 40)),
        })

    # Anomaly phase: unusual protocols and sizes
    for i in range(anomaly_count):
        base_time += rng.expovariate(120)
        proto_roll = rng.random()

        if proto_roll < 0.35:
            # Large ICMP packets (tunnel-like)
            protocol = "ICMP"
            size = rng.randint(500, 1400)
            dst_port = None
            src_port = None
        elif proto_roll < 0.60:
            # GRE / exotic protocol
            protocol = f"PROTO_{rng.choice([47, 50, 51, 41, 4])}"
            size = rng.randint(200, 1200)
            dst_port = None
            src_port = None
        elif proto_roll < 0.80:
            # TCP but absurd sizes
            protocol = "TCP"
            size = rng.choice([1500, 1499, 1498, 40, 41])  # MTU or minimal
            dst_port = rng.randint(10000, 65535)  # unusual ports
            src_port = rng.randint(1024, 65535)
        else:
            # UDP on unusual ports with large payloads
            protocol = "UDP"
            size = rng.randint(800, 1400)
            dst_port = rng.randint(30000, 60000)
            src_port = rng.randint(1024, 65535)

        payload_size = max(0, size - 40)

        packets.append({
            "index": normal_count + i,
            "timestamp": base_time,
            "src_ip": rng.choice(src_ips),
            "dst_ip": rng.choice(dst_ips),
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": protocol,
            "size": size,
            "ip_len": size - 14,
            "ttl": rng.choice([1, 2, 64, 128, 255]),
            "tcp_flags": rng.choice(["S", "F", "R", "SFPUE"]) if protocol == "TCP" else None,
            "payload_size": payload_size,
            "payload_bytes": _generate_payload_bytes(rng, payload_size, high_entropy=True),
        })

    return packets


def simulate_exfiltration(
    packet_count: int = SIMULATION_PACKET_COUNT,
) -> list[dict]:
    """
    Scenario 5: Data exfiltration pattern.

    Characteristics:
    - Sustained large packets (near MTU) to a single external destination
    - High payload entropy (encrypted/compressed data)
    - Consistent high throughput over extended period
    - Unusual destination (not typical CDN/web)
    - Low packet count variance (automated, not human browsing)
    """
    rng = random.Random(_SCENARIO_SEEDS["exfiltration"])
    base_time = time.time()
    packets = []

    campus_ip = "10.5.20.99"
    exfil_target = "203.0.113.42"  # RFC 5737 documentation range

    normal_count = packet_count // 3
    exfil_count = packet_count - normal_count

    src_ips = [_random_ip(rng) for _ in range(15)]

    # Normal phase
    for i in range(normal_count):
        base_time += rng.expovariate(80)
        size = int(rng.gauss(350, 150))
        size = max(64, min(1500, size))

        packets.append({
            "index": i,
            "timestamp": base_time,
            "src_ip": rng.choice(src_ips),
            "dst_ip": _random_external_ip(rng),
            "src_port": rng.randint(1024, 65535),
            "dst_port": rng.choice([80, 443]),
            "protocol": "TCP",
            "size": size,
            "ip_len": size - 14,
            "ttl": 64,
            "tcp_flags": "PA",
            "payload_size": max(0, size - 40),
            "payload_bytes": _generate_payload_bytes(rng, max(0, size - 40)),
        })

    # Exfiltration phase: large encrypted packets, steady rate
    for i in range(exfil_count):
        base_time += rng.gauss(0.01, 0.002)  # very regular ~100 pps
        base_time = max(base_time, packets[-1]["timestamp"] + 0.001) if packets else base_time

        # Near-MTU packets with high-entropy payloads
        size = rng.randint(1350, 1500)
        payload_size = size - 40

        packets.append({
            "index": normal_count + i,
            "timestamp": base_time,
            "src_ip": campus_ip,
            "dst_ip": exfil_target,
            "src_port": rng.choice([44300, 44301, 44302]),  # reused src ports
            "dst_port": 443,
            "protocol": "TCP",
            "size": size,
            "ip_len": size - 14,
            "ttl": 64,
            "tcp_flags": "PA",
            "payload_size": payload_size,
            "payload_bytes": _generate_payload_bytes(rng, payload_size, high_entropy=True),
        })

    return packets


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------
_SCENARIO_FUNCTIONS = {
    "normal": simulate_normal,
    "ddos": simulate_ddos,
    "scan": simulate_scan,
    "protocol_anomaly": simulate_protocol_anomaly,
    "exfiltration": simulate_exfiltration,
}


def simulate_traffic(
    scenario: str,
    packet_count: int = SIMULATION_PACKET_COUNT,
) -> list[dict]:
    """
    Entry point: generate synthetic traffic for a named scenario.

    Args:
        scenario: One of "normal", "ddos", "scan", "protocol_anomaly", "exfiltration"
        packet_count: Number of packets to generate

    Returns:
        List of packet dictionaries (same schema as pcap_parser output)
    """
    func = _SCENARIO_FUNCTIONS.get(scenario)
    if func is None:
        raise ValueError(
            f"Unknown scenario '{scenario}'. Valid: {list(_SCENARIO_FUNCTIONS.keys())}"
        )
    logger.info(f"Simulating '{scenario}' scenario with {packet_count} packets")
    return func(packet_count)


def get_scenario_descriptions() -> dict[str, dict]:
    """Return human-readable descriptions of each scenario for the UI."""
    return {
        "normal": {
            "name": "Normal Campus Traffic",
            "description": "Steady HTTP/HTTPS-like patterns with typical packet sizes and rates. "
                          "Represents baseline campus network activity.",
            "expected_result": "No anomalies — establishes baseline behavior",
            "icon": "shield-check",
        },
        "ddos": {
            "name": "Volumetric / DDoS-like",
            "description": "Sudden massive spike in packet rate and byte volume from many sources "
                          "targeting a single server. Simulates SYN flood characteristics.",
            "expected_result": "High-severity volumetric anomaly alerts",
            "icon": "alert-triangle",
        },
        "scan": {
            "name": "Port Scan / Reconnaissance",
            "description": "Rapid small packets to many distinct destination ports from a single "
                          "source. Simulates systematic port sweep behavior.",
            "expected_result": "Medium-to-high severity scan detection",
            "icon": "search",
        },
        "protocol_anomaly": {
            "name": "Protocol Anomaly",
            "description": "Unusual protocol distribution with oversized ICMP, exotic protocols "
                          "(GRE, ESP), and unexpected packet sizes. May indicate tunneling.",
            "expected_result": "Protocol anomaly classification",
            "icon": "alert-circle",
        },
        "exfiltration": {
            "name": "Data Exfiltration Pattern",
            "description": "Sustained near-MTU packets with high-entropy payloads to a single "
                          "external destination. Pattern consistent with automated data theft.",
            "expected_result": "Exfiltration pattern alerts with high confidence",
            "icon": "upload-cloud",
        },
    }
