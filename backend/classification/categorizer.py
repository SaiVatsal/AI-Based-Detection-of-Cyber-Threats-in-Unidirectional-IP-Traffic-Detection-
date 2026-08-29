"""
CampusShield AI — Threat Categorizer
======================================
Rule-based post-anomaly classification strictly aligned with the official
Smart India Hackathon Problem Statement (SIH26145).

Detects all 6 official threat classes:
  a. Volumetric / Protocol DDoS
  b. Botnet C2 Beaconing
  c. DGA Domains and DNS Tunnelling
  d. Malware inside Encrypted Sessions (Metadata-only)
  e. Reconnaissance and Port Scanning
  f. Data Exfiltration
"""

import logging
from typing import Optional, List, Dict

logger = logging.getLogger(__name__)


class ThreatCategorizer:
    """
    Rule-based categorizer that classifies anomalous windows
    based on how their features deviate from baseline statistics.
    """

    CATEGORIES = [
        {
            "id": "volumetric",
            "label": "Volumetric Anomaly (DDoS-like / SIH-a)",
            "description": (
                "Massive spike in packet rate and/or byte volume (SYN floods, "
                "UDP reflection/amplification, or spoofed-source floods)."
            ),
            "severity_boost": 1.2,
        },
        {
            "id": "scan",
            "label": "Scan-like Behavior (Reconnaissance / SIH-e)",
            "description": (
                "Fan-out probing patterns from a source across multiple destination "
                "ports or hosts using rapid small probe frames."
            ),
            "severity_boost": 1.0,
        },
        {
            "id": "protocol_anomaly",
            "label": "Protocol Anomaly (Encrypted Malware / SIH-d)",
            "description": (
                "Unusual protocol distribution or transport metadata anomalies "
                "(TLS/QUIC sequence anomalies) without decrypting payload."
            ),
            "severity_boost": 0.9,
        },
        {
            "id": "exfiltration",
            "label": "Potential Exfiltration Pattern (SIH-f)",
            "description": (
                "Asymmetric flow-volume anomalies with high payload Shannon entropy "
                "and sustained MTU packet sizes."
            ),
            "severity_boost": 1.3,
        },
        {
            "id": "botnet_c2",
            "label": "Botnet C2 Beaconing (SIH-b)",
            "description": (
                "Periodicity and inter-arrival timing analysis showing regular "
                "interval heartbeats toward command-and-control infrastructure."
            ),
            "severity_boost": 1.1,
        },
        {
            "id": "dns_tunneling",
            "label": "DGA Domains & DNS Tunnelling (SIH-c)",
            "description": (
                "High Shannon entropy on query strings, query-length anomalies, "
                "or anomalous UDP port 53 tunnel behavior."
            ),
            "severity_boost": 1.2,
        },
        {
            "id": "unclassified",
            "label": "Unclassified Anomaly",
            "description": (
                "Statistical anomaly detected but does not match specific known "
                "signatures. Requires manual SOC review."
            ),
            "severity_boost": 0.7,
        },
    ]

    def __init__(self, baseline_stats: Optional[dict] = None):
        self.baseline = baseline_stats or {}

    @classmethod
    def get_all_categories(cls) -> List[Dict]:
        """Return all available category definitions."""
        return cls.CATEGORIES

    def set_baseline(self, baseline_stats: dict) -> None:
        self.baseline = baseline_stats
        logger.info(f"Updated categorizer baseline ({len(baseline_stats)} features)")

    def categorize(self, features: dict, anomaly_score: float) -> dict:
        if not self.baseline:
            return self._make_result("unclassified", ["No baseline available"])

        matching_rules = []

        pps = features.get("packets_per_second", 0)
        bps = features.get("bytes_per_second", 0)
        baseline_pps = self.baseline.get("packets_per_second", {}).get("mean", 1)
        baseline_bps = self.baseline.get("bytes_per_second", {}).get("mean", 1)
        pps_ratio = pps / max(baseline_pps, 0.001)
        bps_ratio = bps / max(baseline_bps, 0.001)

        unique_ports = features.get("unique_dst_ports", 0)
        baseline_ports = self.baseline.get("unique_dst_ports", {}).get("mean", 1)
        mean_pkt_size = features.get("mean_packet_size", 0)
        port_entropy = features.get("dst_port_entropy", 0)
        baseline_port_entropy = self.baseline.get("dst_port_entropy", {}).get("mean", 0)
        ports_ratio = unique_ports / max(baseline_ports, 1)

        payload_entropy = features.get("payload_entropy", 0)
        proto_entropy = features.get("protocol_entropy", 0)
        baseline_proto = self.baseline.get("protocol_entropy", {}).get("mean", 0)
        tcp_ratio = features.get("tcp_ratio", 0)
        udp_ratio = features.get("udp_ratio", 0)
        baseline_tcp = self.baseline.get("tcp_ratio", {}).get("mean", 0.7)

        mean_iat = features.get("mean_iat", 0)
        std_iat = features.get("std_iat", 0)

        # 1. Volumetric / Protocol DDoS (SIH-a)
        if pps_ratio > 5.0 and bps_ratio > 3.0:
            matching_rules.append(f"PPS {pps_ratio:.1f}x baseline, BPS {bps_ratio:.1f}x baseline")
            return self._make_result("volumetric", matching_rules)
        if pps_ratio > 8.0:
            matching_rules.append(f"PPS {pps_ratio:.1f}x baseline (extreme rate flood)")
            return self._make_result("volumetric", matching_rules)

        # 2. Reconnaissance & Port Scanning (SIH-e)
        if ports_ratio > 3.0 and mean_pkt_size < 120:
            matching_rules.append(f"Unique dst ports {ports_ratio:.1f}x baseline, small probe frames")
            return self._make_result("scan", matching_rules)
        if port_entropy > max(baseline_port_entropy * 2.0, 2.0) and mean_pkt_size < 160:
            matching_rules.append(f"High port entropy {port_entropy:.2f}")
            return self._make_result("scan", matching_rules)

        # 3. Protocol Anomaly (SIH-d)
        if proto_entropy > max(baseline_proto * 2.0, 1.5):
            matching_rules.append(f"Protocol entropy {proto_entropy:.2f} vs baseline {baseline_proto:.2f}")
            return self._make_result("protocol_anomaly", matching_rules)

        if (tcp_ratio + udp_ratio) < 0.5 and baseline_tcp > 0.5:
            matching_rules.append(f"Unusual protocols dominate (TCP+UDP = {tcp_ratio + udp_ratio:.0%})")
            return self._make_result("protocol_anomaly", matching_rules)

        # 4. Data Exfiltration (SIH-f)
        if payload_entropy > 7.0 and mean_pkt_size > 500:
            matching_rules.append(f"High payload entropy ({payload_entropy:.2f} bits/byte) with large packets")
            return self._make_result("exfiltration", matching_rules)

        # 5. DGA Domains & DNS Tunnelling (SIH-c)
        if udp_ratio > 0.70 and payload_entropy > 6.5:
            matching_rules.append("High UDP ratio with elevated payload entropy (DNS tunnel indicator)")
            return self._make_result("dns_tunneling", matching_rules)

        # 6. Botnet C2 Beaconing (SIH-b)
        if std_iat < 0.005 and mean_iat > 0.010 and pps < 50:
            matching_rules.append("Extremely low IAT standard deviation (regular periodic beaconing)")
            return self._make_result("botnet_c2", matching_rules)

        return self._make_result("unclassified", ["Generic statistical outlier"])

    def _make_result(self, category_id: str, matching_rules: list) -> dict:
        cat_def = next(
            (c for c in self.CATEGORIES if c["id"] == category_id),
            self.CATEGORIES[-1],
        )
        return {
            "category_id": cat_def["id"],
            "label": cat_def["label"],
            "description": cat_def["description"],
            "severity_boost": cat_def["severity_boost"],
            "matching_rules": matching_rules,
        }
