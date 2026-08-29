"""
CampusShield AI — Threat Categorizer
======================================
Rule-based post-anomaly classification using feature thresholds.

This module is ONLY called for windows already flagged as anomalous
by the Isolation Forest. It answers "what KIND of anomaly is this?"
using feature deviation heuristics against the learned baseline.

IMPORTANT: Categories use hedged language ("DDoS-like", "Scan-like")
because we cannot prove intent from one-way traffic alone.
"""

import logging
from typing import Optional

logger = logging.getLogger(__name__)


class ThreatCategorizer:
    """
    Rule-based categorizer that classifies anomalous windows
    based on how their features deviate from baseline statistics.
    """

    # Category definitions with conditions
    CATEGORIES = [
        {
            "id": "volumetric",
            "label": "Volumetric Anomaly (DDoS-like)",
            "description": (
                "Massive spike in packet rate and/or byte volume, consistent "
                "with flood-style denial-of-service behavior."
            ),
            "severity_boost": 1.2,
        },
        {
            "id": "scan",
            "label": "Scan-like Behavior",
            "description": (
                "Rapid small packets targeting many distinct destination ports, "
                "consistent with port scanning or reconnaissance."
            ),
            "severity_boost": 1.0,
        },
        {
            "id": "protocol_anomaly",
            "label": "Protocol Anomaly",
            "description": (
                "Unusual protocol distribution or unexpected packet sizes "
                "for the observed protocols. May indicate tunneling or "
                "protocol abuse."
            ),
            "severity_boost": 0.9,
        },
        {
            "id": "exfiltration",
            "label": "Potential Exfiltration Pattern",
            "description": (
                "Sustained large packets with high-entropy payloads to a "
                "concentrated destination. Pattern consistent with automated "
                "data transfer."
            ),
            "severity_boost": 1.3,
        },
        {
            "id": "unclassified",
            "label": "Unclassified Anomaly",
            "description": (
                "Statistical anomaly detected but does not match known "
                "threat patterns. Requires manual investigation."
            ),
            "severity_boost": 0.7,
        },
    ]

    def __init__(self, baseline_stats: Optional[dict] = None):
        """
        Args:
            baseline_stats: Dictionary of {feature_name: {mean, std, min, max}}
                          from compute_baseline_stats() on normal traffic.
        """
        self.baseline = baseline_stats or {}

    def set_baseline(self, baseline_stats: dict) -> None:
        """Update the baseline statistics."""
        self.baseline = baseline_stats
        logger.info(f"Updated categorizer baseline ({len(baseline_stats)} features)")

    def categorize(self, features: dict, anomaly_score: float) -> dict:
        """
        Classify an anomalous traffic window into a threat category.

        Args:
            features: Feature dict for the window
            anomaly_score: Raw anomaly score from Isolation Forest

        Returns:
            Dict with keys:
                category_id, label, description, severity_boost,
                matching_rules (list of rule descriptions that triggered)
        """
        if not self.baseline:
            return self._make_result("unclassified", ["No baseline available"])

        matching_rules = []

        # -----------------------------------------------------------------
        # Rule 1: Volumetric / DDoS-like
        # Triggers when packet rate AND byte rate are both significantly
        # above baseline means.
        # -----------------------------------------------------------------
        pps = features.get("packets_per_second", 0)
        bps = features.get("bytes_per_second", 0)
        baseline_pps = self.baseline.get("packets_per_second", {}).get("mean", 1)
        baseline_bps = self.baseline.get("bytes_per_second", {}).get("mean", 1)

        pps_ratio = pps / max(baseline_pps, 0.001)
        bps_ratio = bps / max(baseline_bps, 0.001)

        if pps_ratio > 5.0 and bps_ratio > 3.0:
            matching_rules.append(
                f"Packets/sec {pps_ratio:.1f}x baseline, "
                f"Bytes/sec {bps_ratio:.1f}x baseline"
            )
            return self._make_result("volumetric", matching_rules)

        # Also catch high PPS alone (possible small-packet flood)
        if pps_ratio > 10.0:
            matching_rules.append(
                f"Packets/sec {pps_ratio:.1f}x baseline (extreme rate)"
            )
            return self._make_result("volumetric", matching_rules)

        # -----------------------------------------------------------------
        # Rule 2: Scan-like Behavior
        # Triggers when many unique destination ports AND small packet sizes.
        # -----------------------------------------------------------------
        unique_ports = features.get("unique_dst_ports", 0)
        baseline_ports = self.baseline.get("unique_dst_ports", {}).get("mean", 1)
        mean_pkt_size = features.get("mean_packet_size", 0)
        port_entropy = features.get("dst_port_entropy", 0)
        baseline_port_entropy = self.baseline.get("dst_port_entropy", {}).get("mean", 0)

        ports_ratio = unique_ports / max(baseline_ports, 1)

        if ports_ratio > 3.0 and mean_pkt_size < 100:
            matching_rules.append(
                f"Unique dst ports {ports_ratio:.1f}x baseline, "
                f"mean packet size {mean_pkt_size:.0f}B (small probes)"
            )
            return self._make_result("scan", matching_rules)

        if port_entropy > baseline_port_entropy * 2.0 and mean_pkt_size < 150:
            matching_rules.append(
                f"Port entropy {port_entropy:.2f} vs baseline "
                f"{baseline_port_entropy:.2f}, small packets"
            )
            return self._make_result("scan", matching_rules)

        # -----------------------------------------------------------------
        # Rule 3: Protocol Anomaly
        # Triggers when protocol distribution entropy is unusually high
        # or unusual protocols dominate.
        # -----------------------------------------------------------------
        proto_entropy = features.get("protocol_entropy", 0)
        baseline_proto = self.baseline.get("protocol_entropy", {}).get("mean", 0)
        tcp_ratio = features.get("tcp_ratio", 0)
        udp_ratio = features.get("udp_ratio", 0)
        baseline_tcp = self.baseline.get("tcp_ratio", {}).get("mean", 0.7)

        if proto_entropy > max(baseline_proto * 2.0, 1.5):
            matching_rules.append(
                f"Protocol entropy {proto_entropy:.2f} vs baseline "
                f"{baseline_proto:.2f}"
            )
            return self._make_result("protocol_anomaly", matching_rules)

        # Low TCP+UDP ratio means unusual protocols dominate
        if (tcp_ratio + udp_ratio) < 0.5 and baseline_tcp > 0.5:
            matching_rules.append(
                f"TCP+UDP ratio {tcp_ratio + udp_ratio:.2f} (unusual protocols dominate)"
            )
            return self._make_result("protocol_anomaly", matching_rules)

        # -----------------------------------------------------------------
        # Rule 4: Potential Exfiltration
        # Triggers when payload entropy is very high AND total volume
        # is significantly above baseline.
        # -----------------------------------------------------------------
        payload_entropy = features.get("payload_entropy", 0)
        total_bytes = features.get("total_bytes", 0)
        baseline_bytes = self.baseline.get("total_bytes", {}).get("mean", 1)
        mean_size = features.get("mean_packet_size", 0)
        std_size = features.get("std_packet_size", 0)
        baseline_mean_size = self.baseline.get("mean_packet_size", {}).get("mean", 400)

        bytes_ratio = total_bytes / max(baseline_bytes, 1)

        if payload_entropy > 7.0 and bytes_ratio > 2.0:
            matching_rules.append(
                f"Payload entropy {payload_entropy:.2f} (near-random), "
                f"volume {bytes_ratio:.1f}x baseline"
            )
            return self._make_result("exfiltration", matching_rules)

        # High entropy + large consistent packets (low std/mean ratio)
        if payload_entropy > 7.0 and mean_size > baseline_mean_size * 1.5:
            cv = std_size / max(mean_size, 1)
            if cv < 0.15:  # very consistent packet sizes
                matching_rules.append(
                    f"Payload entropy {payload_entropy:.2f}, "
                    f"mean size {mean_size:.0f}B (large, consistent), "
                    f"CV={cv:.3f}"
                )
                return self._make_result("exfiltration", matching_rules)

        # -----------------------------------------------------------------
        # Fallback: Unclassified Anomaly
        # -----------------------------------------------------------------
        matching_rules.append(
            "Anomaly detected but no specific threat pattern matched"
        )
        return self._make_result("unclassified", matching_rules)

    def _make_result(self, category_id: str, rules: list[str]) -> dict:
        """Build the categorization result dict."""
        cat = next(
            (c for c in self.CATEGORIES if c["id"] == category_id),
            self.CATEGORIES[-1],
        )
        return {
            "category_id": cat["id"],
            "label": cat["label"],
            "description": cat["description"],
            "severity_boost": cat["severity_boost"],
            "matching_rules": rules,
        }

    @staticmethod
    def get_all_categories() -> list[dict]:
        """Return all defined threat categories for UI display."""
        return ThreatCategorizer.CATEGORIES.copy()
