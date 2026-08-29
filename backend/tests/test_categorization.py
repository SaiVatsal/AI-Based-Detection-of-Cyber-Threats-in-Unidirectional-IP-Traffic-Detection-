"""
Tests for threat categorization.
"""

import pytest
from backend.classification.categorizer import ThreatCategorizer


def _make_baseline():
    """Create a realistic baseline stats dict."""
    return {
        "packets_per_second": {"mean": 100, "std": 20, "min": 50, "max": 150, "median": 100},
        "bytes_per_second": {"mean": 40000, "std": 10000, "min": 20000, "max": 60000, "median": 40000},
        "unique_dst_ports": {"mean": 5, "std": 2, "min": 2, "max": 10, "median": 5},
        "dst_port_entropy": {"mean": 1.5, "std": 0.5, "min": 0.5, "max": 3.0, "median": 1.5},
        "protocol_entropy": {"mean": 0.5, "std": 0.2, "min": 0, "max": 1.0, "median": 0.5},
        "tcp_ratio": {"mean": 0.7, "std": 0.1, "min": 0.5, "max": 0.9, "median": 0.7},
        "udp_ratio": {"mean": 0.25, "std": 0.1, "min": 0.1, "max": 0.4, "median": 0.25},
        "payload_entropy": {"mean": 4.0, "std": 1.0, "min": 2.0, "max": 6.0, "median": 4.0},
        "total_bytes": {"mean": 400000, "std": 100000, "min": 200000, "max": 600000, "median": 400000},
        "mean_packet_size": {"mean": 400, "std": 100, "min": 200, "max": 600, "median": 400},
        "std_packet_size": {"mean": 150, "std": 50, "min": 50, "max": 250, "median": 150},
        "packet_count": {"mean": 1000, "std": 200, "min": 500, "max": 1500, "median": 1000},
    }


class TestThreatCategorizer:
    def test_volumetric_detection(self):
        cat = ThreatCategorizer(_make_baseline())
        features = {
            "packets_per_second": 800,  # 8x baseline
            "bytes_per_second": 200000,  # 5x baseline
            "unique_dst_ports": 3,
            "mean_packet_size": 60,
            "protocol_entropy": 0.3,
            "tcp_ratio": 0.9,
            "udp_ratio": 0.1,
            "payload_entropy": 3.0,
            "total_bytes": 500000,
            "dst_port_entropy": 1.0,
            "std_packet_size": 10,
        }
        result = cat.categorize(features, -0.3)
        assert result["category_id"] == "volumetric"
        assert "DDoS-like" in result["label"]

    def test_scan_detection(self):
        cat = ThreatCategorizer(_make_baseline())
        features = {
            "packets_per_second": 120,
            "bytes_per_second": 5000,
            "unique_dst_ports": 50,  # 10x baseline
            "mean_packet_size": 60,  # very small
            "protocol_entropy": 0.3,
            "tcp_ratio": 0.95,
            "udp_ratio": 0.05,
            "payload_entropy": 2.0,
            "total_bytes": 50000,
            "dst_port_entropy": 5.0,
            "std_packet_size": 5,
        }
        result = cat.categorize(features, -0.2)
        assert result["category_id"] == "scan"
        assert "Scan-like" in result["label"]

    def test_protocol_anomaly_detection(self):
        cat = ThreatCategorizer(_make_baseline())
        features = {
            "packets_per_second": 90,
            "bytes_per_second": 35000,
            "unique_dst_ports": 3,
            "mean_packet_size": 400,
            "protocol_entropy": 2.0,  # 4x baseline
            "tcp_ratio": 0.2,  # low TCP
            "udp_ratio": 0.1,  # low UDP → exotic protocols
            "payload_entropy": 5.0,
            "total_bytes": 350000,
            "dst_port_entropy": 1.0,
            "std_packet_size": 200,
        }
        result = cat.categorize(features, -0.2)
        assert result["category_id"] == "protocol_anomaly"

    def test_exfiltration_detection(self):
        cat = ThreatCategorizer(_make_baseline())
        features = {
            "packets_per_second": 110,
            "bytes_per_second": 50000,
            "unique_dst_ports": 2,
            "mean_packet_size": 1400,  # near MTU
            "protocol_entropy": 0.0,
            "tcp_ratio": 1.0,
            "udp_ratio": 0.0,
            "payload_entropy": 7.8,  # high entropy
            "total_bytes": 1500000,  # 3.75x baseline
            "dst_port_entropy": 0.0,
            "std_packet_size": 20,  # very consistent
        }
        result = cat.categorize(features, -0.25)
        assert result["category_id"] == "exfiltration"
        assert "Exfiltration" in result["label"]

    def test_unclassified_anomaly(self):
        cat = ThreatCategorizer(_make_baseline())
        features = {
            "packets_per_second": 110,
            "bytes_per_second": 45000,
            "unique_dst_ports": 6,
            "mean_packet_size": 420,
            "protocol_entropy": 0.6,
            "tcp_ratio": 0.7,
            "udp_ratio": 0.25,
            "payload_entropy": 4.5,
            "total_bytes": 450000,
            "dst_port_entropy": 1.8,
            "std_packet_size": 160,
        }
        result = cat.categorize(features, -0.1)
        assert result["category_id"] == "unclassified"

    def test_hedged_language_in_labels(self):
        """All category labels should use hedged language."""
        categories = ThreatCategorizer.get_all_categories()
        for cat in categories:
            label = cat["label"].lower()
            # Should NOT have definitive claims
            assert "confirmed" not in label
            assert "definitely" not in label

    def test_no_baseline_returns_unclassified(self):
        cat = ThreatCategorizer(baseline_stats=None)
        result = cat.categorize({"packets_per_second": 500}, -0.3)
        assert result["category_id"] == "unclassified"
