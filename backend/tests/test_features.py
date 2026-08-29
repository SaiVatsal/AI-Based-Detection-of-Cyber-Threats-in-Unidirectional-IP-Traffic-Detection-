"""
Tests for unidirectional feature extraction.
Verifies all features are computable from one-way traffic.
"""

import pytest
import time
import math
from backend.features.extractor import (
    extract_features_from_window,
    extract_features_windowed,
    compute_baseline_stats,
    features_to_dataframe,
    FEATURE_NAMES,
    _shannon_entropy,
    _byte_entropy,
)


def _make_packet(
    timestamp=None, size=200, protocol="TCP", dst_port=80,
    src_ip="10.0.0.1", dst_ip="192.168.1.1", payload_bytes=None,
):
    """Helper to create a minimal packet dict."""
    return {
        "index": 0,
        "timestamp": timestamp or time.time(),
        "size": size,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": 12345,
        "dst_port": dst_port,
        "protocol": protocol,
        "ip_len": size - 14,
        "ttl": 64,
        "tcp_flags": "PA" if protocol == "TCP" else None,
        "payload_size": max(0, size - 40),
        "payload_bytes": payload_bytes or b"Hello World " * 10,
    }


class TestFeatureExtraction:
    """Test that all features are extractable from one-way packets."""

    def test_empty_packets_returns_zeros(self):
        features = extract_features_from_window([])
        assert all(v == 0.0 for v in features.values())
        assert set(features.keys()) == set(FEATURE_NAMES)

    def test_single_packet_produces_valid_features(self):
        pkt = _make_packet()
        features = extract_features_from_window([pkt])
        assert features["packet_count"] == 1.0
        assert features["mean_packet_size"] == pkt["size"]
        assert features["std_packet_size"] == 0.0  # no variance with 1 packet

    def test_all_feature_names_present(self):
        packets = [_make_packet(timestamp=time.time() + i * 0.01) for i in range(10)]
        features = extract_features_from_window(packets)
        for name in FEATURE_NAMES:
            assert name in features, f"Missing feature: {name}"
            assert isinstance(features[name], float), f"{name} is not float"

    def test_packet_size_features(self):
        packets = [
            _make_packet(timestamp=time.time() + i * 0.01, size=s)
            for i, s in enumerate([100, 200, 300, 400, 500])
        ]
        features = extract_features_from_window(packets)
        assert features["min_packet_size"] == 100
        assert features["max_packet_size"] == 500
        assert features["mean_packet_size"] == 300
        assert features["std_packet_size"] > 0

    def test_timing_features_with_bursts(self):
        base = time.time()
        # Create burst: 5 packets very close, then gap, then 5 more
        packets = []
        for i in range(5):
            packets.append(_make_packet(timestamp=base + i * 0.0001))  # burst
        for i in range(5):
            packets.append(_make_packet(timestamp=base + 1.0 + i * 0.0001))  # burst after gap
        features = extract_features_from_window(packets)
        assert features["mean_iat"] > 0
        assert features["burst_count"] >= 1

    def test_protocol_entropy(self):
        base = time.time()
        # All TCP → entropy should be 0
        tcp_only = [_make_packet(timestamp=base + i * 0.01, protocol="TCP") for i in range(10)]
        features_tcp = extract_features_from_window(tcp_only)
        assert features_tcp["protocol_entropy"] == 0.0
        assert features_tcp["tcp_ratio"] == 1.0

        # Mixed protocols → entropy should be > 0
        mixed = []
        for i in range(10):
            proto = ["TCP", "UDP", "ICMP"][i % 3]
            mixed.append(_make_packet(timestamp=base + i * 0.01, protocol=proto, dst_port=80 if proto != "ICMP" else None))
        features_mixed = extract_features_from_window(mixed)
        assert features_mixed["protocol_entropy"] > 0

    def test_payload_entropy_structured_vs_random(self):
        base = time.time()
        # Structured payload (low entropy)
        structured = [
            _make_packet(timestamp=base + i * 0.01, payload_bytes=b"AAAA" * 64)
            for i in range(5)
        ]
        # Random payload (high entropy)
        import os
        random_bytes = os.urandom(256)
        random_pkts = [
            _make_packet(timestamp=base + i * 0.01, payload_bytes=random_bytes)
            for i in range(5)
        ]
        f_struct = extract_features_from_window(structured)
        f_random = extract_features_from_window(random_pkts)
        assert f_random["payload_entropy"] > f_struct["payload_entropy"]

    def test_dst_port_entropy(self):
        base = time.time()
        # Many unique ports → high entropy
        many_ports = [
            _make_packet(timestamp=base + i * 0.01, dst_port=i + 1)
            for i in range(50)
        ]
        features = extract_features_from_window(many_ports)
        assert features["unique_dst_ports"] == 50
        assert features["dst_port_entropy"] > 4.0  # high

    def test_no_bidirectional_fields_accessed(self):
        """
        CRITICAL: Verify feature extraction never references return traffic.
        Our packets have no 'reverse_*' or 'response_*' fields.
        """
        pkt = _make_packet()
        # Remove any hypothetical bidirectional fields
        for key in list(pkt.keys()):
            if "reverse" in key or "response" in key or "return" in key:
                del pkt[key]
        # Should still extract all features without error
        features = extract_features_from_window([pkt])
        assert len(features) == len(FEATURE_NAMES)


class TestWindowedExtraction:
    def test_windowed_extraction_produces_windows(self):
        base = time.time()
        packets = [_make_packet(timestamp=base + i * 0.5) for i in range(100)]
        windows = extract_features_windowed(packets, window_size=5.0)
        assert len(windows) > 0
        assert "window_index" in windows[0]

    def test_features_to_dataframe(self):
        base = time.time()
        packets = [_make_packet(timestamp=base + i * 0.1) for i in range(20)]
        windows = extract_features_windowed(packets, window_size=1.0)
        df = features_to_dataframe(windows)
        assert list(df.columns) == FEATURE_NAMES
        assert len(df) == len(windows)


class TestBaselineStats:
    def test_baseline_computation(self):
        base = time.time()
        packets = [_make_packet(timestamp=base + i * 0.1) for i in range(50)]
        windows = extract_features_windowed(packets, window_size=2.0)
        stats = compute_baseline_stats(windows)
        assert len(stats) == len(FEATURE_NAMES)
        for name in FEATURE_NAMES:
            assert "mean" in stats[name]
            assert "std" in stats[name]


class TestEntropyFunctions:
    def test_shannon_entropy_uniform(self):
        # Uniform distribution of 4 categories → 2 bits
        e = _shannon_entropy([25, 25, 25, 25])
        assert abs(e - 2.0) < 0.01

    def test_shannon_entropy_single(self):
        e = _shannon_entropy([100])
        assert e == 0.0

    def test_byte_entropy_random(self):
        import os
        e = _byte_entropy(os.urandom(10000))
        assert e > 7.5  # should be near 8.0

    def test_byte_entropy_constant(self):
        e = _byte_entropy(b"\x00" * 1000)
        assert e == 0.0
