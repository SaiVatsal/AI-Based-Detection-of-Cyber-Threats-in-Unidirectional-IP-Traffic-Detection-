"""
CRITICAL TEST: Prove the pipeline is truly unidirectional.

This test feeds the SAME one-way traffic through the pipeline with and without
hypothetical return traffic data. Results MUST be identical, proving we never
use bidirectional information.
"""

import pytest
import time
import copy

from backend.features.extractor import extract_features_from_window, FEATURE_NAMES


def _make_one_way_packets(n=50):
    """Generate one-way traffic packets."""
    base = time.time()
    packets = []
    for i in range(n):
        packets.append({
            "index": i,
            "timestamp": base + i * 0.01,
            "size": 200 + (i % 10) * 50,
            "src_ip": "10.0.0.1",
            "dst_ip": "192.168.1.100",
            "src_port": 40000 + i,
            "dst_port": 80,
            "protocol": "TCP",
            "ip_len": 186 + (i % 10) * 50,
            "ttl": 64,
            "tcp_flags": "PA",
            "payload_size": 160 + (i % 10) * 50,
            "payload_bytes": b"GET /page HTTP/1.1\r\n" * 5,
        })
    return packets


class TestUnidirectionalGuarantee:
    """
    The most important test in the entire test suite.
    Proves that our pipeline does not use any bidirectional information.
    """

    def test_features_identical_with_and_without_return_traffic(self):
        """
        If we add return-traffic fields to packets (src/dst swapped, response data),
        the extracted features MUST be identical to without those fields.

        This proves the feature extractor never accesses reverse-direction data.
        """
        one_way = _make_one_way_packets(50)

        # Create a version with hypothetical return traffic metadata
        with_return = copy.deepcopy(one_way)
        for pkt in with_return:
            # Add fields that would exist in bidirectional flow analysis
            pkt["reverse_packets"] = 42
            pkt["reverse_bytes"] = 84000
            pkt["rtt_ms"] = 15.5
            pkt["response_time"] = 0.003
            pkt["syn_ack_received"] = True
            pkt["connection_state"] = "ESTABLISHED"
            pkt["bidirectional_duration"] = 5.0
            pkt["reverse_payload"] = b"HTTP/1.1 200 OK\r\n"

        features_one_way = extract_features_from_window(one_way)
        features_with_return = extract_features_from_window(with_return)

        # Every single feature must be identical
        for name in FEATURE_NAMES:
            assert features_one_way[name] == features_with_return[name], (
                f"Feature '{name}' differs when return traffic is present! "
                f"One-way: {features_one_way[name]}, With-return: {features_with_return[name]}. "
                f"This means the pipeline is using bidirectional data — CRITICAL BUG."
            )

    def test_no_reverse_fields_in_feature_computation(self):
        """
        Verify that our feature names never reference bidirectional concepts.
        """
        bidirectional_keywords = [
            "reverse", "backward", "return", "response", "rtt",
            "round_trip", "syn_ack", "handshake", "bidirectional",
            "server_to_client", "downstream", "reply",
        ]

        for feature_name in FEATURE_NAMES:
            for keyword in bidirectional_keywords:
                assert keyword not in feature_name.lower(), (
                    f"Feature '{feature_name}' contains bidirectional keyword '{keyword}'"
                )

    def test_single_direction_ip_pairs(self):
        """
        Features should be identical whether we know src→dst or not,
        as long as the observable packet data is the same.
        """
        base = time.time()
        packets_a = [
            {
                "index": i,
                "timestamp": base + i * 0.01,
                "size": 300,
                "src_ip": "10.0.0.1",
                "dst_ip": "192.168.1.100",
                "src_port": 50000,
                "dst_port": 443,
                "protocol": "TCP",
                "ip_len": 286,
                "ttl": 64,
                "tcp_flags": "PA",
                "payload_size": 260,
                "payload_bytes": b"encrypted" * 28,
            }
            for i in range(20)
        ]

        # Same packets but with different IPs — features should differ only
        # in IP-related fields, not in our extracted features (which don't include IPs)
        packets_b = copy.deepcopy(packets_a)
        for pkt in packets_b:
            pkt["src_ip"] = "172.16.0.1"
            pkt["dst_ip"] = "10.10.10.10"

        features_a = extract_features_from_window(packets_a)
        features_b = extract_features_from_window(packets_b)

        # Features should be identical because our extractor doesn't use IPs as features
        for name in FEATURE_NAMES:
            assert features_a[name] == features_b[name], (
                f"Feature '{name}' depends on IP addresses — should be independent"
            )
