"""
CampusShield AI — Unidirectional Feature Extraction
=====================================================
Extract ML-ready features from one-way traffic data.

DESIGN PRINCIPLE:
    Every feature computed here is derivable from packets observed in
    ONE direction only. We never reference return traffic, round-trip
    times, bidirectional flow volumes, or session reconstruction.

    Each feature has a documented rationale for why it's unidirectional-safe.
"""

import math
import logging
from collections import Counter
from typing import Optional

import numpy as np
import pandas as pd

from backend.config import WINDOW_SIZE_SECONDS, BURST_IAT_THRESHOLD

logger = logging.getLogger(__name__)

# Feature names in canonical order (used for model input)
FEATURE_NAMES = [
    # Packet size features
    "packet_count",
    "min_packet_size",
    "max_packet_size",
    "mean_packet_size",
    "std_packet_size",
    "packet_size_skewness",
    # Timing features
    "mean_iat",
    "std_iat",
    "min_iat",
    "max_iat",
    "burst_count",
    # Volume features
    "bytes_per_second",
    "packets_per_second",
    "total_bytes",
    # Protocol features
    "protocol_entropy",
    "unique_dst_ports",
    "dst_port_entropy",
    "tcp_ratio",
    "udp_ratio",
    # Payload features
    "payload_entropy",
]


def _shannon_entropy(counts: list[int]) -> float:
    """
    Compute Shannon entropy from a list of occurrence counts.
    Returns entropy in bits.
    """
    total = sum(counts)
    if total == 0:
        return 0.0
    entropy = 0.0
    for c in counts:
        if c > 0:
            p = c / total
            entropy -= p * math.log2(p)
    return entropy


def _byte_entropy(data: bytes) -> float:
    """
    Compute Shannon entropy of raw bytes.
    Max entropy = 8.0 bits (uniform random bytes).
    Typical encrypted/compressed data: 7.5-8.0
    Typical text: 3.0-5.0
    """
    if not data:
        return 0.0
    counts = Counter(data)
    return _shannon_entropy(list(counts.values()))


def _compute_skewness(values: np.ndarray) -> float:
    """
    Compute Fisher-Pearson skewness coefficient.
    Positive = right-skewed (many small, few large).
    """
    n = len(values)
    if n < 3:
        return 0.0
    mean = np.mean(values)
    std = np.std(values, ddof=1)
    if std == 0:
        return 0.0
    return (n / ((n - 1) * (n - 2))) * np.sum(((values - mean) / std) ** 3)


def extract_features_from_window(packets: list[dict]) -> dict[str, float]:
    """
    Extract the full feature vector from a list of packets in one time window.

    Args:
        packets: List of packet dictionaries (from pcap_parser or simulator)

    Returns:
        Dictionary mapping feature names to float values.
        All features are unidirectional-safe by design.
    """
    if not packets:
        return {name: 0.0 for name in FEATURE_NAMES}

    n = len(packets)

    # ---------------------------------------------------------------
    # Packet Size Features
    # SAFE: computed purely from observed packet sizes
    # ---------------------------------------------------------------
    sizes = np.array([p["size"] for p in packets], dtype=np.float64)

    packet_count = float(n)
    min_packet_size = float(np.min(sizes))
    max_packet_size = float(np.max(sizes))
    mean_packet_size = float(np.mean(sizes))
    std_packet_size = float(np.std(sizes, ddof=1)) if n > 1 else 0.0
    packet_size_skewness = _compute_skewness(sizes)

    # ---------------------------------------------------------------
    # Timing Features
    # SAFE: inter-arrival times between consecutive OBSERVED packets.
    # We never measure round-trip delay or request-response latency.
    # ---------------------------------------------------------------
    timestamps = np.array([p["timestamp"] for p in packets], dtype=np.float64)
    timestamps.sort()

    if n > 1:
        iats = np.diff(timestamps)
        iats = iats[iats >= 0]  # guard against unsorted data

        if len(iats) > 0:
            mean_iat = float(np.mean(iats))
            std_iat = float(np.std(iats, ddof=1)) if len(iats) > 1 else 0.0
            min_iat = float(np.min(iats))
            max_iat = float(np.max(iats))

            # Burst detection: count transitions from non-burst to burst
            burst_mask = iats < BURST_IAT_THRESHOLD
            burst_transitions = np.diff(burst_mask.astype(int))
            burst_count = float(np.sum(burst_transitions == 1))
            # If first IAT is a burst, count it
            if burst_mask[0]:
                burst_count += 1.0
        else:
            mean_iat = std_iat = min_iat = max_iat = 0.0
            burst_count = 0.0
    else:
        mean_iat = std_iat = min_iat = max_iat = 0.0
        burst_count = 0.0

    # ---------------------------------------------------------------
    # Volume Features
    # SAFE: total observed volume / observation window
    # ---------------------------------------------------------------
    total_bytes = float(np.sum(sizes))
    duration = float(timestamps[-1] - timestamps[0]) if n > 1 else 1.0
    duration = max(duration, 0.001)  # avoid division by zero

    bytes_per_second = total_bytes / duration
    packets_per_second = packet_count / duration

    # ---------------------------------------------------------------
    # Protocol Features
    # SAFE: based on protocol field in observed packets only
    # ---------------------------------------------------------------
    protocols = [p["protocol"] for p in packets]
    proto_counts = Counter(protocols)
    protocol_entropy = _shannon_entropy(list(proto_counts.values()))

    tcp_count = proto_counts.get("TCP", 0)
    udp_count = proto_counts.get("UDP", 0)
    tcp_ratio = tcp_count / n
    udp_ratio = udp_count / n

    # Destination port analysis
    dst_ports = [p["dst_port"] for p in packets if p["dst_port"] is not None]
    unique_dst_ports = float(len(set(dst_ports)))

    if dst_ports:
        port_counts = Counter(dst_ports)
        dst_port_entropy = _shannon_entropy(list(port_counts.values()))
    else:
        dst_port_entropy = 0.0

    # ---------------------------------------------------------------
    # Payload Entropy
    # SAFE: computed from observed payload bytes only
    # ---------------------------------------------------------------
    all_payload_bytes = b""
    for p in packets:
        if p.get("payload_bytes"):
            pb = p["payload_bytes"]
            if isinstance(pb, (bytes, bytearray)):
                all_payload_bytes += pb

    payload_entropy = _byte_entropy(all_payload_bytes)

    # ---------------------------------------------------------------
    # Assemble feature vector
    # ---------------------------------------------------------------
    return {
        "packet_count": packet_count,
        "min_packet_size": min_packet_size,
        "max_packet_size": max_packet_size,
        "mean_packet_size": mean_packet_size,
        "std_packet_size": std_packet_size,
        "packet_size_skewness": packet_size_skewness,
        "mean_iat": mean_iat,
        "std_iat": std_iat,
        "min_iat": min_iat,
        "max_iat": max_iat,
        "burst_count": burst_count,
        "bytes_per_second": bytes_per_second,
        "packets_per_second": packets_per_second,
        "total_bytes": total_bytes,
        "protocol_entropy": protocol_entropy,
        "unique_dst_ports": unique_dst_ports,
        "dst_port_entropy": dst_port_entropy,
        "tcp_ratio": tcp_ratio,
        "udp_ratio": udp_ratio,
        "payload_entropy": payload_entropy,
    }


def extract_features_windowed(
    packets: list[dict],
    window_size: float = WINDOW_SIZE_SECONDS,
) -> list[dict]:
    """
    Segment packets into time windows and extract features per window.

    Args:
        packets: Full list of packet dicts
        window_size: Window duration in seconds

    Returns:
        List of feature dictionaries, one per window.
        Each dict includes 'window_index', 'window_start', 'window_end'
        plus all FEATURE_NAMES.
    """
    if not packets:
        return []

    # Sort by timestamp
    sorted_pkts = sorted(packets, key=lambda p: p["timestamp"])
    start_time = sorted_pkts[0]["timestamp"]
    end_time = sorted_pkts[-1]["timestamp"]

    windows = []
    window_idx = 0
    current_start = start_time

    while current_start <= end_time:
        current_end = current_start + window_size
        window_pkts = [
            p for p in sorted_pkts
            if current_start <= p["timestamp"] < current_end
        ]

        if window_pkts:
            features = extract_features_from_window(window_pkts)
            features["window_index"] = window_idx
            features["window_start"] = current_start
            features["window_end"] = current_end
            features["window_packet_count"] = len(window_pkts)
            windows.append(features)
            window_idx += 1

        current_start = current_end

    logger.info(
        f"Extracted features from {len(windows)} windows "
        f"({window_size}s each, {len(packets)} total packets)"
    )
    return windows


def features_to_dataframe(feature_windows: list[dict]) -> pd.DataFrame:
    """
    Convert list of feature dicts to a pandas DataFrame with only
    the ML feature columns (excludes window metadata).
    """
    if not feature_windows:
        return pd.DataFrame(columns=FEATURE_NAMES)

    df = pd.DataFrame(feature_windows)
    # Return only the feature columns in canonical order
    return df[FEATURE_NAMES].fillna(0.0)


def compute_baseline_stats(feature_windows: list[dict]) -> dict[str, dict]:
    """
    Compute baseline statistics (mean, std) for each feature
    from a set of 'normal' traffic windows. Used later for
    deviation-based scoring and explainability.
    """
    if not feature_windows:
        return {}

    df = features_to_dataframe(feature_windows)
    stats = {}
    for col in FEATURE_NAMES:
        stats[col] = {
            "mean": float(df[col].mean()),
            "std": float(df[col].std()) if len(df) > 1 else 0.0,
            "min": float(df[col].min()),
            "max": float(df[col].max()),
            "median": float(df[col].median()),
        }
    return stats
