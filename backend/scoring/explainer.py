"""
CampusShield AI — Explainability Engine
=========================================
Generate human-readable explanations of why a traffic window
was flagged as anomalous, by comparing observed features
against baseline statistics.
"""

import logging
from typing import Optional

logger = logging.getLogger(__name__)

# Human-readable feature descriptions
FEATURE_DESCRIPTIONS = {
    "packet_count": "number of packets observed",
    "min_packet_size": "minimum packet size (bytes)",
    "max_packet_size": "maximum packet size (bytes)",
    "mean_packet_size": "average packet size (bytes)",
    "std_packet_size": "packet size variability",
    "packet_size_skewness": "packet size distribution skew",
    "mean_iat": "average time between packets (seconds)",
    "std_iat": "inter-arrival time variability",
    "min_iat": "minimum time between packets",
    "max_iat": "maximum time between packets",
    "burst_count": "number of packet bursts",
    "bytes_per_second": "data throughput (bytes/sec)",
    "packets_per_second": "packet rate (packets/sec)",
    "total_bytes": "total data volume (bytes)",
    "protocol_entropy": "protocol diversity (Shannon entropy)",
    "unique_dst_ports": "number of distinct destination ports",
    "dst_port_entropy": "destination port diversity (Shannon entropy)",
    "tcp_ratio": "fraction of TCP traffic",
    "udp_ratio": "fraction of UDP traffic",
    "payload_entropy": "payload randomness (0=structured, 8=random)",
}


def generate_contributing_factors(
    features: dict,
    deviations: list[dict],
    max_factors: int = 10,
) -> list[dict]:
    """
    From the deviation analysis, produce a ranked list of
    contributing factors suitable for UI display and DB storage.

    Args:
        features: Observed feature values
        deviations: Sorted deviation list from scorer
        max_factors: Maximum number of factors to return

    Returns:
        List of ContributingFactor-ready dicts
    """
    factors = []
    for rank, dev in enumerate(deviations[:max_factors], start=1):
        feature_name = dev["feature_name"]
        factors.append({
            "feature_name": feature_name,
            "observed_value": dev["observed_value"],
            "baseline_value": dev["baseline_mean"],
            "deviation_pct": round(dev["deviation_pct"], 2),
            "contribution_rank": rank,
            "direction": dev["direction"],
            "z_score": round(dev["z_score"], 2),
            "description": FEATURE_DESCRIPTIONS.get(feature_name, feature_name),
        })

    return factors


def generate_explanation(
    features: dict,
    category_result: dict,
    score_result: dict,
    top_n: int = 5,
) -> str:
    """
    Generate a natural-language explanation of the detection.

    Args:
        features: Observed feature values
        category_result: Output from ThreatCategorizer
        score_result: Output from compute_threat_score
        top_n: Number of top factors to mention

    Returns:
        Multi-sentence explanation string
    """
    threat_score = score_result["threat_score"]
    severity = score_result["severity"]
    confidence = score_result["confidence"]
    category_label = category_result["label"]
    category_desc = category_result["description"]
    matching_rules = category_result.get("matching_rules", [])
    deviations = score_result.get("deviations", [])

    lines = []

    # Opening statement
    lines.append(
        f"This traffic window has been classified as a **{category_label}** "
        f"with a threat score of **{threat_score}/100** ({severity} severity) "
        f"and {confidence:.0%} confidence."
    )

    # Category description
    lines.append(f"\n{category_desc}")

    # Rules that triggered
    if matching_rules:
        lines.append("\n**Detection triggers:**")
        for rule in matching_rules:
            lines.append(f"  • {rule}")

    # Top contributing factors
    if deviations:
        lines.append(f"\n**Top {min(top_n, len(deviations))} contributing factors:**")
        for dev in deviations[:top_n]:
            feature_name = dev["feature_name"]
            desc = FEATURE_DESCRIPTIONS.get(feature_name, feature_name)
            observed = dev["observed_value"]
            baseline = dev["baseline_mean"]
            direction = dev["direction"]
            z = dev["z_score"]
            pct = dev["deviation_pct"]

            # Format numbers nicely
            if abs(observed) > 1000:
                obs_str = f"{observed:,.0f}"
                base_str = f"{baseline:,.0f}"
            elif abs(observed) > 1:
                obs_str = f"{observed:.2f}"
                base_str = f"{baseline:.2f}"
            else:
                obs_str = f"{observed:.4f}"
                base_str = f"{baseline:.4f}"

            lines.append(
                f"  {dev.get('contribution_rank', '•')}. **{desc}**: "
                f"{obs_str} ({direction} baseline of {base_str}, "
                f"{abs(pct):.1f}% deviation, {z:.1f}σ)"
            )

    # Score breakdown
    components = score_result.get("components", {})
    if components:
        lines.append("\n**Score breakdown:**")
        lines.append(
            f"  • Anomaly score component: {components.get('anomaly_score', 0):.1f}/100 "
            f"(weight: {score_result['weights']['anomaly_score']:.0%})"
        )
        lines.append(
            f"  • Feature deviation component: {components.get('feature_deviation', 0):.1f}/100 "
            f"(weight: {score_result['weights']['feature_deviation']:.0%})"
        )
        lines.append(
            f"  • Category boost component: {components.get('category_boost', 0):.1f}/100 "
            f"(weight: {score_result['weights']['category_boost']:.0%})"
        )

    # Automated Mitigation Suggestions & Prevention
    from backend.scoring.mitigation import generate_mitigation_plan
    cat_id = category_result.get("category_id", "unclassified")
    mitigation = generate_mitigation_plan(
        category_id=cat_id,
        threat_score=score_result.get("threat_score", 0),
        features=features,
    )

    lines.append("\n🛡️ **Automated Incident Mitigation & Prevention Recommendations:**")
    for act in mitigation.get("immediate_actions", []):
        lines.append(f"  • {act}")

    if mitigation.get("firewall_rule"):
        lines.append("\n**Recommended Firewall Rule (IPTables):**")
        lines.append(f"```bash\n{mitigation['firewall_rule']}\n```")

    if mitigation.get("waf_policy"):
        lines.append("\n**Recommended WAF / Rate-Limiting Policy:**")
        lines.append(f"```nginx\n{mitigation['waf_policy']}\n```")

    return "\n".join(lines)
