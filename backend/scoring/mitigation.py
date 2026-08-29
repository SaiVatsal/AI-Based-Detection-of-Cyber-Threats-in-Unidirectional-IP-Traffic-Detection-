"""
CampusShield AI — Threat Mitigation & Prevention Engine
=========================================================
Generates actionable SOC defense recipes, firewall rules (iptables, nftables),
WAF rate-limiting policies, and unidirectional data diode safeguards for detected threats.
"""

from typing import Any


def generate_mitigation_plan(
    category_id: str,
    threat_score: float,
    features: dict[str, Any],
    source_ips: list[str] | None = None,
    target_port: int = 80,
) -> dict:
    """
    Generate tailored prevention suggestions, firewall rules, and architectural
    safeguards based on the detected threat pattern.
    """
    source_ips = source_ips or ["198.51.100.0/24", "203.0.113.45"]
    primary_src = source_ips[0] if source_ips else "0.0.0.0/0"
    pps = int(features.get("packets_per_second", 0))

    if category_id == "volumetric" or pps > 1000:
        return {
            "category": "Volumetric Anomaly (DDoS)",
            "threat_level": "CRITICAL" if threat_score > 75 else "HIGH",
            "summary": f"Detected high-velocity request surge ({pps:,} req/s) exceeding normal campus baseline.",
            "immediate_actions": [
                f"Apply ingress rate limiting on perimeter gateway to cap traffic at 200 req/s per subnet.",
                f"Drop unauthenticated SYN burst traffic from source subnet {primary_src}.",
                "Engage BGP Anycast null-routing / Cloudflare scrubbing if volume exceeds link capacity.",
                "Verify Data Diode optical TX buffer to prevent hardware packet drops."
            ],
            "firewall_rule": f"# Linux IPTables Ingress Rate Limiter & Drop\niptables -A INPUT -p tcp --dport {target_port} -m limit --limit 150/s --limit-burst 300 -j ACCEPT\niptables -A INPUT -s {primary_src} -p tcp --dport {target_port} -j DROP",
            "waf_policy": f"# Nginx WAF Zone Limiting\nlimit_req_zone $binary_remote_addr zone=campus_limit:10m rate=50r/s;\nlimit_req zone=campus_limit burst=100 nodelay;",
            "data_diode_guidance": "Because this traffic is on the input side of the unidirectional gateway, ensure hardware queue limits are tuned so legitimate mission-critical telemetry is not starved.",
        }

    elif category_id == "scan":
        return {
            "category": "Port & Path Sweep Reconnaissance",
            "threat_level": "HIGH",
            "summary": f"Detected systematic multi-port scanning probe across ports (Unique ports: {features.get('unique_dst_ports', 'Many')}).",
            "immediate_actions": [
                f"Immediately block reconnaissance scanner IP: {primary_src}.",
                "Disable exposed administrative ports (e.g., 22 SSH, 3306 MySQL, 6379 Redis) on gateway interfaces.",
                "Deploy TCP tarpit / port-knocking to neutralize automated scanning bots.",
                "Isolate target subnet segment to prevent lateral movement."
            ],
            "firewall_rule": f"# Instant IP Drop & Port Scan Protection\niptables -I INPUT -s {primary_src} -j DROP\niptables -A INPUT -m recent --name portscan --rcheck --seconds 86400 -j DROP",
            "waf_policy": f"# Block Known Recon Paths\nlocation ~* /((\\.env)|(admin)|(config)|(actuator)|(api/v1/debug)) {{\n    deny all;\n    return 403;\n}}",
            "data_diode_guidance": "Verify that unidirectional gateway only exposes strictly defined UDP/Syslog ports. Close all unused listening sockets.",
        }

    elif category_id == "protocol_anomaly":
        return {
            "category": "Protocol & Malformed Payload Anomaly",
            "threat_level": "HIGH",
            "summary": "Detected non-standard protocol distribution, exotic IP headers, or malformed frame lengths.",
            "immediate_actions": [
                "Enforce strict protocol header validation at the network boundary.",
                "Drop fragmented ICMP / GRE / raw IP encapsulation packets lacking valid checksums.",
                "Verify packet length sanity (discard packets under 40 bytes or exceeding MTU 1500).",
            ],
            "firewall_rule": f"# Drop Malformed & Invalid TCP/IP Flag Packets\niptables -A INPUT -m conntrack --ctstate INVALID -j DROP\niptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP\niptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP",
            "waf_policy": "# Reject Non-Standard HTTP Methods & Enforce TLS 1.3\nif ($request_method !~ ^(GET|POST|HEAD|PUT|DELETE)$) {\n    return 405;\n}",
            "data_diode_guidance": "Hardware data diodes must use protocol-break proxies that terminate raw packets and re-serialize only valid application payloads.",
        }

    elif category_id == "exfiltration":
        return {
            "category": "Data Exfiltration Outflow",
            "threat_level": "HIGH",
            "summary": "Detected sustained large-payload high-entropy transmissions indicating bulk data exfiltration.",
            "immediate_actions": [
                "Temporarily throttle high-volume outbound socket connections from source host.",
                "Inspect payload entropy to verify if unauthorized encrypted archives are being transmitted.",
                "Alert Data Loss Prevention (DLP) team and audit access logs for the originating service.",
            ],
            "firewall_rule": f"# Restrict Bulk Outbound Bandwidth\niptables -A OUTPUT -p tcp --dport {target_port} -m limit --limit 50/s -j ACCEPT",
            "waf_policy": "# Limit Request Body Payload Size\nclient_max_body_size 10M;\nclient_body_buffer_size 128k;",
            "data_diode_guidance": "If this unidirectional link is intended solely for sensor logs, enforce strict schema validation to block arbitrary binary exfiltration.",
        }

    else:
        return {
            "category": "Nominal / Baseline Traffic",
            "threat_level": "LOW",
            "summary": "Traffic patterns remain within normal campus statistical baselines.",
            "immediate_actions": [
                "Continue standard passive telemetry monitoring.",
                "Keep Isolation Forest baseline updated periodically with nominal traffic windows.",
            ],
            "firewall_rule": "# Traffic is nominal. Standard policy:\niptables -P INPUT ACCEPT",
            "waf_policy": "# Default security headers\nadd_header X-Frame-Options SAMEORIGIN;\nadd_header X-Content-Type-Options nosniff;",
            "data_diode_guidance": "Unidirectional data diode optical link functioning with zero detected anomalies.",
        }
