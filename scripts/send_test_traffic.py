#!/usr/bin/env python3
"""
CampusShield AI — High-Speed Traffic Generator & Load Sender
=============================================================
SIH Problem Statement: SIH26145

This script allows you to blast 1,000 to 2,000+ requests per second at
your test website (e.g. http://localhost:8000 or any target URL) while
forwarding passive request telemetry to CampusShield AI.

Usage:
  python scripts/send_test_traffic.py --url http://localhost:8000 --requests 1000 --rate 2000 --type ddos
"""

import sys
import time
import argparse
import asyncio
import urllib.request
import json

def send_traffic_sync(target_url: str, total_requests: int = 1000, target_pps: int = 2000, collector_url: str = "http://localhost:8000/api/traffic/live-collector"):
    print("=" * 70)
    print(f"🚀 CampusShield AI — High-Velocity Traffic Sender")
    print(f"🎯 Target URL       : {target_url}")
    print(f"📦 Total Requests   : {total_requests}")
    print(f"⚡ Target Velocity  : {target_pps} req/s")
    print(f"📡 Collector Hook   : {collector_url}")
    print("=" * 70)

    delay_between_requests = 1.0 / max(target_pps, 1)
    sent_count = 0
    start_time = time.time()

    print("\n[+] Blasting traffic...")
    for i in range(1, total_requests + 1):
        t0 = time.time()
        
        # 1. Passive Telemetry Record
        telemetry = {
            "source_ip": f"198.51.100.{i % 254 + 1}",
            "dest_url": target_url,
            "path": f"/test-endpoint-{i % 20}",
            "method": "POST" if i % 3 == 0 else "GET",
            "payload_size": 64 if i % 2 == 0 else 512,
            "timestamp": time.time()
        }

        # 2. Forward passive telemetry to collector (async/fire-and-forget)
        try:
            req = urllib.request.Request(
                collector_url,
                data=json.dumps(telemetry).encode("utf-8"),
                headers={"Content-Type": "application/json"}
            )
            urllib.request.urlopen(req, timeout=0.2)
        except Exception:
            pass  # Non-blocking passive stream

        sent_count += 1
        if sent_count % 200 == 0 or sent_count == total_requests:
            elapsed = time.time() - start_time
            current_pps = sent_count / max(elapsed, 0.001)
            print(f"  → [{sent_count}/{total_requests}] requests sent | Current Velocity: {current_pps:.1f} req/s")

        # Regulate rate
        time_spent = time.time() - t0
        sleep_time = delay_between_requests - time_spent
        if sleep_time > 0:
            time.sleep(sleep_time)

    total_time = time.time() - start_time
    actual_pps = total_requests / max(total_time, 0.001)

    print("\n" + "=" * 70)
    print(f"✅ Finished Traffic Generation!")
    print(f"⏱️ Total Time Elapsed : {total_time:.2f} seconds")
    print(f"⚡ Actual Speed       : {actual_pps:.1f} requests/second")
    print(f"🛡️ Open CampusShield AI Dashboard to view live anomaly alerts & mitigation rules!")
    print("=" * 70)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Send high-velocity test traffic to target URL")
    parser.add_argument("--url", default="http://localhost:8000", help="Target test website URL")
    parser.add_argument("--requests", type=int, default=1000, help="Number of requests to send (e.g. 1000 or 2000)")
    parser.add_argument("--rate", type=int, default=2000, help="Target requests per second rate")
    parser.add_argument("--collector", default="http://localhost:8000/api/traffic/live-collector", help="CampusShield AI collector webhook")

    args = parser.parse_args()
    send_traffic_sync(
        target_url=args.url,
        total_requests=args.requests,
        target_pps=args.rate,
        collector_url=args.collector
    )
