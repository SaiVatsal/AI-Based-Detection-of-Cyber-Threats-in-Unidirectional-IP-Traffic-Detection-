# 🛡️ CampusShield AI — AI-Based Cyber Threat Detection in Unidirectional IP Traffic

> **Smart India Hackathon (SIH) — Problem Statement ID: SIH26145**  
> **Domain**: Defense & Cyber Security · High-Assurance Enclaves & Hardware Data Diodes

[![Live Demo](https://img.shields.io/badge/Live%20Deployment-Vercel-00f0ff?style=flat-square&logo=vercel)](https://ai-based-detection-of-cyber-threats-seven.vercel.app)
[![Build Status](https://img.shields.io/badge/Build-Passing%20(0%20errors)-00ff88?style=flat-square)](https://github.com/SaiVatsal/AI-Based-Detection-of-Cyber-Threats-in-Unidirectional-IP-Traffic-Detection-)
[![Test Suite](https://img.shields.io/badge/Pytest%20Suite-35%2F35%20Passed-00ff88?style=flat-square)](https://github.com/SaiVatsal/AI-Based-Detection-of-Cyber-Threats-in-Unidirectional-IP-Traffic-Detection-)
[![Python](https://img.shields.io/badge/Python-3.11+-38bdf8?style=flat-square&logo=python)](https://python.org)
[![React](https://img.shields.io/badge/Frontend-React%2019%20%2B%20Vite-61dafb?style=flat-square&logo=react)](https://react.dev)

---

## 📌 Executive Summary & Background

Critical infrastructure facilities (nuclear plants, aerospace command centers, defense telemetry gateways, and high-security campus networks) deploy **Hardware Optical Data Diodes** and **passive optical taps** to copy internal link traffic into an isolated monitoring enclave. 

By physical law, a data diode permits light transmission in **one direction only** (Tx $\rightarrow$ Rx). This physically prevents external attackers from pivoting back into the operational core network.

### The Engineering Challenge
Conventional Network Intrusion Detection Systems (such as **Snort**, **Suricata**, or **Zeek**) fail completely on unidirectional links:
- They require bi-directional state tracking (TCP 3-way handshakes: `SYN` $\rightarrow$ `SYN-ACK` $\rightarrow$ `ACK`).
- They expect round-trip response measurements to confirm host liveness and session termination.
- In a data diode tap, return traffic is **physically non-existent** ($0$ reverse packets).

**CampusShield AI** is an AI/ML intelligence pipeline and Security Operations Center (SOC) platform engineered to detect, categorize, score, and generate actionable defense playbooks for network threats **purely from passive, one-way IP telemetry**.

---

## ⚡ Key Capabilities at a Glance

- 🔬 **100% Unidirectional-Safe Feature Extraction**: Extracts 20 statistical and information-theoretic features per sliding time window ($\Delta t$) with zero reverse channel dependency.
- 🌲 **Unsupervised Isolation Forest Anomaly Engine**: Detects zero-day anomalies and outliers without requiring labeled attack datasets or broken TCP session tables.
- 🎯 **All 6 SIH Problem Statement Threat Classes Covered**:
  1. **Volumetric & Protocol DDoS**: High-frequency SYN floods, UDP amplification, and spoofed-source floods (tested at 2,000+ req/s).
  2. **Botnet C2 Beaconing**: Inter-arrival time ($\Delta t$) variance analysis detecting periodic heartbeats.
  3. **DGA Domains & DNS Tunnelling**: Payload Shannon entropy and query length anomaly detection on port 53.
  4. **Malware inside Encrypted Sessions**: TLS 1.3 / QUIC metadata inspection without decrypting private payloads.
  5. **Reconnaissance & Port Sweeps**: Fan-out detection across destination ports and subnets.
  6. **Data Exfiltration**: Asymmetric flow volumes and high-entropy MTU payload transfers.
- 🌐 **Real-Time URL & 2,000+ Req/s Rate Inspector**: Inspects any live domain (e.g., Google, Gemini, internal gateways), measures request velocity, flags statistical departures ($18\sigma$), and generates instant firewall rules.
- 🛡️ **Automated Mitigation Playbooks**: Generates copy-paste **Linux IPTables drop rules**, **Nginx WAF rate-limiting configurations**, and hardware optical buffer guidance.
- 📥 **One-Click DevOps Script Export**: Instantly exports `mitigate_threat.sh` and `waf_policy.json`.
- 📊 **Executive PDF Reports**: Generates formal incident audit reports using ReportLab.

---

## 🏛️ System Architecture

```
                       PASSIVE NETWORK INGESTION (DATA DIODE / TAP)
             [ Physical Tx Optical Fiber ] ──────────> [ Promiscuous Rx Port ]
                                                              │
                                                              ▼
                                                   [ Raw Packet Telemetry ]
                                                              │
    ┌─────────────────────────────────────────────────────────┴──────────────────────────────────────────┐
    │                                                                                                    │
    ▼                                                                                                    ▼
[ PCAP File Parser ]                                                                          [ Passive Webhook Ingest ]
(Scapy Streaming)                                                                             (/api/traffic/live-collector)
    │                                                                                                    │
    └─────────────────────────────────────────────────────────┬──────────────────────────────────────────┘
                                                              │
                                                              ▼
                                           [ Sliding Window Ingestion (1.0s) ]
                                                              │
                                                              ▼
                                      [ Unidirectional Feature Extractor (20 Features) ]
                                      • Shannon Entropy H(X)     • Inter-Arrival Time (Δt)
                                      • Packet Size Skewness     • Protocol & Port Spread
                                                              │
                                                              ▼
                                            [ Dynamic Baseline Normalization ]
                                                (StandardScaler Z-Scores)
                                                              │
                                                              ▼
                                        [ Unsupervised Isolation Forest (100 Trees) ]
                                          Anomaly Scoring: s(x, n) = 2^(-E(h(x))/c(n))
                                                              │
                                                              ▼
                                        [ Rule-Based SIH26145 Threat Categorizer ]
                                        (DDoS, Botnet C2, DNS Tunnel, Recon, Exfil)
                                                              │
                                                              ▼
                                              [ Threat Scorer & Explainer ]
                                                Fused Score (0 - 100 Scale)
                                                              │
                                                              ▼
                                       [ Automated Mitigation & Defense Playbook ]
                                        • Linux IPTables Drop Rules
                                        • Nginx WAF Zone Limiting Policies
                                        • Hardware Optical Diode Buffer Advice
                                                              │
                                                              ▼
                                   ┌──────────────────────────┴──────────────────────────┐
                                   ▼                                                     ▼
                      [ WebSocket Event Stream ]                             [ SQLite WAL Persistence ]
                           (/ws/alerts)                                      • Audit Log History
                                   │                                         • Incident Records
                                   ▼                                         • Executive PDF Generator
                    [ SOC Dark Cyber Dashboard ]
                    (React 19 + Vite + Recharts)
```

---

## 📐 Mathematical Formulation & Feature Engineering

### 1. Shannon Entropy ($H(X)$)
Measures byte randomness in payloads and destination port spreads:
$$H(X) = -\sum_{i=0}^{255} P(b_i) \log_2 P(b_i)$$
- **Structured HTTP Text**: $H(X) \approx 3.5 - 4.5\text{ bits/byte}$
- **Encrypted / Exfiltrated Payloads**: $H(X) \approx 7.8 - 7.99\text{ bits/byte}$

### 2. Inter-Arrival Time ($\Delta t$) & Rate Velocity (PPS)
Arrival timestamps $[t_1, t_2, \dots, t_n]$ are processed incrementally:
$$\Delta t_i = t_i - t_{i-1}, \quad \text{PPS} = \frac{N}{\sum_{i=1}^N \Delta t_i}$$
- **Nominal Campus Baseline**: $\Delta t \approx 0.010\text{s}$ ($\sim 100\text{ req/s}$)
- **Volumetric DDoS Attack**: $\Delta t \le 0.0004\text{s}$ ($2,000+\text{ req/s}$, producing an $18.4\sigma$ deviation)

### 3. Isolation Forest Anomaly Scoring
$$s(x, n) = 2^{-\frac{E(h(x))}{c(n)}}$$
Where $E(h(x))$ is the average path depth to isolate observation $x$ across 100 decision trees. Anomalies isolate near the root ($s(x) > 0.70$).

### 4. Fused Threat Score (0–100)
$$\text{Threat Score} = (0.40 \times S_{\text{isolation}}) + (0.35 \times S_{\text{deviation}}) + (0.25 \times S_{\text{category}})$$

---

## 📊 The 20 Unidirectional Features

| Index | Feature Name | Category | Mathematical Description |
|:---:|:---|:---|:---|
| 1 | `packet_count` | Rate | Total observed packets in 1.0s window |
| 2 | `total_bytes` | Volume | Total bytes ingested in window |
| 3 | `bytes_per_second` | Velocity | Byte throughput ($BPS$) |
| 4 | `packets_per_second` | Velocity | Packet rate ($PPS$) |
| 5 | `min_packet_size` | Size | Minimum observed frame length |
| 6 | `max_packet_size` | Size | Maximum observed frame length |
| 7 | `mean_packet_size` | Size | $\mu$ of packet lengths |
| 8 | `std_packet_size` | Size | $\sigma$ of packet lengths |
| 9 | `packet_size_skewness` | Size | Third standardized moment of sizes |
| 10 | `min_iat` | Timing | Minimum inter-arrival time $\Delta t$ |
| 11 | `max_iat` | Timing | Maximum inter-arrival time $\Delta t$ |
| 12 | `mean_iat` | Timing | Mean inter-arrival time ($\overline{\Delta t}$) |
| 13 | `std_iat` | Timing | Jitter / variance in packet arrival intervals |
| 14 | `burst_count` | Timing | Rapid bursts ($\Delta t < 1\text{ms}$) |
| 15 | `unique_dst_ports` | Port | Count of distinct destination ports |
| 16 | `dst_port_entropy` | Port | Shannon entropy across target ports |
| 17 | `protocol_entropy` | Protocol | Shannon entropy across IP protocols |
| 18 | `tcp_ratio` | Protocol | Fraction of TCP frames ($N_{\text{tcp}} / N_{\text{total}}$) |
| 19 | `udp_ratio` | Protocol | Fraction of UDP frames ($N_{\text{udp}} / N_{\text{total}}$) |
| 20 | `payload_entropy` | Payload | Shannon byte entropy of raw payloads |

---

## 💻 Tech Stack & Dependencies

- **Core Backend**: Python 3.11+, FastAPI (Async ASGI), Uvicorn
- **Machine Learning**: scikit-learn (`IsolationForest`), NumPy, Pandas, SciPy
- **Packet Ingestion**: Scapy
- **Database**: SQLite 3 with Write-Ahead Logging (WAL) & SQLAlchemy ORM
- **Authentication**: JWT (HMAC-SHA256 via `python-jose`), Passlib with `bcrypt` (12 rounds)
- **Reporting**: ReportLab (Vector PDF Generation)
- **Frontend SPA**: React 19, Vite, Recharts, Lucide React
- **Styling**: Ultra-Dark Obsidian SOC Design System (Vanilla CSS Custom Properties)
- **Test Harness**: Pytest, Pytest-Asyncio, HTTPX

---

## 🚀 Quick Start Guide

### Prerequisites
- Python 3.11+
- Node.js 18+
- Git

### 1. Clone the Repository
```bash
git clone https://github.com/SaiVatsal/AI-Based-Detection-of-Cyber-Threats-in-Unidirectional-IP-Traffic-Detection-.git
cd AI-Based-Detection-of-Cyber-Threats-in-Unidirectional-IP-Traffic-Detection-
```

### 2. Backend Setup
```bash
# Create and activate virtual environment
python -m venv venv
# On Windows:
venv\Scripts\activate
# On Linux/macOS:
source venv/bin/activate

# Install dependencies
pip install -r backend/requirements.txt

# Launch FastAPI Server
uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000
```
API Swagger documentation is live at: `http://localhost:8000/docs`

### 3. Frontend Setup
```bash
cd frontend
npm install
npm run dev
```
Open **`http://localhost:5173`** in your browser.

---

## 🔐 Credentials

| User ID / Username | Password | Role | Access Level |
|:---|:---|:---|:---|
| **`2500040224`** | **`Bitcoin@100`** | `admin` | **Master SOC Access** |

*Note: Self-service registration is also available via the Sign Up tab on the login portal.*

---

## 🧪 Automated Testing & Verification

Run the full test suite verifying 100% unidirectional compliance:

```bash
python -m pytest backend/tests/ -v
```

### Key Test Suites:
- `test_unidirectional.py`: **Mathematical Guarantee Test** — Verifies that feature extraction yields identical values with and without return traffic.
- `test_features.py`: Tests all 20 unidirectional feature extractors, byte entropy, and sliding windows.
- `test_categorization.py`: Validates detection logic across all 6 SIH threat categories.
- `test_scoring.py`: Tests score normalization, $Z$-score deviations, and severity mapping.
- `test_detection.py`: Tests Isolation Forest anomaly scoring and contamination tuning.

---

## 🌐 Cloud Deployment

### Deploying to Vercel
1. Import repository on [Vercel](https://vercel.com/new).
2. Root Directory: `./` (Vercel automatically detects `vercel.json`).
3. Click **Deploy**.

---

## 👥 Authors & Acknowledgments

- **Developed for**: Smart India Hackathon (SIH) — Problem Statement **SIH26145**
- **Domain**: Unidirectional IP Traffic Cyber Threat Detection
- **License**: MIT Open Source License
