# 🛡️ CampusShield AI

**SIH26145 — AI-Powered Cyber Threat Detection for Unidirectional IP Traffic**

---

## Problem Statement

Conventional IDS tools (Snort, Suricata, Zeek) rely on **bidirectional flow features** — TCP handshakes, request-response correlation, and session reconstruction. Behind a **data diode or unidirectional gateway**, none of that exists. We only see packets flowing in one direction with no return path.

CampusShield AI detects cyber threats using **only unidirectional traffic features** — packet sizes, timing, rates, entropy, and protocol distribution — observable from a single direction.

## Approach

1. **Unidirectional Feature Extraction** — 20 ML-ready features computed from one-way packet metadata only
2. **Isolation Forest** — Unsupervised anomaly detection to learn "normal" baseline and flag statistical outliers
3. **Rule-Based Categorization** — Post-anomaly classification into threat types (DDoS-like, Scan-like, Protocol Anomaly, Exfiltration)
4. **Explainable Scoring** — Normalized 0-100 threat score with contributing factor breakdown
5. **Real-Time Alerts** — WebSocket-driven live alert feed with severity escalation

> ⚠️ **MVP Prototype**: Uses PCAP files and synthetic traffic simulation. No physical data diode required. We make no claims about production detection accuracy without field validation.

---

## Architecture

```
PCAP Upload / Simulation
        │
        ▼
  Packet Processing (scapy / simulator)
        │
        ▼
  Unidirectional Feature Extraction (20 features)
        │
        ▼
  Normalization (StandardScaler)
        │
        ▼
  Isolation Forest Anomaly Detection
        │
        ▼
  Threat Categorization (rule-based)
        │
        ▼
  Threat Scoring (0-100) + Explainability
        │
        ▼
  Alert Generation → WebSocket → Dashboard
                   → SQLite → PDF Reports
```

## Tech Stack

| Layer | Technology |
|:---|:---|
| Backend | Python 3.11+, FastAPI, Uvicorn |
| ML | scikit-learn (IsolationForest), NumPy, Pandas |
| PCAP | scapy |
| Database | SQLite (WAL mode) |
| Auth | JWT (python-jose), bcrypt (passlib) |
| Real-time | FastAPI WebSockets |
| Frontend | React 18, Vite, Recharts, Lucide Icons |
| Reports | ReportLab (PDF) |

---

## Quick Start

### Prerequisites

- Python 3.11+
- Node.js 18+
- pip / virtualenv

### Backend

```bash
cd backend

# Create virtual environment
python -m venv venv
venv\Scripts\activate        # Windows
# source venv/bin/activate   # Linux/macOS

# Install dependencies
pip install -r requirements.txt

# Start server
cd ..
uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000
```

The API documentation is at http://localhost:8000/docs

### Frontend

```bash
cd frontend
npm install
npm run dev
```

Open http://localhost:5173

### Demo Credentials

| Username | Password | Role |
|:---|:---|:---|
| `admin` | `admin123` | Administrator |
| `analyst` | `analyst123` | Security Analyst |

---

## Demo Scenarios

| Scenario | Description | Expected Detection |
|:---|:---|:---|
| **Normal** | Steady HTTP/HTTPS campus traffic | No anomalies (baseline) |
| **DDoS** | Volumetric SYN flood from 500 sources | Volumetric Anomaly alerts |
| **Port Scan** | Sequential port sweep to 1000+ ports | Scan-like Behavior alerts |
| **Protocol Anomaly** | Large ICMP, GRE, exotic protocols | Protocol Anomaly alerts |
| **Exfiltration** | Sustained encrypted data to external host | Exfiltration Pattern alerts |

---

## Unidirectional Features (20)

All features are computable from **one-way traffic only**:

| Category | Features | Why Unidirectional-Safe |
|:---|:---|:---|
| Packet Size | count, min, max, mean, std, skewness | Observed packet sizes — no response needed |
| Timing | mean/std/min/max IAT, burst count | Inter-arrival of observed packets only |
| Volume | bytes/sec, packets/sec, total bytes | One-way throughput |
| Protocol | protocol entropy, port entropy, TCP/UDP ratio | Protocol field in observed packets |
| Payload | payload entropy | Entropy of observed bytes only |

---

## API Endpoints

| Method | Endpoint | Description |
|:---|:---|:---|
| POST | `/api/auth/login` | JWT authentication |
| POST | `/api/auth/register` | Register user (admin only) |
| GET | `/api/auth/me` | Current user profile |
| POST | `/api/traffic/upload` | Upload PCAP file |
| POST | `/api/traffic/simulate/{scenario}` | Start simulation |
| GET | `/api/traffic/sessions` | List sessions |
| GET | `/api/traffic/scenarios` | Available scenarios |
| GET | `/api/detection/config` | Detection configuration |
| PUT | `/api/detection/config` | Update sensitivity |
| GET | `/api/detection/results/{session_id}` | Detection results |
| GET | `/api/alerts` | List alerts |
| PUT | `/api/alerts/{id}/acknowledge` | Acknowledge alert |
| GET | `/api/alerts/stats` | Alert statistics |
| POST | `/api/reports/generate/{session_id}` | Generate PDF report |
| WS | `/ws/alerts?token=JWT` | Real-time alert stream |

---

## Testing

```bash
cd backend
python -m pytest tests/ -v
```

### Test Coverage

- **test_features.py** — Feature extraction correctness, all 20 features
- **test_detection.py** — Isolation Forest training, prediction, persistence
- **test_categorization.py** — All threat category triggers, hedged language
- **test_scoring.py** — Score normalization, severity mapping
- **test_unidirectional.py** — **CRITICAL**: Proves pipeline works identically with/without return traffic

---

## Project Structure

```
campusshield-ai/
├── README.md
├── backend/
│   ├── main.py                 # FastAPI entry point
│   ├── config.py               # Configuration
│   ├── requirements.txt
│   ├── api/router.py           # Route aggregator
│   ├── auth/                   # JWT + bcrypt auth
│   ├── database/               # SQLAlchemy models, CRUD, audit
│   ├── ingestion/              # PCAP parser, traffic simulator
│   ├── features/               # Feature extraction + normalization
│   ├── detection/              # Isolation Forest wrapper
│   ├── classification/         # Rule-based categorizer
│   ├── scoring/                # Threat scorer + explainer
│   ├── alerts/                 # Alert manager + WebSocket
│   ├── reports/                # PDF report generator
│   └── tests/                  # Test suite
└── frontend/
    ├── src/
    │   ├── pages/              # Dashboard, Demo, Alerts, Reports
    │   ├── components/         # KPI cards, charts, pipeline viz
    │   ├── hooks/              # WebSocket hook
    │   └── services/           # API client
    └── index.html
```

---

## Limitations & Honest Scope

1. **No real data diode** — Simulates unidirectional constraint in software
2. **Synthetic traffic** — Demo scenarios are statistically designed, not captured from real attacks
3. **No flow correlation** — Cannot correlate related flows across time windows
4. **Rule-based categorization** — Heuristic thresholds, not ML-trained classifiers
5. **Single-model approach** — One Isolation Forest; production would use ensemble methods
6. **SQLite** — Adequate for MVP; production would use PostgreSQL with connection pooling

---

## License

Built for Smart India Hackathon 2024 — Problem Statement SIH26145.
