"""
CampusShield AI — Application Configuration
============================================
Environment-based configuration with secure defaults.
All sensitive values should be overridden via environment variables in production.
"""

import os
from pathlib import Path

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
UPLOAD_DIR = DATA_DIR / "uploads"
MODEL_DIR = DATA_DIR / "models"
REPORT_DIR = DATA_DIR / "reports"

# Ensure directories exist at import time
for _dir in (DATA_DIR, UPLOAD_DIR, MODEL_DIR, REPORT_DIR):
    _dir.mkdir(parents=True, exist_ok=True)

# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    f"sqlite:///{DATA_DIR / 'campusshield.db'}",
)

# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------
SECRET_KEY = os.getenv(
    "SECRET_KEY",
    "campusshield-dev-secret-change-in-production-82a7f3c1",
)
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("TOKEN_EXPIRE_MINUTES", "480"))

# ---------------------------------------------------------------------------
# CORS
# ---------------------------------------------------------------------------
CORS_ORIGINS: list[str] = os.getenv(
    "CORS_ORIGINS",
    "http://localhost:5173,http://localhost:3000,http://127.0.0.1:5173",
).split(",")

# ---------------------------------------------------------------------------
# Upload Limits
# ---------------------------------------------------------------------------
MAX_UPLOAD_SIZE_MB = int(os.getenv("MAX_UPLOAD_SIZE_MB", "100"))
MAX_UPLOAD_SIZE_BYTES = MAX_UPLOAD_SIZE_MB * 1024 * 1024
ALLOWED_EXTENSIONS = {".pcap", ".pcapng", ".cap"}

# ---------------------------------------------------------------------------
# Detection Defaults
# ---------------------------------------------------------------------------
DEFAULT_CONTAMINATION = float(os.getenv("DEFAULT_CONTAMINATION", "0.05"))
MIN_CONTAMINATION = 0.001
MAX_CONTAMINATION = 0.5
DEFAULT_N_ESTIMATORS = int(os.getenv("N_ESTIMATORS", "200"))
DEFAULT_RANDOM_STATE = 42

# Feature extraction
WINDOW_SIZE_SECONDS = float(os.getenv("WINDOW_SIZE_SECONDS", "10.0"))
BURST_IAT_THRESHOLD = float(os.getenv("BURST_IAT_THRESHOLD", "0.001"))

# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------
SEVERITY_THRESHOLDS = {
    "LOW": (0, 30),
    "MEDIUM": (31, 60),
    "HIGH": (61, 80),
    "CRITICAL": (81, 100),
}

SCORE_WEIGHTS = {
    "anomaly_score": 0.40,
    "feature_deviation": 0.40,
    "category_boost": 0.20,
}

# ---------------------------------------------------------------------------
# Simulation
# ---------------------------------------------------------------------------
SIMULATION_PACKET_COUNT = int(os.getenv("SIM_PACKET_COUNT", "2000"))
SIMULATION_SCENARIOS = [
    "normal",
    "ddos",
    "scan",
    "protocol_anomaly",
    "exfiltration",
]

# ---------------------------------------------------------------------------
# WebSocket
# ---------------------------------------------------------------------------
WS_HEARTBEAT_INTERVAL = int(os.getenv("WS_HEARTBEAT_INTERVAL", "30"))

# ---------------------------------------------------------------------------
# Authorized Users (Configured with Full Admin Privileges)
# ---------------------------------------------------------------------------
DEMO_USERS = [
    {
        "username": os.getenv("ADMIN_USERNAME", "2500040224"),
        "password": os.getenv("ADMIN_PASSWORD", "Bitcoin@100"),
        "email": os.getenv("ADMIN_EMAIL", "2500040224@campusshield.ai"),
        "role": "admin",
        "full_name": os.getenv("ADMIN_FULLNAME", "Lead Security Architect (2500040224)"),
    },
]


