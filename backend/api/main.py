import os
import sqlite3
import json
from fastapi import FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware

# ---------------- PATHS ----------------
BASE_DIR = os.path.dirname(os.path.dirname(__file__))

DB_PATH = os.path.join(BASE_DIR, "storage", "nids_alerts.db")

ACTIVE_FLOWS_PATH = os.path.join(
    BASE_DIR,
    "storage",
    "runtime",
    "active_flows.json"
)

LIVE_TRAFFIC_PATH = os.path.join(
    BASE_DIR,
    "storage",
    "runtime",
    "live_traffic.json"
)

CAPTURE_STATUS_PATH = os.path.join(
    BASE_DIR,
    "storage",
    "runtime",
    "capture_status.json"
)

# ---------------- APP ----------------
app = FastAPI(
    title="NIDS Backend API",
    version="1.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------- DB ----------------
def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

# ---------------- ALERTS ----------------
@app.get("/alerts")
def get_alerts(limit: int = Query(50, ge=1, le=500)):
    """
    Returns the latest IDS alerts.
    This is the PRIMARY endpoint consumed by the frontend.
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT
            id,
            timestamp,
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            protocol,
            attack_probability,
            prediction,
            severity
        FROM alerts
        ORDER BY id DESC
        LIMIT ?
        """,
        (limit,),
    )

    rows = cursor.fetchall()
    conn.close()

    alerts = []
    for row in rows:
        alerts.append({
            "id": row["id"],
            "timestamp": row["timestamp"],
            "src_ip": row["src_ip"],
            "src_port": row["src_port"],
            "dst_ip": row["dst_ip"],
            "dst_port": row["dst_port"],
            "protocol": row["protocol"],
            "attack_probability": row["attack_probability"],
            "prediction": row["prediction"],
            "severity": row["severity"],
        })

    return alerts

# ---------------- ACTIVE FLOWS ----------------
@app.get("/active-flows")
def get_active_flows():
    """
    Snapshot of currently active flows (no ML, no mutation).
    """
    if not os.path.exists(ACTIVE_FLOWS_PATH):
        return []

    try:
        with open(ACTIVE_FLOWS_PATH, "r") as f:
            return json.load(f)
    except Exception:
        return []

# ---------------- LIVE TRAFFIC ----------------
@app.get("/live-traffic")
def get_live_traffic():
    """
    Packet counters over a short rolling window.
    """
    if not os.path.exists(LIVE_TRAFFIC_PATH):
        return {
            "timestamp": None,
            "total_packets": 0,
            "tcp_packets": 0,
            "udp_packets": 0,
        }

    try:
        with open(LIVE_TRAFFIC_PATH, "r") as f:
            return json.load(f)
    except Exception:
        return {
            "timestamp": None,
            "total_packets": 0,
            "tcp_packets": 0,
            "udp_packets": 0,
        }

# ---------------- CAPTURE STATUS ----------------
@app.get("/capture-status")
def get_capture_status():
    """
    Indicates whether live capture is running.
    """
    if not os.path.exists(CAPTURE_STATUS_PATH):
        return {
            "running": False,
            "timestamp": None
        }

    try:
        with open(CAPTURE_STATUS_PATH, "r") as f:
            return json.load(f)
    except Exception:
        return {
            "running": False,
            "timestamp": None
        }
