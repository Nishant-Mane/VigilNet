import os
import sqlite3
from fastapi import FastAPI, Query

BASE_DIR = os.path.dirname(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, "storage", "nids_alerts.db")

app = FastAPI(title="NIDS Backend API", version="1.0")


def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


@app.get("/alerts")
def get_alerts(limit: int = Query(50, ge=1, le=500)):
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT
            id,
            timestamp,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
            duration,
            packet_count,
            attack_probability,
            prediction,
            severity
        FROM alerts
        ORDER BY id DESC
        LIMIT ?
        """,
        (limit,)
    )

    rows = cursor.fetchall()
    conn.close()

    return [dict(row) for row in rows]
