import sqlite3
import os
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(__file__), "nids_alerts.db")


def insert_alert(flow, ml_result):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute(
        """
        INSERT INTO alerts (
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
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            datetime.utcnow().isoformat(),
            flow.src_ip,
            flow.dst_ip,
            flow.src_port,
            flow.dst_port,
            flow.protocol,
            flow.duration(),
            flow.fwd_packets + flow.bwd_packets,
            ml_result["attack_probability"],
            ml_result["prediction"],
            ml_result["severity"],
        )
    )

    conn.commit()
    conn.close()
