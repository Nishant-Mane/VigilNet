import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "nids_alerts.db")


def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,

        src_ip TEXT NOT NULL,
        dst_ip TEXT NOT NULL,
        src_port INTEGER NOT NULL,
        dst_port INTEGER NOT NULL,
        protocol TEXT NOT NULL,

        duration REAL NOT NULL,
        packet_count INTEGER NOT NULL,

        attack_probability REAL NOT NULL,
        prediction INTEGER NOT NULL,
        severity TEXT NOT NULL
    )
    """)

    conn.commit()
    conn.close()

    print(f"[DB INIT] SQLite database ready at: {DB_PATH}")


if __name__ == "__main__":
    init_db()
