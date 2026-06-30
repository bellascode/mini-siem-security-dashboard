import os
import sqlite3
from pathlib import Path


DB_PATH = Path(os.getenv("SIEM_DB_PATH", "siem.db"))


def get_connection():
    """
    Opens a connection to the SQLite database.

    timeout=10 helps avoid immediate database locking errors when
    the Flask dashboard and real-time monitor are using the database
    at the same time.
    """
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn


def column_exists(conn, table_name, column_name):
    """
    Checks whether a column already exists in a table.

    This is used for simple database migrations while the project is
    still being developed.
    """
    rows = conn.execute(f"PRAGMA table_info({table_name})").fetchall()

    for row in rows:
        if row["name"] == column_name:
            return True

    return False


def init_db():
    """
    Creates database tables if they do not already exist.
    """
    with get_connection() as conn:
        conn.execute("PRAGMA journal_mode=WAL")

        conn.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                source TEXT NOT NULL,
                event_type TEXT NOT NULL,
                ip TEXT,
                username TEXT,
                method TEXT,
                path TEXT,
                status_code INTEGER,
                raw_log TEXT NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                alert_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                ip TEXT,
                description TEXT NOT NULL,
                evidence_count INTEGER DEFAULT 0,
                alert_key TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)

        if not column_exists(conn, "alerts", "alert_key"):
            conn.execute("""
                ALTER TABLE alerts
                ADD COLUMN alert_key TEXT
            """)

        if not column_exists(conn, "alerts", "updated_at"):
            conn.execute("""
                ALTER TABLE alerts
                ADD COLUMN updated_at TEXT
            """)

        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_events_ip
            ON events(ip)
        """)

        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_events_type
            ON events(event_type)
        """)

        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_events_timestamp
            ON events(timestamp)
        """)

        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_alerts_ip
            ON alerts(ip)
        """)

        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_alerts_type
            ON alerts(alert_type)
        """)

        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_alerts_severity
            ON alerts(severity)
        """)

        conn.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS idx_alerts_alert_key
            ON alerts(alert_key)
        """)


def reset_db():
    """
    Deletes the database and recreates it.

    Useful while testing.
    """
    db_files = [
        DB_PATH,
        Path(str(DB_PATH) + "-wal"),
        Path(str(DB_PATH) + "-shm"),
    ]

    for db_file in db_files:
        if db_file.exists():
            db_file.unlink()

    init_db()


def insert_event(event):
    """
    Inserts one parsed event into the database.
    """
    with get_connection() as conn:
        conn.execute("""
            INSERT INTO events (
                timestamp,
                source,
                event_type,
                ip,
                username,
                method,
                path,
                status_code,
                raw_log
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            event["timestamp"],
            event["source"],
            event["event_type"],
            event.get("ip"),
            event.get("username"),
            event.get("method"),
            event.get("path"),
            event.get("status_code"),
            event["raw_log"],
        ))


def insert_events(events):
    """
    Inserts many parsed events into the database.
    """
    with get_connection() as conn:
        conn.executemany("""
            INSERT INTO events (
                timestamp,
                source,
                event_type,
                ip,
                username,
                method,
                path,
                status_code,
                raw_log
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, [
            (
                event["timestamp"],
                event["source"],
                event["event_type"],
                event.get("ip"),
                event.get("username"),
                event.get("method"),
                event.get("path"),
                event.get("status_code"),
                event["raw_log"],
            )
            for event in events
        ])


def build_alert_key(alert):
    """
    Builds a stable deduplication key for alerts.

    Example:
        SSH Brute Force|185.220.101.45

    This prevents the same alert type for the same IP from being inserted
    over and over during real-time monitoring.
    """
    if alert.get("alert_key"):
        return alert["alert_key"]

    alert_type = alert.get("alert_type", "unknown_alert")
    ip = alert.get("ip") or "unknown_ip"

    return f"{alert_type}|{ip}"


def _upsert_alert(conn, alert):
    """
    Inserts a new alert if it is new.

    If the same alert already exists, it updates the timestamp,
    description, severity, and evidence count instead of inserting
    a duplicate row.

    Returns True if a new alert was inserted.
    Returns False if an existing alert was updated.
    """
    alert_key = build_alert_key(alert)

    cursor = conn.execute("""
        INSERT OR IGNORE INTO alerts (
            timestamp,
            alert_type,
            severity,
            ip,
            description,
            evidence_count,
            alert_key,
            updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
    """, (
        alert["timestamp"],
        alert["alert_type"],
        alert["severity"],
        alert.get("ip"),
        alert["description"],
        alert.get("evidence_count", 0),
        alert_key,
    ))

    if cursor.rowcount == 1:
        return True

    conn.execute("""
        UPDATE alerts
        SET
            timestamp = ?,
            severity = ?,
            description = ?,
            evidence_count = MAX(COALESCE(evidence_count, 0), ?),
            updated_at = CURRENT_TIMESTAMP
        WHERE alert_key = ?
    """, (
        alert["timestamp"],
        alert["severity"],
        alert["description"],
        alert.get("evidence_count", 0),
        alert_key,
    ))

    return False


def insert_alert(alert):
    """
    Inserts or updates one alert.

    Returns True if a new alert was inserted.
    Returns False if an existing alert was updated.
    """
    with get_connection() as conn:
        return _upsert_alert(conn, alert)


def insert_alerts(alerts):
    """
    Inserts or updates many alerts.

    Returns only the alerts that were newly inserted.
    """
    inserted_alerts = []

    with get_connection() as conn:
        for alert in alerts:
            was_inserted = _upsert_alert(conn, alert)

            if was_inserted:
                inserted_alerts.append(alert)

    return inserted_alerts


def count_events():
    """
    Returns the number of events currently stored.
    """
    with get_connection() as conn:
        row = conn.execute("""
            SELECT COUNT(*) AS total
            FROM events
        """).fetchone()

        return row["total"]


def count_alerts():
    """
    Returns the number of alerts currently stored.
    """
    with get_connection() as conn:
        row = conn.execute("""
            SELECT COUNT(*) AS total
            FROM alerts
        """).fetchone()

        return row["total"]


def fetch_recent_events(limit=20):
    """
    Returns the most recent events.
    """
    with get_connection() as conn:
        rows = conn.execute("""
            SELECT
                id,
                timestamp,
                source,
                event_type,
                ip,
                username,
                method,
                path,
                status_code
            FROM events
            ORDER BY id DESC
            LIMIT ?
        """, (limit,)).fetchall()

        return [dict(row) for row in rows]


def fetch_recent_alerts(limit=20):
    """
    Returns the most recent alerts.
    """
    with get_connection() as conn:
        rows = conn.execute("""
            SELECT
                id,
                timestamp,
                alert_type,
                severity,
                ip,
                description,
                evidence_count,
                alert_key,
                updated_at
            FROM alerts
            ORDER BY timestamp DESC, id DESC
            LIMIT ?
        """, (limit,)).fetchall()

        return [dict(row) for row in rows]


def fetch_all_events():
    """
    Returns all events in insertion order.

    This is useful for running detection against stored events.
    """
    with get_connection() as conn:
        rows = conn.execute("""
            SELECT
                id,
                timestamp,
                source,
                event_type,
                ip,
                username,
                method,
                path,
                status_code,
                raw_log
            FROM events
            ORDER BY id ASC
        """).fetchall()

        return [dict(row) for row in rows]


def fetch_top_ips(limit=5):
    """
    Returns the most common source IPs.
    """
    with get_connection() as conn:
        rows = conn.execute("""
            SELECT
                ip,
                COUNT(*) AS total
            FROM events
            WHERE ip IS NOT NULL
            GROUP BY ip
            ORDER BY total DESC
            LIMIT ?
        """, (limit,)).fetchall()

        return [dict(row) for row in rows]


def fetch_alert_counts_by_type():
    """
    Returns alert counts grouped by alert type.
    """
    with get_connection() as conn:
        rows = conn.execute("""
            SELECT
                alert_type,
                COUNT(*) AS total
            FROM alerts
            GROUP BY alert_type
            ORDER BY total DESC
        """).fetchall()

        return [dict(row) for row in rows]


def fetch_event_counts_by_type():
    """
    Returns event counts grouped by event type.
    """
    with get_connection() as conn:
        rows = conn.execute("""
            SELECT
                event_type,
                COUNT(*) AS total
            FROM events
            GROUP BY event_type
            ORDER BY total DESC
        """).fetchall()

        return [dict(row) for row in rows]