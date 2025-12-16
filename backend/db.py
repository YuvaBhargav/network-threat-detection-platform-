import os
import sqlite3
from pathlib import Path
from config import get_config

BASE_DIR = Path(__file__).parent
_conn = None

def _get_db_path():
    cfg = get_config()
    storage = cfg.get("storage", {})
    db_file = storage.get("db_file", "data/threats.db")
    path = BASE_DIR / db_file
    path.parent.mkdir(parents=True, exist_ok=True)
    return str(path)

def get_db():
    global _conn
    if _conn is None:
        db_path = _get_db_path()
        _conn = sqlite3.connect(db_path, check_same_thread=False)
        _conn.row_factory = sqlite3.Row
        _conn.execute(
            "CREATE TABLE IF NOT EXISTS threats ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT,"
            "timestamp TEXT,"
            "threat_type TEXT,"
            "source_ip TEXT,"
            "destination_ip TEXT,"
            "ports TEXT,"
            "meta TEXT)"
        )
        _conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_threats_unique "
            "ON threats(timestamp, threat_type, source_ip, destination_ip, ports)"
        )
        _conn.execute(
            "CREATE TABLE IF NOT EXISTS alerts ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT,"
            "timestamp TEXT,"
            "alert_type TEXT,"
            "source_ip TEXT,"
            "destination_ip TEXT,"
            "ports TEXT,"
            "message TEXT,"
            "geolocation TEXT)"
        )
        _conn.execute(
            "CREATE TABLE IF NOT EXISTS stats ("
            "key TEXT PRIMARY KEY,"
            "value TEXT)"
        )
        # Ensure meta column exists on threats (for existing DBs)
        try:
            cur = _conn.execute("PRAGMA table_info(threats)")
            cols = [row["name"] for row in cur.fetchall()]
            if "meta" not in cols:
                _conn.execute("ALTER TABLE threats ADD COLUMN meta TEXT")
        except Exception:
            pass
        _conn.commit()
    return _conn

def get_db_path():
    return _get_db_path()

def get_stat(key, default=None):
    conn = get_db()
    cur = conn.execute("SELECT value FROM stats WHERE key = ?", (key,))
    row = cur.fetchone()
    return row["value"] if row else default

def set_stat(key, value):
    conn = get_db()
    conn.execute("INSERT INTO stats(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value", (key, str(value)))
    conn.commit()
