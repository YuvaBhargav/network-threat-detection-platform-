import json
from datetime import datetime
import threading
from db import get_db

class AlertHistory:
    def __init__(self):
        self.lock = threading.Lock()
    
    def add_alert(self, alert_type, source_ip, message, destination_ip=None, ports=None, geolocation=None):
        with self.lock:
            conn = get_db()
            ts = datetime.now().isoformat()
            geo = json.dumps(geolocation) if geolocation is not None else None
            pr = json.dumps(ports) if isinstance(ports, (list, dict)) else (str(ports) if ports is not None else None)
            conn.execute(
                "INSERT INTO alerts (timestamp, alert_type, source_ip, destination_ip, ports, message, geolocation) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (ts, alert_type, source_ip, destination_ip, pr, message, geo)
            )
            conn.commit()
    
    def get_recent_alerts(self, limit=100):
        conn = get_db()
        cur = conn.execute("SELECT timestamp, alert_type, source_ip, destination_ip, ports, message, geolocation FROM alerts ORDER BY id DESC LIMIT ?", (limit,))
        rows = cur.fetchall()
        result = []
        for r in rows:
            geo = json.loads(r["geolocation"]) if r["geolocation"] else None
            result.append({
                "timestamp": r["timestamp"],
                "alert_type": r["alert_type"],
                "source_ip": r["source_ip"],
                "destination_ip": r["destination_ip"],
                "ports": r["ports"],
                "message": r["message"],
                "geolocation": geo
            })
        return result
    
    def get_alerts_by_type(self, alert_type, limit=100):
        conn = get_db()
        cur = conn.execute("SELECT timestamp, alert_type, source_ip, destination_ip, ports, message, geolocation FROM alerts WHERE alert_type = ? ORDER BY id DESC LIMIT ?", (alert_type, limit))
        rows = cur.fetchall()
        result = []
        for r in rows:
            geo = json.loads(r["geolocation"]) if r["geolocation"] else None
            result.append({
                "timestamp": r["timestamp"],
                "alert_type": r["alert_type"],
                "source_ip": r["source_ip"],
                "destination_ip": r["destination_ip"],
                "ports": r["ports"],
                "message": r["message"],
                "geolocation": geo
            })
        return result
    
    def get_alerts_by_ip(self, ip_address, limit=100):
        conn = get_db()
        cur = conn.execute("SELECT timestamp, alert_type, source_ip, destination_ip, ports, message, geolocation FROM alerts WHERE source_ip = ? ORDER BY id DESC LIMIT ?", (ip_address, limit))
        rows = cur.fetchall()
        result = []
        for r in rows:
            geo = json.loads(r["geolocation"]) if r["geolocation"] else None
            result.append({
                "timestamp": r["timestamp"],
                "alert_type": r["alert_type"],
                "source_ip": r["source_ip"],
                "destination_ip": r["destination_ip"],
                "ports": r["ports"],
                "message": r["message"],
                "geolocation": geo
            })
        return result
    
    def clear_history(self):
        conn = get_db()
        conn.execute("DELETE FROM alerts")
        conn.commit()

_alert_history = None

def get_alert_history():
    global _alert_history
    if _alert_history is None:
        _alert_history = AlertHistory()
    return _alert_history

