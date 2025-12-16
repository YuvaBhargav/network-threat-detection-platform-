from flask import Flask, Response, jsonify, request
from flask_cors import CORS
import time
import json
import pandas as pd
import os
import sys
from pathlib import Path
import numpy as np
import threading
import csv as csv_module

# Add parent directory to path for imports
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

from config import get_config
from geolocation import get_geolocation_service
from alert_history import get_alert_history
from db import get_db, get_db_path, get_stat, set_stat

app = Flask(__name__)
CORS(app)

config = get_config()
DATA_DIR = os.path.join(BASE_DIR, config["storage"]["log_file"].split("/")[0])
LOG_FILE = os.path.join(BASE_DIR, config["storage"]["log_file"])

# Thread lock for CSV operations
csv_lock = threading.Lock()

def import_csv_to_db_if_needed():
    try:
        conn = get_db()
        migrated = get_stat("csv_migrated", None)
        if str(migrated).strip() == "1":
            return
        if not os.path.exists(LOG_FILE):
            return
        with csv_lock:
            df = pd.read_csv(LOG_FILE)
            if df.empty:
                return
            df = df.rename(columns={
                "Timestamp": "timestamp",
                "Threat Type": "threatType", 
                "Source IP": "sourceIP",
                "Destination IP": "destinationIP",
                "Ports": "ports"
            })
            records = df.to_dict('records')
            for rec in records:
                ts = rec.get("timestamp")
                tt = rec.get("threatType")
                sip = rec.get("sourceIP")
                dip = rec.get("destinationIP")
                ports = rec.get("ports")
                try:
                    conn.execute(
                        "INSERT OR IGNORE INTO threats (timestamp, threat_type, source_ip, destination_ip, ports, meta) VALUES (?, ?, ?, ?, ?, ?)",
                        (ts, tt, str(sip) if sip is not None else None, str(dip) if dip is not None else None, str(ports) if ports is not None else None, None)
                    )
                except Exception:
                    pass
            conn.commit()
            print(f"✅ Migrated {len(records)} rows from CSV to DB at {get_db_path()}")
            try:
                set_stat("csv_migrated", 1)
            except Exception:
                pass
    except Exception as e:
        print(f"⚠️ CSV to DB migration failed: {e}")
        import traceback
        traceback.print_exc()


def get_threats_from_db():
    try:
        import_csv_to_db_if_needed()
        conn = get_db()
        cur = conn.execute("SELECT id, timestamp, threat_type, source_ip, destination_ip, ports FROM threats ORDER BY id ASC")
        rows = cur.fetchall()
        records = []
        for r in rows:
            meta_obj = None
            try:
                meta_obj = json.loads(r["meta"]) if r["meta"] else None
            except Exception:
                meta_obj = None
            records.append({
                "timestamp": r["timestamp"],
                "threatType": r["threat_type"],
                "sourceIP": r["source_ip"],
                "destinationIP": r["destination_ip"],
                "ports": r["ports"],
                "meta": meta_obj
            })
        try:
            geo_service = get_geolocation_service()
            if geo_service and geo_service.enabled:
                geolocations = {}
                unique_ips = [str(item["sourceIP"]).strip() for item in records if item["sourceIP"] and str(item["sourceIP"]).strip() not in ["N/A", "nan", "", "None"]]
                for ip in list(dict.fromkeys(unique_ips))[:100]:
                    try:
                        geo = geo_service.get_location(ip)
                        if geo:
                            geolocations[ip] = geo
                    except Exception:
                        continue
                for item in records:
                    ip = item["sourceIP"]
                    item["geolocation"] = geolocations.get(ip)
            else:
                pass
        except Exception:
            pass
        return records
    except Exception as e:
        print(f"Error reading DB: {e}")
        import traceback
        traceback.print_exc()
        return []


class NpEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, np.integer):
            return int(obj)
        if isinstance(obj, np.floating):
            # Check for NaN or inf values
            if pd.isna(obj) or np.isinf(obj):
                return None
            return float(obj)
        if isinstance(obj, np.ndarray):
            return obj.tolist()
        if pd.isna(obj):
            return None  # Return None instead of empty string for JSON null
        if isinstance(obj, (float, int)) and (pd.isna(obj) or np.isinf(obj)):
            return None
        return super(NpEncoder, self).default(obj)

@app.route('/api/threats', methods=['GET'])
def get_threats():
    try:
        threats = get_threats_from_db()
        # Use custom encoder to handle NaN values properly
        response = app.response_class(
            response=json.dumps(threats, cls=NpEncoder),
            status=200,
            mimetype='application/json'
        )
        return response
    except Exception as e:
        print(f"Error in get_threats endpoint: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

@app.route('/api/threats/stream', methods=['GET'])
def stream_threats():
    def event_stream():
        last_id = 0
        last_heartbeat = time.time()
        while True:
            try:
                conn = get_db()
                cur = conn.execute("SELECT MAX(id) AS max_id FROM threats")
                row = cur.fetchone()
                current_max = row["max_id"] or 0
                if current_max > last_id:
                    cur2 = conn.execute("SELECT timestamp, threat_type, source_ip, destination_ip, ports, meta FROM threats WHERE id = ?", (current_max,))
                    r = cur2.fetchone()
                    if r:
                        item = {
                            "timestamp": r["timestamp"],
                            "threatType": r["threat_type"],
                            "sourceIP": r["source_ip"],
                            "destinationIP": r["destination_ip"],
                            "ports": r["ports"],
                            "meta": json.loads(r["meta"]) if r["meta"] else None
                        }
                        yield f"data: {json.dumps(item, cls=NpEncoder)}\n\n"
                    last_id = current_max
            except Exception:
                pass
            now = time.time()
            if now - last_heartbeat > 10:
               
                yield ": keepalive\n\n"
                last_heartbeat = now
            time.sleep(1)  # Check for new entries every second

    response = Response(event_stream(), content_type='text/event-stream')
    response.headers['Cache-Control'] = 'no-cache'
    response.headers['Connection'] = 'keep-alive'
    response.headers['Access-Control-Allow-Origin'] = '*'  
    return response

@app.route('/api/health', methods=['GET'])
def health():
    exists = os.path.exists(LOG_FILE)
    size = os.path.getsize(LOG_FILE) if exists else 0
    db_path = get_db_path()
    db_exists = os.path.exists(db_path)
    db_size = os.path.getsize(db_path) if db_exists else 0
    packets = None
    try:
        val = get_stat("packet_count", None)
        packets = int(val) if val is not None else None
    except Exception:
        packets = None
    return jsonify({
        "status": "ok",
        "logFileExists": exists,
        "logFileSize": size,
        "dbFileExists": db_exists,
        "dbFileSize": db_size,
        "packetsProcessed": packets
    })

@app.route('/api/geolocation/<ip_address>', methods=['GET'])
def get_geolocation(ip_address):
    """Get geolocation data for an IP address"""
    try:
        from urllib.parse import unquote
        ip_address = unquote(ip_address)  # Decode URL-encoded IP
        geo_service = get_geolocation_service()
        if not geo_service or not geo_service.enabled:
            return jsonify({"error": "Geolocation service is disabled"}), 503
        
        location = geo_service.get_location(ip_address)
        if location:
            return jsonify(location)
        return jsonify({"error": "Geolocation data not available for this IP address"}), 404
    except Exception as e:
        print(f"Error in geolocation endpoint: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

@app.route('/api/alerts', methods=['GET'])
def get_alerts():
    """Get alert history"""
    limit = request.args.get('limit', 100, type=int)
    alert_type = request.args.get('type', None)
    ip_address = request.args.get('ip', None)
    
    alert_history = get_alert_history()
    
    if alert_type:
        alerts = alert_history.get_alerts_by_type(alert_type, limit)
    elif ip_address:
        alerts = alert_history.get_alerts_by_ip(ip_address, limit)
    else:
        alerts = alert_history.get_recent_alerts(limit)
    
    return jsonify(alerts)

@app.route('/api/alerts/stats', methods=['GET'])
def get_alert_stats():
    """Get alert statistics"""
    alert_history = get_alert_history()
    recent_alerts = alert_history.get_recent_alerts(1000)
    
    stats = {
        "total": len(recent_alerts),
        "by_type": {},
        "by_ip": {},
        "recent_24h": 0
    }
    
    now = time.time()
    for alert in recent_alerts:
        # Count by type
        alert_type = alert.get("alert_type", "Unknown")
        stats["by_type"][alert_type] = stats["by_type"].get(alert_type, 0) + 1
        
        # Count by IP
        src_ip = alert.get("source_ip", "Unknown")
        stats["by_ip"][src_ip] = stats["by_ip"].get(src_ip, 0) + 1
        
        # Count recent (last 24 hours)
        try:
            alert_time = time.mktime(time.strptime(alert["timestamp"], "%Y-%m-%dT%H:%M:%S.%f"))
            if now - alert_time < 86400:  # 24 hours
                stats["recent_24h"] += 1
        except:
            pass
    
    return jsonify(stats)

@app.route('/api/threats/export', methods=['GET'])
def export_threats():
    """Export threats in JSON format"""
    format_type = request.args.get('format', 'json')
    threats = get_threats_from_db()
    
    if format_type == 'json':
        return jsonify({
            "exported_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "total_threats": len(threats),
            "threats": threats
        })
    else:
        # CSV export (for backward compatibility)
        return Response(
            json.dumps(threats, cls=NpEncoder),
            mimetype='application/json',
            headers={'Content-Disposition': 'attachment; filename=threats_export.json'}
        )

if __name__ == '__main__':
    print(f"Starting Flask server on http://localhost:5000")
    print(f"Log file path: {LOG_FILE}")
    print(f"Log file exists: {os.path.exists(LOG_FILE)}")
    if os.path.exists(LOG_FILE):
        print(f"Log file size: {os.path.getsize(LOG_FILE)} bytes")
    try:
        app.run(debug=True, port=5000, host='0.0.0.0')
    except Exception as e:
        print(f"Failed to start server: {e}")
        import traceback
        traceback.print_exc()
