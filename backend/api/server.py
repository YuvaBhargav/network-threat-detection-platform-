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

app = Flask(__name__)
CORS(app)

config = get_config()
DATA_DIR = os.path.join(BASE_DIR, config["storage"]["log_file"].split("/")[0])
LOG_FILE = os.path.join(BASE_DIR, config["storage"]["log_file"])

# Thread lock for CSV operations
csv_lock = threading.Lock()


def get_threats_from_csv():
    """Thread-safe CSV reading with geolocation enrichment"""
    if not os.path.exists(LOG_FILE):
        print(f"Warning: Log file not found at {LOG_FILE}")
        return []
    
    with csv_lock:
        try:
            df = pd.read_csv(LOG_FILE)
            
            # Check if CSV is empty
            if df.empty:
                return []
            
            df = df.rename(columns={
                "Timestamp": "timestamp",
                "Threat Type": "threatType", 
                "Source IP": "sourceIP",
                "Destination IP": "destinationIP",
                "Ports": "ports"
            })

            # Fill NaN values with empty strings or None
            # Fill NaN values - use None for object columns, empty string for text columns
            for col in df.columns:
                if df[col].dtype == 'object':
                    df[col] = df[col].fillna("")
                else:
                    df[col] = df[col].fillna("")
            
            # Enrich with geolocation data (non-blocking, skip on error)
            try:
                geo_service = get_geolocation_service()
                if geo_service and geo_service.enabled:
                    print(f"🌍 Geolocation enabled, enriching {len(df)} threats...")
                    geolocations = {}
                    unique_ips = [str(ip).strip() for ip in df["sourceIP"].unique() 
                                 if ip and str(ip).strip() not in ["N/A", "nan", "", "None"] and pd.notna(ip)]
                    
                    print(f"📊 Found {len(unique_ips)} unique IPs to lookup")
                    # Limit geolocation lookups to prevent timeouts (increase limit for better coverage)
                    for ip in unique_ips[:100]:  # Increased limit
                        try:
                            geo = geo_service.get_location(ip)
                            if geo:
                                geolocations[ip] = geo
                        except Exception as geo_error:
                            print(f"⚠️ Geolocation lookup failed for {ip}: {geo_error}")
                            import traceback
                            traceback.print_exc()
                            continue
                    
                    print(f"✅ Geolocation data retrieved for {len(geolocations)} IPs")
                    # Add geolocation column
                    df["geolocation"] = df["sourceIP"].map(geolocations)
                    # Fill NaN geolocation values with None (which will be converted to null in JSON)
                    df["geolocation"] = df["geolocation"].fillna(None)
                else:
                    print("⚠️ Geolocation service disabled or unavailable")
            except Exception as geo_err:
                print(f"❌ Geolocation enrichment skipped: {geo_err}")
                import traceback
                traceback.print_exc()
                # Continue without geolocation data
            
            # Replace any remaining NaN/NaT values with None before converting to dict
            df = df.replace({np.nan: None, pd.NaT: None})
            
            # Convert to dict
            records = df.to_dict('records')
            
            # Clean up any remaining NaN values that might have slipped through
            def clean_nan(obj):
                if isinstance(obj, dict):
                    return {k: clean_nan(v) for k, v in obj.items()}
                elif isinstance(obj, list):
                    return [clean_nan(item) for item in obj]
                elif isinstance(obj, (np.integer, np.floating)):
                    if pd.isna(obj) or np.isinf(obj):
                        return None
                    return float(obj) if isinstance(obj, np.floating) else int(obj)
                elif isinstance(obj, float):
                    if pd.isna(obj) or np.isinf(obj) or str(obj).lower() == 'nan':
                        return None
                elif pd.isna(obj) if hasattr(pd, 'isna') else (obj != obj):
                    return None
                elif isinstance(obj, str) and obj.lower() in ['nan', 'nat', 'none', '']:
                    return None if obj.lower() in ['nan', 'nat', 'none'] else obj
                return obj
            
            cleaned_records = [clean_nan(record) for record in records]
            return cleaned_records
        except Exception as e:
            print(f"Error reading CSV: {e}")
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
        threats = get_threats_from_csv()
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
        last_size = 0
        last_heartbeat = time.time()
        while True:
            current_size = os.path.getsize(LOG_FILE) if os.path.exists(LOG_FILE) else 0
            if current_size > last_size:
                threats = get_threats_from_csv()
                if threats:
                    
                    yield f"data: {json.dumps(threats[-1], cls=NpEncoder)}\n\n"
                last_size = current_size
            now = time.time()
            if now - last_heartbeat > 10:
               
                yield ": keepalive\n\n"
                last_heartbeat = now
            time.sleep(1)  # Check for new entries every second
    response = Response(event_stream(), content_type='text/event-stream')
    response.headers['Cache-Control'] = 'no-cache'
    response.headers['Connection'] = 'keep-alive'
    response.headers['Access-Control-Allow-Origin'] = '*'  
    response.headers['X-Accel-Buffering'] = 'no'
    response.headers['Transfer-Encoding'] = 'chunked'
    response.headers['Content-Type'] = 'text/event-stream'
    return response

@app.route('/api/health', methods=['GET'])
def health():
    exists = os.path.exists(LOG_FILE)
    size = os.path.getsize(LOG_FILE) if exists else 0
    return jsonify({
        "status": "ok",
        "logFileExists": exists,
        "logFileSize": size
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
    threats = get_threats_from_csv()
    
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
        app.run(debug=True, port=5000, host='0.0.0.0', use_reloader=False)
    except Exception as e:
        print(f"Failed to start server: {e}")
        import traceback
        traceback.print_exc()
