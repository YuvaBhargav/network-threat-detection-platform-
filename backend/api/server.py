from flask import Flask, Response, jsonify, request
from flask_cors import CORS
import time
import json
import pandas as pd
import os
import sys
import socket
import ipaddress
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
from datetime import datetime, timedelta

app = Flask(__name__)
CORS(app)

config = get_config()
DATA_DIR = os.path.join(BASE_DIR, config["storage"]["log_file"].split("/")[0])
LOG_FILE = os.path.join(BASE_DIR, config["storage"]["log_file"])

# Thread lock for CSV operations
csv_lock = threading.Lock()


def get_local_ipv4_addresses():
    addresses = {"127.0.0.1"}
    try:
        hostname = socket.gethostname()
        for result in socket.getaddrinfo(hostname, None, socket.AF_INET):
            candidate = result[4][0]
            if candidate:
                addresses.add(candidate)
    except Exception:
        pass
    return addresses


LOCAL_IP_ADDRESSES = get_local_ipv4_addresses()
THREAT_BASE_SCORES = {
    "Possible DDoS": 90,
    "SYN Flood": 88,
    "Port Scanning": 62,
    "Malicious IP (OSINT)": 82,
    "Malicious Domain (OSINT)": 80,
    "SQL Injection": 86,
    "XSS Attack": 72,
}


def is_private_or_loopback(ip_value):
    try:
        address = ipaddress.ip_address(ip_value)
        return address.is_private or address.is_loopback
    except Exception:
        return False


def classify_direction(source_ip, destination_ip):
    src_local = source_ip in LOCAL_IP_ADDRESSES
    dst_local = destination_ip in LOCAL_IP_ADDRESSES

    if src_local and not dst_local:
        return "outbound"
    if dst_local and not src_local:
        return "inbound"
    if src_local and dst_local:
        return "local"
    if is_private_or_loopback(source_ip) and is_private_or_loopback(destination_ip):
        return "lan"
    return "external"


def normalize_threat_record(row):
    meta_obj = None
    try:
        meta_obj = json.loads(row["meta"]) if row["meta"] else None
    except Exception:
        meta_obj = None

    source_ip = row["source_ip"]
    destination_ip = row["destination_ip"]
    direction = classify_direction(source_ip, destination_ip)

    return {
        "id": row["id"] if "id" in row.keys() else None,
        "timestamp": row["timestamp"],
        "threatType": row["threat_type"],
        "sourceIP": source_ip,
        "destinationIP": destination_ip,
        "ports": row["ports"],
        "meta": meta_obj,
        "direction": direction,
        "sourceRole": "Local Host" if source_ip in LOCAL_IP_ADDRESSES else "Remote Host",
        "destinationRole": "Local Host" if destination_ip in LOCAL_IP_ADDRESSES else "Remote Host",
    }


def parse_threat_timestamp(value):
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except Exception:
        try:
            return datetime.strptime(value, "%Y-%m-%d %H:%M:%S")
        except Exception:
            return None


def compute_event_score(item):
    score = THREAT_BASE_SCORES.get(item.get("threatType"), 45)
    direction = item.get("direction")
    if direction == "inbound":
        score += 8
    elif direction == "outbound":
        score += 4

    meta = item.get("meta") or {}
    if "window_count" in meta:
        score += min(12, int(meta.get("window_count", 0)) // 50)
    if "attempt_count" in meta:
        score += min(10, int(meta.get("attempt_count", 0)) * 2)
    if "unique_sources" in meta:
        score += min(10, int(meta.get("unique_sources", 0)))
    if item.get("sourceRole") == "Remote Host" and direction == "inbound":
        score += 5
    return max(0, min(100, score))


def build_event_explanation(item):
    threat_type = item.get("threatType", "Unknown threat")
    direction = item.get("direction", "external")
    source_ip = item.get("sourceIP", "unknown")
    destination_ip = item.get("destinationIP", "unknown")
    service = item.get("ports", "unknown")
    meta = item.get("meta") or {}

    if threat_type == "Possible DDoS":
        return (
            f"{threat_type} was flagged because {destination_ip}:{service} received concentrated "
            f"traffic pressure within the detection window. Sources={meta.get('unique_sources', 'n/a')}, "
            f"events={meta.get('window_count', 'n/a')}."
        )
    if threat_type == "Port Scanning":
        return (
            f"{source_ip} touched many ports on {destination_ip} in a short burst, which matches "
            f"reconnaissance behavior. Unique ports={len(meta.get('unique_ports', [])) if isinstance(meta.get('unique_ports'), list) else meta.get('unique_ports', 'n/a')}."
        )
    if threat_type == "SQL Injection":
        return (
            f"Repeated SQLi payloads were observed from {source_ip} toward {destination_ip}. "
            f"Attempt count in window={meta.get('attempt_count', 'n/a')}."
        )
    if threat_type == "XSS Attack":
        return (
            f"Repeated XSS-like payloads were observed from {source_ip} toward {destination_ip}. "
            f"Attempt count in window={meta.get('attempt_count', 'n/a')}."
        )
    if threat_type == "SYN Flood":
        return (
            f"SYN flood behavior was detected from {source_ip} toward {destination_ip}:{service}. "
            f"SYN count={meta.get('syn_count', 'n/a')}, SYN-ACK count={meta.get('synack_count', 'n/a')}."
        )
    if "Malicious" in threat_type:
        return (
            f"{threat_type} means the event matched an external reputation feed. "
            f"Traffic direction={direction}, source={source_ip}, target={destination_ip}."
        )
    return f"{threat_type} was recorded for {source_ip} -> {destination_ip} on {service} ({direction})."


def build_incidents(recent_rows):
    buckets = {}
    for item in recent_rows:
        key = (item["threatType"], item["sourceIP"], item["destinationIP"])
        bucket = buckets.setdefault(
            key,
            {
                "threatType": item["threatType"],
                "sourceIP": item["sourceIP"],
                "destinationIP": item["destinationIP"],
                "direction": item.get("direction"),
                "count": 0,
                "maxScore": 0,
                "latestTimestamp": item["timestamp"],
                "services": set(),
            },
        )
        bucket["count"] += 1
        bucket["services"].add(str(item.get("ports", "unknown")))
        bucket["maxScore"] = max(bucket["maxScore"], item.get("score", 0))
        if str(item["timestamp"]) > str(bucket["latestTimestamp"]):
            bucket["latestTimestamp"] = item["timestamp"]

    incidents = []
    for bucket in buckets.values():
        incidents.append(
            {
                "threatType": bucket["threatType"],
                "sourceIP": bucket["sourceIP"],
                "destinationIP": bucket["destinationIP"],
                "direction": bucket["direction"],
                "count": bucket["count"],
                "severityScore": bucket["maxScore"],
                "latestTimestamp": bucket["latestTimestamp"],
                "services": sorted(bucket["services"]),
            }
        )

    incidents.sort(key=lambda item: (item["severityScore"], item["count"], item["latestTimestamp"]), reverse=True)
    return incidents[:8]


def build_trend_summary(recent_rows):
    now = datetime.utcnow()
    last_6h = now - timedelta(hours=6)
    prev_6h = now - timedelta(hours=12)

    current = [item for item in recent_rows if parse_threat_timestamp(item["timestamp"]) and parse_threat_timestamp(item["timestamp"]) >= last_6h]
    previous = [
        item
        for item in recent_rows
        if parse_threat_timestamp(item["timestamp"])
        and prev_6h <= parse_threat_timestamp(item["timestamp"]) < last_6h
    ]

    current_count = len(current)
    previous_count = len(previous)
    delta = current_count - previous_count
    direction = "stable"
    if delta > 0:
        direction = "up"
    elif delta < 0:
        direction = "down"

    return {
        "currentWindow": current_count,
        "previousWindow": previous_count,
        "delta": delta,
        "direction": direction,
        "dominantThreat": max(
            {"none": 0, **{item["threatType"]: sum(1 for row in current if row["threatType"] == item["threatType"]) for item in current}}.items(),
            key=lambda pair: pair[1],
        )[0],
    }


def build_anomalies(recent_rows):
    anomalies = []
    if not recent_rows:
        return anomalies

    remote_inbound = [item for item in recent_rows if item.get("direction") == "inbound" and item.get("sourceRole") == "Remote Host"]
    if remote_inbound:
        top = max(remote_inbound, key=lambda item: item.get("score", 0))
        anomalies.append(
            {
                "title": "High-risk inbound activity",
                "detail": f"{top['sourceIP']} targeted {top['destinationIP']} with {top['threatType']} (score {top['score']}).",
            }
        )

    outbound_web = [item for item in recent_rows if item.get("direction") == "outbound" and item["threatType"] in {"SQL Injection", "XSS Attack"}]
    if outbound_web:
        anomalies.append(
            {
                "title": "Outbound web attack traffic observed",
                "detail": f"{len(outbound_web)} outbound web attack events were seen from the monitored host. Validate whether these were tests or unexpected local behavior.",
            }
        )

    top_incident = build_incidents(recent_rows[:])[:1]
    if top_incident:
        incident = top_incident[0]
        anomalies.append(
            {
                "title": "Most concentrated incident cluster",
                "detail": f"{incident['threatType']} from {incident['sourceIP']} to {incident['destinationIP']} repeated {incident['count']} times across {', '.join(incident['services'])}.",
            }
        )

    return anomalies[:4]


def get_analysis_snapshot():
    conn = get_db()
    now = datetime.utcnow()
    since = (now - timedelta(hours=24)).strftime("%Y-%m-%d %H:%M:%S")
    cur = conn.execute(
        "SELECT timestamp, threat_type, source_ip, destination_ip, ports, meta "
        "FROM threats ORDER BY id DESC LIMIT 500"
    )
    rows = cur.fetchall()
    recent_rows = []
    for row in rows:
        parsed = parse_threat_timestamp(row["timestamp"])
        if parsed and parsed >= now - timedelta(hours=24):
            item = normalize_threat_record(row)
            item["score"] = compute_event_score(item)
            item["explanation"] = build_event_explanation(item)
            recent_rows.append(item)

    counts = {
        "total_24h": len(recent_rows),
        "ddos": sum(1 for item in recent_rows if item["threatType"] and "DDoS" in item["threatType"]),
        "port_scan": sum(1 for item in recent_rows if item["threatType"] and "Port Scan" in item["threatType"]),
        "sqli": sum(1 for item in recent_rows if item["threatType"] and "SQL Injection" in item["threatType"]),
        "xss": sum(1 for item in recent_rows if item["threatType"] and "XSS" in item["threatType"]),
        "osint": sum(1 for item in recent_rows if item["threatType"] and "Malicious" in item["threatType"]),
        "inbound": sum(1 for item in recent_rows if item.get("direction") == "inbound"),
        "outbound": sum(1 for item in recent_rows if item.get("direction") == "outbound"),
    }

    source_counts = {}
    destination_counts = {}
    for item in recent_rows:
        source_counts[item["sourceIP"]] = source_counts.get(item["sourceIP"], 0) + 1
        destination_counts[item["destinationIP"]] = destination_counts.get(item["destinationIP"], 0) + 1

    top_sources = sorted(source_counts.items(), key=lambda pair: pair[1], reverse=True)[:5]
    top_destinations = sorted(destination_counts.items(), key=lambda pair: pair[1], reverse=True)[:5]
    newest = recent_rows[:8]
    incidents = build_incidents(recent_rows)
    trends = build_trend_summary(recent_rows)
    anomalies = build_anomalies(recent_rows)
    risk_score = 0
    if recent_rows:
        risk_score = min(
            100,
            int(
                (sum(item["score"] for item in recent_rows[:25]) / max(1, min(len(recent_rows), 25))) * 0.7
                + min(30, len(incidents) * 3)
            ),
        )

    return {
        "generated_at": now.isoformat(),
        "counts": counts,
        "top_sources": top_sources,
        "top_destinations": top_destinations,
        "newest": newest,
        "incidents": incidents,
        "trends": trends,
        "anomalies": anomalies,
        "riskScore": risk_score,
    }


def build_analysis_reply(message, snapshot):
    text = (message or "").strip().lower()
    counts = snapshot["counts"]
    newest = snapshot["newest"]
    top_sources = snapshot["top_sources"]
    top_destinations = snapshot["top_destinations"]
    incidents = snapshot.get("incidents", [])
    anomalies = snapshot.get("anomalies", [])
    trends = snapshot.get("trends", {})

    summary_lines = [
        f"Threats in the last 24h: {counts['total_24h']}",
        f"DDoS: {counts['ddos']}, Port scans: {counts['port_scan']}, SQLi: {counts['sqli']}, XSS: {counts['xss']}, OSINT hits: {counts['osint']}",
        f"Inbound vs outbound: {counts['inbound']} inbound, {counts['outbound']} outbound",
        f"Current risk score: {snapshot.get('riskScore', 0)}/100",
    ]

    recommendation_lines = []
    if counts["ddos"] > 0:
        recommendation_lines.append("Review repeated DDoS targets and consider rate-limits or upstream filtering on the busiest service.")
    if counts["port_scan"] > 0:
        recommendation_lines.append("Port scan activity is present; validate exposed services and tighten allowlists on frequently probed ports.")
    if counts["sqli"] > 0 or counts["xss"] > 0:
        recommendation_lines.append("Web attack traffic is present; review WAF rules, input validation paths, and any public-facing app endpoints.")
    if counts["outbound"] > counts["inbound"]:
        recommendation_lines.append("Most detections are outbound from the monitored host, so validate whether these are testing actions versus suspicious local activity.")
    if not recommendation_lines:
        recommendation_lines.append("The last 24h looks relatively calm; keep watching for shifts in directionality and repeated sources.")

    if any(keyword in text for keyword in ["top source", "who", "attacker", "source ip"]):
        lines = ["Top source IPs in the last 24h:"]
        if top_sources:
            lines.extend([f"- {ip}: {count} events" for ip, count in top_sources])
        else:
            lines.append("- No recent sources recorded")
        return "\n".join(lines)

    if any(keyword in text for keyword in ["target", "destination", "victim"]):
        lines = ["Most targeted destinations in the last 24h:"]
        if top_destinations:
            lines.extend([f"- {ip}: {count} events" for ip, count in top_destinations])
        else:
            lines.append("- No recent destinations recorded")
        return "\n".join(lines)

    if any(keyword in text for keyword in ["recommend", "fix", "next step", "improve", "mitigate"]):
        return "Recommended next actions:\n" + "\n".join(f"- {line}" for line in recommendation_lines)

    if any(keyword in text for keyword in ["trend", "spike", "change", "rising", "falling"]):
        return (
            "Trend summary:\n"
            f"- Last 6h events: {trends.get('currentWindow', 0)}\n"
            f"- Previous 6h events: {trends.get('previousWindow', 0)}\n"
            f"- Direction: {trends.get('direction', 'stable')}\n"
            f"- Dominant threat in current window: {trends.get('dominantThreat', 'none')}"
        )

    if any(keyword in text for keyword in ["anomaly", "weird", "suspicious", "odd"]):
        if anomalies:
            return "Anomaly highlights:\n" + "\n".join(f"- {item['title']}: {item['detail']}" for item in anomalies)
        return "No standout anomalies were identified in the current 24h snapshot."

    if any(keyword in text for keyword in ["incident", "cluster", "campaign"]):
        if incidents:
            return "Highest-priority incidents:\n" + "\n".join(
                f"- {item['threatType']} from {item['sourceIP']} to {item['destinationIP']} | count={item['count']} | score={item['severityScore']}"
                for item in incidents[:5]
            )
        return "No incident clusters were found."

    if any(keyword in text for keyword in ["explain", "why this alert", "alert detail"]):
        if newest:
            item = newest[0]
            return (
                f"Latest alert explanation ({item['threatType']}):\n"
                f"- Score: {item.get('score', 0)}/100\n"
                f"- Direction: {item.get('direction', 'external')}\n"
                f"- {item.get('explanation', 'No explanation available.')}"
            )
        return "There is no recent alert to explain."

    if any(keyword in text for keyword in ["recent", "latest", "what happened", "timeline"]):
        lines = ["Most recent detections:"]
        if newest:
            lines.extend([
                f"- {item['timestamp']}: {item['threatType']} from {item['sourceIP']} to {item['destinationIP']} ({item.get('direction', 'external')}, score {item.get('score', 0)})"
                for item in newest
            ])
        else:
            lines.append("- No recent threats in the last 24h")
        return "\n".join(lines)

    return (
        "Security analysis summary:\n"
        + "\n".join(f"- {line}" for line in summary_lines)
        + (
            "\n\nKey anomalies:\n" + "\n".join(f"- {item['title']}: {item['detail']}" for item in anomalies)
            if anomalies
            else ""
        )
        + "\n\nRecommendations:\n"
        + "\n".join(f"- {line}" for line in recommendation_lines)
    )

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
        cur = conn.execute(
            "SELECT id, timestamp, threat_type, source_ip, destination_ip, ports, meta "
            "FROM threats ORDER BY id DESC"
        )
        rows = cur.fetchall()
        records = [normalize_threat_record(r) for r in rows]
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
                        item = normalize_threat_record(r)
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
        "packetsProcessed": packets,
        "localIPs": sorted(LOCAL_IP_ADDRESSES),
    })

@app.route('/api/chat', methods=['POST'])
def chat():
    try:
        body = request.get_json(force=True, silent=True) or {}
        message = body.get("message")
        if not isinstance(message, str) or not message.strip():
            return jsonify({"error": "Invalid message"}), 400
        snapshot = get_analysis_snapshot()
        reply = build_analysis_reply(message, snapshot)
        return jsonify({"reply": reply, "snapshot": snapshot})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/analysis/summary', methods=['GET'])
def analysis_summary():
    try:
        snapshot = get_analysis_snapshot()
        return jsonify(snapshot)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

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
