import datetime
import json
import os
import re
import smtplib
import sqlite3
import sys
import threading
import time
from collections import defaultdict
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from urllib.parse import unquote, urlparse

import requests
from scapy.all import IP, Raw, TCP, UDP, sniff
from scapy.layers.http import HTTPRequest

# Add parent directory to path for imports
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

from alert_history import get_alert_history
from config import get_alert_email_config, get_config, get_network_interface
from db import get_db
from geolocation import get_geolocation_service

# Load configuration
config = get_config()
detection_config = config["detection"]
alerts_config = config["alerts"]
osint_config = config["osint"]

NETWORK_INTERFACE = get_network_interface()
DEBUG_HTTP_PAYLOADS = os.getenv("DEBUG_HTTP_PAYLOADS", "").strip().lower() in {
    "1",
    "true",
    "yes",
    "on",
}

email_config = get_alert_email_config()
SENDER_EMAIL = email_config["sender_email"]
SENDER_PASSWORD = email_config["sender_password"]
RECIPIENT_EMAILS = email_config["recipient_emails"]

DDOS_THRESHOLD = detection_config["ddos_threshold"]
PORT_SCAN_THRESHOLD = detection_config["port_scan_threshold"]
SQL_INJECTION_THRESHOLD = detection_config["sql_injection_threshold"]
XSS_THRESHOLD = detection_config["xss_threshold"]
SYN_FLOOD_THRESHOLD = detection_config["syn_flood_threshold"]
SYN_ACK_RATIO_THRESHOLD = detection_config["syn_ack_ratio_threshold"]
TIME_WINDOW = detection_config["time_window_seconds"]

DATA_DIR = os.path.join(BASE_DIR, config["storage"]["log_file"].split("/")[0])
LOG_FILE = os.path.join(BASE_DIR, config["storage"]["log_file"])

ip_request_count = defaultdict(list)
ddos_sources = defaultdict(set)
ddos_source_ports = defaultdict(set)
ip_ports_accessed = defaultdict(list)
sql_injection_attempts = defaultdict(list)
xss_attempts = defaultdict(list)
sql_request_fingerprints = defaultdict(dict)
xss_request_fingerprints = defaultdict(dict)

last_alert_time = {}
syn_flow_events = defaultdict(list)
synack_flow_events = defaultdict(list)

MALICIOUS_IPS = set()
MALICIOUS_DOMAINS = set()

SQL_PATTERNS = [
    r"\bunion\b\s+(?:all\s+)?select\b",
    r"\bselect\b.+\bfrom\b",
    r"\binsert\b.+\binto\b",
    r"\bupdate\b.+\bset\b",
    r"\bdelete\b.+\bfrom\b",
    r"\bdrop\b\s+table\b",
    r"\bor\b\s+1\s*=\s*1\b",
    r"\band\b\s+1\s*=\s*1\b",
    r"['\"`]\s*(?:or|and)\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+",
    r"\bexec(?:ute)?\b\s*(?:xp_|sp_)\w+",
    r"\binformation_schema\b",
    r"\bsleep\s*\(",
    r"\bbenchmark\s*\(",
]

XSS_PATTERNS = [
    r"<script[^>]*>.*?</script>",
    r"javascript:",
    r"onerror\s*=",
    r"onload\s*=",
    r"alert\s*\(",
]

HTTP_METHOD_PREFIXES = (
    "GET ",
    "POST ",
    "PUT ",
    "DELETE ",
    "PATCH ",
    "HEAD ",
    "OPTIONS ",
)


def normalize_domain(value):
    if not value:
        return None

    candidate = value.strip().lower()
    if not candidate or candidate.startswith("#"):
        return None

    if "://" in candidate:
        parsed = urlparse(candidate)
        candidate = parsed.hostname or candidate
    else:
        candidate = candidate.split("/")[0]

    candidate = candidate.split(":")[0].strip(".")
    return candidate or None


def prune_old_entries(entries, now, window_seconds):
    return [entry for entry in entries if now - entry < window_seconds]


def is_ephemeral_port(port):
    return isinstance(port, int) and port >= 49152


def looks_like_http_request_payload(payload):
    if not payload:
        return False

    upper_payload = payload[:256].upper()
    if upper_payload.startswith(HTTP_METHOD_PREFIXES):
        return True

    return "HOST:" in upper_payload and "HTTP/" in upper_payload


def debug_log_http_payload(packet, payload, reason):
    if not DEBUG_HTTP_PAYLOADS:
        return

    src_ip = packet[IP].src if packet.haslayer(IP) else "unknown"
    dst_ip = packet[IP].dst if packet.haslayer(IP) else "unknown"
    dst_port = None
    if packet.haslayer(TCP):
        dst_port = packet[TCP].dport
    elif packet.haslayer(UDP):
        dst_port = packet[UDP].dport

    preview = payload[:160].replace("\r", "\\r").replace("\n", "\\n")
    print(
        f"[HTTP DEBUG] {reason} src={src_ip} dst={dst_ip}:{dst_port} preview={preview}"
    )


def extract_http_request_details(payload):
    if not payload:
        return None

    lines = payload.splitlines()
    if not lines:
        return None

    request_line = lines[0].strip()
    parts = request_line.split()
    if len(parts) < 2:
        return None

    method = parts[0].upper()
    if method not in {prefix.strip() for prefix in HTTP_METHOD_PREFIXES}:
        return None

    target = parts[1]
    host = extract_host_from_payload(payload)
    return {
        "method": method,
        "target": target,
        "host": host,
        "request_line": request_line,
    }


def fetch_osint_data():
    global MALICIOUS_IPS, MALICIOUS_DOMAINS
    try:
        feodo_url = osint_config.get(
            "feodo_tracker_url",
            "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
        )
        resp = requests.get(feodo_url, timeout=10)
        if resp.status_code == 200:
            MALICIOUS_IPS = {
                line.strip()
                for line in resp.text.splitlines()
                if line and not line.startswith("#")
            }
            print(f"Loaded {len(MALICIOUS_IPS)} malicious IPs from Feodo Tracker")

        urlhaus_url = osint_config.get(
            "urlhaus_url", "https://urlhaus.abuse.ch/downloads/text/"
        )
        dresp = requests.get(urlhaus_url, timeout=10)
        if dresp.status_code == 200:
            MALICIOUS_DOMAINS = {
                normalize_domain(line.strip())
                for line in dresp.text.splitlines()
                if line and not line.startswith("#") and normalize_domain(line.strip())
            }
            print(f"Loaded {len(MALICIOUS_DOMAINS)} malicious domains from URLhaus")
    except Exception as exc:
        print(f"OSINT fetch failed: {exc}")


fetch_osint_data()


def schedule_osint_updates():
    """Periodically refresh OSINT data."""
    update_interval = osint_config.get("update_interval_hours", 24) * 3600
    while True:
        time.sleep(update_interval)
        fetch_osint_data()


osint_thread = threading.Thread(target=schedule_osint_updates, daemon=True)
osint_thread.start()


def send_alert(message, src_ip, attack_type, destination_ip=None, ports=None):
    now = time.time()
    key = (src_ip, attack_type)
    throttle_seconds = alerts_config.get("throttle_seconds", 300)

    if key in last_alert_time and now - last_alert_time[key] < throttle_seconds:
        return

    geo_service = get_geolocation_service()
    geolocation = None
    if geo_service.enabled:
        try:
            geolocation = geo_service.get_location(src_ip)
        except Exception as exc:
            print(f"Geolocation lookup failed for {src_ip}: {exc}")

    alert_history = get_alert_history()
    alert_history.add_alert(
        attack_type, src_ip, message, destination_ip, ports, geolocation
    )
    last_alert_time[key] = now

    if (
        alerts_config.get("enabled", True)
        and SENDER_EMAIL
        and SENDER_PASSWORD
        and RECIPIENT_EMAILS
    ):
        msg = MIMEMultipart()
        msg["From"] = SENDER_EMAIL
        msg["To"] = ", ".join(RECIPIENT_EMAILS)
        msg["Subject"] = f"Security Alert: {attack_type}"

        geo_info = ""
        if geolocation:
            geo_info = (
                f"\nLocation: {geolocation.get('city', 'Unknown')}, "
                f"{geolocation.get('country', 'Unknown')}"
            )
            if geolocation.get("isp"):
                geo_info += f"\nISP: {geolocation.get('isp')}"

        body = f"""
Threat Detected: {attack_type}
Source IP: {src_ip}
Destination IP: {destination_ip or 'N/A'}
Ports: {ports or 'N/A'}
Details: {message}
Time: {datetime.datetime.now()}{geo_info}
"""
        msg.attach(MIMEText(body, "plain", "utf-8"))

        try:
            smtp_server = alerts_config.get("smtp_server", "smtp.gmail.com")
            smtp_port = alerts_config.get("smtp_port", 587)
            server = smtplib.SMTP(smtp_server, smtp_port)
            server.starttls()
            server.login(SENDER_EMAIL, SENDER_PASSWORD)
            server.sendmail(SENDER_EMAIL, RECIPIENT_EMAILS, msg.as_string())
            server.quit()
            print(f"Alert sent: {attack_type} from {src_ip}")
        except Exception as exc:
            print(f"Email error: {exc}")
    else:
        print(f"Alert logged: {attack_type} from {src_ip} (email not configured)")


def extract_meta_from_packet(packet, src_ip=None, dst_ip=None, port=None):
    meta = {}
    try:
        if packet.haslayer(IP):
            meta["ttl"] = int(packet[IP].ttl)
            meta["len"] = int(packet[IP].len) if hasattr(packet[IP], "len") else None
        if packet.haslayer(TCP):
            flags = packet[TCP].flags
            try:
                meta["tcp_flags"] = int(flags)
            except Exception:
                meta["tcp_flags"] = str(flags)
            meta["protocol"] = "TCP"
        elif packet.haslayer(UDP):
            meta["protocol"] = "UDP"
        if packet.haslayer(Raw):
            try:
                meta["payload_len"] = len(packet[Raw].load)
            except Exception:
                pass
        if packet.haslayer(HTTPRequest):
            try:
                host = packet[HTTPRequest].Host
                meta["http_host"] = (
                    host.decode() if hasattr(host, "decode") else host
                )
                path = packet[HTTPRequest].Path
                meta["http_path"] = (
                    path.decode() if hasattr(path, "decode") else path
                )
                method = packet[HTTPRequest].Method
                meta["http_method"] = (
                    method.decode() if hasattr(method, "decode") else method
                )
            except Exception:
                pass
    except Exception:
        pass
    if src_ip is not None:
        meta["src_ip"] = src_ip
    if dst_ip is not None:
        meta["dst_ip"] = dst_ip
    if port is not None:
        meta["port"] = port
    return meta


def extract_host_from_payload(payload):
    try:
        match = re.search(r"\bHost:\s*([^\r\n]+)", payload, re.I)
        if match:
            return normalize_domain(match.group(1))
    except Exception:
        return None
    return None


def log_threat_to_db(threat, src_ip, dst_ip, ports, meta=None):
    conn = get_db()
    ts = datetime.datetime.now().isoformat(timespec="microseconds")
    pr = json.dumps(ports) if isinstance(ports, (list, dict)) else str(ports)
    mj = json.dumps(meta) if isinstance(meta, dict) else (meta if meta is not None else None)
    try:
        conn.execute(
            "INSERT INTO threats (timestamp, threat_type, source_ip, destination_ip, ports, meta) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (ts, threat, src_ip, dst_ip, pr, mj),
        )
        conn.commit()
    except sqlite3.IntegrityError:
        # Duplicate detections should not interrupt packet capture.
        conn.rollback()


def track_deduped_request(tracker, src_ip, fingerprint, now, dedup_window=60):
    recent = tracker[src_ip]
    expired = [key for key, ts in recent.items() if now - ts >= dedup_window]
    for key in expired:
        recent.pop(key, None)

    if fingerprint in recent:
        return False

    recent[fingerprint] = now
    return True


def build_request_fingerprint(packet, payload):
    dst_ip = packet[IP].dst if packet.haslayer(IP) else "unknown"
    dst_port = None
    if packet.haslayer(TCP):
        dst_port = packet[TCP].dport
    elif packet.haslayer(UDP):
        dst_port = packet[UDP].dport

    host = None
    path = None
    method = None
    if packet.haslayer(HTTPRequest):
        try:
            host = packet[HTTPRequest].Host.decode(errors="ignore")
        except Exception:
            host = getattr(packet[HTTPRequest], "Host", None)
        try:
            path = packet[HTTPRequest].Path.decode(errors="ignore")
        except Exception:
            path = getattr(packet[HTTPRequest], "Path", None)
        try:
            method = packet[HTTPRequest].Method.decode(errors="ignore")
        except Exception:
            method = getattr(packet[HTTPRequest], "Method", None)

    return json.dumps(
        {
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "host": host,
            "path": path,
            "method": method,
            "payload": payload[:200],
        },
        sort_keys=True,
    )


def summarize_source_syn_state(src_ip, now):
    syn_total = 0
    synack_total = 0

    for key in list(syn_flow_events.keys()):
        if key[0] != src_ip:
            continue
        pruned = prune_old_entries(syn_flow_events[key], now, TIME_WINDOW)
        if pruned:
            syn_flow_events[key] = pruned
            syn_total += len(pruned)
        else:
            syn_flow_events.pop(key, None)

    for key in list(synack_flow_events.keys()):
        if key[0] != src_ip:
            continue
        pruned = prune_old_entries(synack_flow_events[key], now, TIME_WINDOW)
        if pruned:
            synack_flow_events[key] = pruned
            synack_total += len(pruned)
        else:
            synack_flow_events.pop(key, None)

    ratio = (synack_total / syn_total) if syn_total > 0 else 1
    return syn_total, synack_total, ratio


def detect_ddos(packet, src_ip, dst_ip, port):
    if port is None:
        return

    protocol = "OTHER"
    if packet.haslayer(TCP):
        protocol = "TCP"
        flags = packet[TCP].flags
        try:
            flag_number = int(flags)
            is_syn_only = (flag_number & 0x02) != 0 and (flag_number & 0x10) == 0
        except Exception:
            flag_string = str(flags)
            is_syn_only = "S" in flag_string and "A" not in flag_string

        if not is_syn_only:
            return
    elif packet.haslayer(UDP):
        protocol = "UDP"
    else:
        return

    if is_ephemeral_port(port):
        return

    now = time.time()
    key = (dst_ip, port, protocol)
    ip_request_count[key].append(now)
    ip_request_count[key] = prune_old_entries(ip_request_count[key], now, TIME_WINDOW)
    ddos_sources[key].add(src_ip)
    if packet.haslayer(TCP):
        ddos_source_ports[key].add(packet[TCP].sport)
    elif packet.haslayer(UDP):
        ddos_source_ports[key].add(packet[UDP].sport)

    packet_count = len(ip_request_count[key])
    unique_sources = len(ddos_sources[key])
    unique_source_ports = len(ddos_source_ports[key])
    sustained_single_source = packet_count > (DDOS_THRESHOLD * 2) and unique_source_ports >= 50
    distributed_sources = packet_count > DDOS_THRESHOLD and unique_sources >= 3

    if sustained_single_source or distributed_sources:
        send_alert(
            f"Suspicious flood targeting {dst_ip}:{port} over {protocol}",
            src_ip,
            "DDoS",
            destination_ip=dst_ip,
            ports=port,
        )
        log_threat_to_db(
            "Possible DDoS",
            src_ip,
            dst_ip,
            port,
            meta={
                "window_count": packet_count,
                "protocol": protocol,
                "unique_sources": unique_sources,
                "unique_source_ports": unique_source_ports,
                "time_window_seconds": TIME_WINDOW,
            },
        )
        ip_request_count[key].clear()
        ddos_sources[key].clear()
        ddos_source_ports[key].clear()


def detect_port_scan(src_ip, dst_ip, port):
    if port is None:
        return

    now = time.time()
    key = (src_ip, dst_ip)
    ip_ports_accessed[key].append((port, now))
    ip_ports_accessed[key] = [
        entry for entry in ip_ports_accessed[key] if now - entry[1] < TIME_WINDOW
    ]

    unique_ports = {entry[0] for entry in ip_ports_accessed[key]}
    total = len(ip_ports_accessed[key])
    unique_count = len(unique_ports)
    ratio = (unique_count / total) if total > 0 else 0
    if (
        unique_count > PORT_SCAN_THRESHOLD
        and total > PORT_SCAN_THRESHOLD
        and ratio > 0.7
    ):
        sorted_ports = sorted(unique_ports)
        send_alert(
            f"Multiple destination ports accessed on {dst_ip}: {sorted_ports}",
            src_ip,
            "Port Scan",
            destination_ip=dst_ip,
            ports=sorted_ports,
        )
        log_threat_to_db(
            "Port Scanning",
            src_ip,
            dst_ip,
            sorted_ports,
            meta={
                "unique_ports": sorted_ports,
                "total_events": total,
                "ratio": ratio,
                "time_window_seconds": TIME_WINDOW,
            },
        )
        ip_ports_accessed[key].clear()


def detect_web_attacks(packet):
    if not packet.haslayer(TCP) or not packet.haslayer(Raw):
        return

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    payload = unquote(packet[Raw].load.decode(errors="ignore"))
    is_http_request = packet.haslayer(HTTPRequest)
    looks_http_request = looks_like_http_request_payload(payload)
    if not is_http_request and not looks_http_request:
        return

    request_details = extract_http_request_details(payload)
    if not is_http_request and not request_details:
        return

    debug_log_http_payload(
        packet,
        payload,
        "HTTPRequest layer present" if is_http_request else "HTTP-like raw request payload",
    )

    now = time.time()

    payload_to_scan = payload
    if request_details:
        payload_to_scan = "\n".join(
            part
            for part in [
                request_details.get("request_line"),
                request_details.get("host"),
                request_details.get("target"),
            ]
            if part
        )

    fingerprint = build_request_fingerprint(packet, payload_to_scan)
    sql_match = any(re.search(pattern, payload_to_scan, re.I) for pattern in SQL_PATTERNS)
    xss_match = any(re.search(pattern, payload_to_scan, re.I) for pattern in XSS_PATTERNS)
    if DEBUG_HTTP_PAYLOADS and (sql_match or xss_match):
        print(
            f"[HTTP DEBUG] matched sql={sql_match} xss={xss_match} src={src_ip} dst={dst_ip}"
        )

    if sql_match and track_deduped_request(
        sql_request_fingerprints, src_ip, fingerprint, now
    ):
        sql_injection_attempts[src_ip].append(now)

    if xss_match and track_deduped_request(
        xss_request_fingerprints, src_ip, fingerprint, now
    ):
        xss_attempts[src_ip].append(now)

    sql_injection_attempts[src_ip] = prune_old_entries(
        sql_injection_attempts[src_ip], now, 60
    )
    xss_attempts[src_ip] = prune_old_entries(xss_attempts[src_ip], now, 60)

    if len(sql_injection_attempts[src_ip]) >= SQL_INJECTION_THRESHOLD:
        send_alert(
            "Repeated SQL patterns detected",
            src_ip,
            "SQL Injection",
            destination_ip=dst_ip,
            ports="HTTP",
        )
        meta = extract_meta_from_packet(packet, src_ip, dst_ip, "HTTP")
        meta["attack"] = "SQLi"
        meta["attempt_count"] = len(sql_injection_attempts[src_ip])
        log_threat_to_db("SQL Injection", src_ip, dst_ip, "HTTP", meta=meta)
        sql_injection_attempts[src_ip].clear()
        sql_request_fingerprints[src_ip].clear()

    if len(xss_attempts[src_ip]) >= XSS_THRESHOLD:
        send_alert(
            "Repeated XSS patterns detected",
            src_ip,
            "XSS",
            destination_ip=dst_ip,
            ports="HTTP",
        )
        meta = extract_meta_from_packet(packet, src_ip, dst_ip, "HTTP")
        meta["attack"] = "XSS"
        meta["attempt_count"] = len(xss_attempts[src_ip])
        log_threat_to_db("XSS Attack", src_ip, dst_ip, "HTTP", meta=meta)
        xss_attempts[src_ip].clear()
        xss_request_fingerprints[src_ip].clear()

    host = request_details.get("host") if request_details else extract_host_from_payload(payload)
    if host and host in MALICIOUS_DOMAINS:
        send_alert(
            "OSINT-listed domain detected",
            src_ip,
            "OSINT-Domain",
            destination_ip=host,
            ports="HTTP",
        )
        log_threat_to_db(
            "Malicious Domain (OSINT)",
            src_ip,
            host,
            "HTTP",
            meta={"domain": host},
        )


def detect_threat(packet):
    if not packet.haslayer(IP):
        return

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    port = None
    if packet.haslayer(TCP):
        port = packet[TCP].dport
    elif packet.haslayer(UDP):
        port = packet[UDP].dport

    if src_ip in MALICIOUS_IPS:
        send_alert(
            "OSINT-listed IP detected",
            src_ip,
            "OSINT",
            destination_ip=dst_ip,
            ports=port,
        )
        log_threat_to_db(
            "Malicious IP (OSINT)",
            src_ip,
            dst_ip,
            port,
            meta={"osint": True},
        )

    detect_ddos(packet, src_ip, dst_ip, port)
    detect_port_scan(src_ip, dst_ip, port)

    if packet.haslayer(TCP) and packet.haslayer(Raw):
        detect_web_attacks(packet)

    if packet.haslayer(TCP):
        now = time.time()
        flags = packet[TCP].flags
        try:
            flag_number = int(flags)
            is_syn = (flag_number & 0x02) != 0
            is_ack = (flag_number & 0x10) != 0
        except Exception:
            flag_string = str(flags)
            is_syn = "S" in flag_string and "A" not in flag_string
            is_ack = "A" in flag_string

        flow_key = (src_ip, dst_ip, port)
        if is_syn and not is_ack:
            syn_flow_events[flow_key].append(now)
        elif is_syn and is_ack:
            correlated_key = (dst_ip, src_ip, packet[TCP].sport)
            synack_flow_events[correlated_key].append(now)

        syn_count, synack_count, ratio = summarize_source_syn_state(src_ip, now)
        if syn_count > SYN_FLOOD_THRESHOLD and ratio < SYN_ACK_RATIO_THRESHOLD:
            send_alert(
                "SYN flood suspected",
                src_ip,
                "SYN Flood",
                destination_ip=dst_ip,
                ports=port,
            )
            meta = {
                "syn_count": syn_count,
                "synack_count": synack_count,
                "synack_ratio": ratio,
                "time_window_seconds": TIME_WINDOW,
            }
            log_threat_to_db("SYN Flood", src_ip, dst_ip, port, meta=meta)
            for key in [key for key in syn_flow_events if key[0] == src_ip]:
                syn_flow_events.pop(key, None)
            for key in [key for key in synack_flow_events if key[0] == src_ip]:
                synack_flow_events.pop(key, None)

    global PACKET_COUNT
    PACKET_COUNT += 1
    if PACKET_COUNT - _last_flushed >= FLUSH_INTERVAL:
        _flush_packet_count()


PACKET_COUNT = 0
FLUSH_INTERVAL = 100
_last_flushed = 0


def _flush_packet_count():
    global _last_flushed
    from db import get_stat, set_stat

    try:
        current = get_stat("packet_count", "0")
        total = int(current or "0") + (PACKET_COUNT - _last_flushed)
        set_stat("packet_count", total)
        _last_flushed = PACKET_COUNT
    except Exception:
        pass


def start_sniffing():
    print("Packet sniffing started")
    sniff(iface=NETWORK_INTERFACE, prn=detect_threat, store=False)


if __name__ == "__main__":
    start_sniffing()
