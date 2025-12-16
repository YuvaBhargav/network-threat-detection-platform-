import os
import sys
import time
import threading
import smtplib
import datetime
import requests
import re
import json
from collections import defaultdict
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from urllib.parse import unquote

import scapy.all as scapy
from scapy.all import sniff, IP, TCP, UDP, Raw
from scapy.layers.http import HTTPRequest

# Add parent directory to path for imports
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

from config import get_config, get_network_interface, get_alert_email_config
from geolocation import get_geolocation_service
from alert_history import get_alert_history
from db import get_db

# Load configuration
config = get_config()
detection_config = config["detection"]
alerts_config = config["alerts"]
osint_config = config["osint"]

NETWORK_INTERFACE = get_network_interface()

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



ip_request_count = defaultdict(lambda: defaultdict(list))
ip_ports_accessed = defaultdict(list)

sql_injection_attempts = defaultdict(list)
xss_attempts = defaultdict(list)


last_alert_time = {}
syn_events = defaultdict(list)
ack_events = defaultdict(list)

MALICIOUS_IPS = set()
MALICIOUS_DOMAINS = set()



SQL_PATTERNS = [
    r"(\%27)|(\')|(\-\-)|(\%23)|(#)",
    r"union\s+select",
    r"or\s+1=1",
    r"exec(\s|\+)+(s|x)p\w+"
]

XSS_PATTERNS = [
    r"<script[^>]*>.*?</script>",
    r"javascript:",
    r"onerror\s*=",
    r"onload\s*=",
    r"alert\s*\("
]



def fetch_osint_data():
    global MALICIOUS_IPS, MALICIOUS_DOMAINS
    try:
        feodo_url = osint_config.get("feodo_tracker_url", 
                                     "https://feodotracker.abuse.ch/downloads/ipblocklist.txt")
        resp = requests.get(feodo_url, timeout=10)
        if resp.status_code == 200:
            MALICIOUS_IPS = {
                line.strip()
                for line in resp.text.splitlines()
                if line and not line.startswith("#")
            }
            print(f"✅ Loaded {len(MALICIOUS_IPS)} malicious IPs from Feodo Tracker")
        
        urlhaus_url = osint_config.get("urlhaus_url",
                                       "https://urlhaus.abuse.ch/downloads/text/")
        dresp = requests.get(urlhaus_url, timeout=10)
        if dresp.status_code == 200:
            MALICIOUS_DOMAINS = {
                line.strip()
                for line in dresp.text.splitlines()
                if line and not line.startswith("#") and line.strip()
            }
            print(f"✅ Loaded {len(MALICIOUS_DOMAINS)} malicious domains from URLhaus")
    except Exception as e:
        print(f"⚠️ OSINT fetch failed: {e}")

fetch_osint_data()

# Schedule periodic OSINT updates
def schedule_osint_updates():
    """Periodically refresh OSINT data"""
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

    # Get geolocation data
    geo_service = get_geolocation_service()
    geolocation = None
    if geo_service.enabled:
        try:
            geolocation = geo_service.get_location(src_ip)
        except Exception as e:
            print(f"⚠️ Geolocation lookup failed for {src_ip}: {e}")

    # Add to alert history
    alert_history = get_alert_history()
    alert_history.add_alert(attack_type, src_ip, message, destination_ip, ports, geolocation)

    # Send email if configured
    if alerts_config.get("enabled", True) and SENDER_EMAIL and SENDER_PASSWORD and RECIPIENT_EMAILS:
        msg = MIMEMultipart()
        msg["From"] = SENDER_EMAIL
        msg["To"] = ", ".join(RECIPIENT_EMAILS)
        msg["Subject"] = f"🚨 Security Alert: {attack_type}"

        geo_info = ""
        if geolocation:
            geo_info = f"\nLocation: {geolocation.get('city', 'Unknown')}, {geolocation.get('country', 'Unknown')}"
            if geolocation.get('isp'):
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
            last_alert_time[key] = now
            print(f"📧 Alert sent: {attack_type} from {src_ip}")
        except Exception as e:
            print(f"❌ Email error: {e}")
    else:
        print(f"📧 Alert logged: {attack_type} from {src_ip} (email not configured)")



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
                meta["http_host"] = packet[HTTPRequest].Host.decode() if hasattr(packet[HTTPRequest].Host, "decode") else packet[HTTPRequest].Host
                meta["http_path"] = packet[HTTPRequest].Path.decode() if hasattr(packet[HTTPRequest].Path, "decode") else packet[HTTPRequest].Path
                meta["http_method"] = packet[HTTPRequest].Method.decode() if hasattr(packet[HTTPRequest].Method, "decode") else packet[HTTPRequest].Method
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

def log_threat_to_db(threat, src_ip, dst_ip, ports, meta=None):
    conn = get_db()
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    pr = json.dumps(ports) if isinstance(ports, (list, dict)) else str(ports)
    mj = json.dumps(meta) if isinstance(meta, dict) else (meta if meta is not None else None)
    conn.execute(
        "INSERT INTO threats (timestamp, threat_type, source_ip, destination_ip, ports, meta) VALUES (?, ?, ?, ?, ?, ?)",
        (ts, threat, src_ip, dst_ip, pr, mj)
    )
    conn.commit()



def detect_ddos(ip, port):
    if port is None:
        return

    now = time.time()
    ip_request_count[ip][port].append(now)
    ip_request_count[ip][port] = [
        t for t in ip_request_count[ip][port] if now - t < TIME_WINDOW
    ]

    if len(ip_request_count[ip][port]) > DDOS_THRESHOLD:
        send_alert(
            f"High traffic on port {port}",
            ip, "DDoS", destination_ip="N/A", ports=port
        )
        log_threat_to_db("Possible DDoS", ip, "N/A", port, meta={"window_count": len(ip_request_count[ip][port])})
        ip_request_count[ip][port].clear()

def detect_port_scan(ip, port):
    if port is None:
        return

    now = time.time()
    ip_ports_accessed[ip].append((port, now))
    ip_ports_accessed[ip] = [
        p for p in ip_ports_accessed[ip] if now - p[1] < TIME_WINDOW
    ]

    unique_ports = {p[0] for p in ip_ports_accessed[ip]}
    total = len(ip_ports_accessed[ip])
    uniq = len(unique_ports)
    ratio = (uniq / total) if total > 0 else 0
    if uniq > PORT_SCAN_THRESHOLD and total > PORT_SCAN_THRESHOLD and ratio > 0.7:
        send_alert(
            f"Multiple ports accessed: {unique_ports}",
            ip, "Port Scan", destination_ip="N/A", ports=list(unique_ports)
        )
        log_threat_to_db("Port Scanning", ip, "N/A", list(unique_ports), meta={"unique_ports": list(unique_ports), "total_events": total, "ratio": ratio})
        ip_ports_accessed[ip].clear()

def detect_web_attacks(packet):
    if not packet.haslayer(HTTPRequest) or not packet.haslayer(Raw):
        return

    ip = packet[IP].src
    payload = unquote(packet[Raw].load.decode(errors="ignore"))
    now = time.time()

    for pat in SQL_PATTERNS:
        if re.search(pat, payload, re.I):
            sql_injection_attempts[ip].append(now)

    for pat in XSS_PATTERNS:
        if re.search(pat, payload, re.I):
            xss_attempts[ip].append(now)

    sql_injection_attempts[ip] = [t for t in sql_injection_attempts[ip] if now - t < 60]
    xss_attempts[ip] = [t for t in xss_attempts[ip] if now - t < 60]

    if len(sql_injection_attempts[ip]) >= SQL_INJECTION_THRESHOLD:
        send_alert("Repeated SQL patterns detected", ip, "SQL Injection", 
                   destination_ip="Web Server", ports="HTTP")
        meta = extract_meta_from_packet(packet, ip, "Web Server", "HTTP")
        meta["attack"] = "SQLi"
        log_threat_to_db("SQL Injection", ip, "Web Server", "HTTP", meta=meta)
        sql_injection_attempts[ip].clear()

    if len(xss_attempts[ip]) >= XSS_THRESHOLD:
        send_alert("Repeated XSS patterns detected", ip, "XSS",
                   destination_ip="Web Server", ports="HTTP")
        meta = extract_meta_from_packet(packet, ip, "Web Server", "HTTP")
        meta["attack"] = "XSS"
        log_threat_to_db("XSS Attack", ip, "Web Server", "HTTP", meta=meta)
        xss_attempts[ip].clear()
    
    host = None
    try:
        m = re.search(r"\bHost:\s*([^\r\n]+)", payload, re.I)
        if m:
            host = m.group(1).strip().lower()
    except Exception:
        host = None
    if host and host in MALICIOUS_DOMAINS:
        send_alert("OSINT-listed domain detected", ip, "OSINT-Domain",
                   destination_ip=host, ports="HTTP")
        log_threat_to_db("Malicious Domain (OSINT)", ip, host, "HTTP", meta={"domain": host})

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
        send_alert("OSINT-listed IP detected", src_ip, "OSINT",
                   destination_ip=dst_ip, ports=port)
        log_threat_to_db("Malicious IP (OSINT)", src_ip, dst_ip, port, meta={"osint": True})

    detect_ddos(src_ip, port)
    detect_port_scan(src_ip, port)

    if packet.haslayer(TCP) and packet.haslayer(HTTPRequest):
        detect_web_attacks(packet)
    
    if packet.haslayer(TCP):
        now = time.time()
        flags = packet[TCP].flags
        try:
            fnum = int(flags)
            is_syn = (fnum & 0x02) != 0
            is_ack = (fnum & 0x10) != 0
        except Exception:
            fstr = str(flags)
            is_syn = "S" in fstr and "A" not in fstr
            is_ack = "A" in fstr
        if is_syn:
            syn_events[src_ip].append(now)
            syn_events[src_ip] = [t for t in syn_events[src_ip] if now - t < TIME_WINDOW]
        if is_ack:
            ack_events[src_ip].append(now)
            ack_events[src_ip] = [t for t in ack_events[src_ip] if now - t < TIME_WINDOW]
        syn_count = len(syn_events[src_ip])
        ack_count = len(ack_events[src_ip])
        ratio = (ack_count / syn_count) if syn_count > 0 else 1
        if syn_count > SYN_FLOOD_THRESHOLD and ratio < SYN_ACK_RATIO_THRESHOLD:
            send_alert("SYN flood suspected", src_ip, "SYN Flood",
                       destination_ip=dst_ip, ports=port)
            meta = {"syn_count": syn_count, "ack_count": ack_count, "ratio": ratio}
            log_threat_to_db("SYN Flood", src_ip, dst_ip, port, meta=meta)
            syn_events[src_ip].clear()
            ack_events[src_ip].clear()

    global PACKET_COUNT
    PACKET_COUNT += 1
    if PACKET_COUNT - _last_flushed >= FLUSH_INTERVAL:
        _flush_packet_count()

PACKET_COUNT = 0
FLUSH_INTERVAL = 100
_last_flushed = 0

def _flush_packet_count():
    global _last_flushed
    from db import set_stat, get_stat
    try:
        current = get_stat("packet_count", "0")
        total = int(current or "0") + (PACKET_COUNT - _last_flushed)
        set_stat("packet_count", total)
        _last_flushed = PACKET_COUNT
    except Exception:
        pass



def start_sniffing():
    print("🚀 Packet sniffing started")
    sniff(
        iface=NETWORK_INTERFACE,
        prn=detect_threat,
        store=False
    )

if __name__ == "__main__":
    start_sniffing()
