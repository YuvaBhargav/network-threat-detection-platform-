import os
import time
import threading
import smtplib
import datetime
import requests
import re
import csv
from collections import defaultdict
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from urllib.parse import unquote

import scapy.all as scapy
from scapy.all import sniff, IP, TCP, UDP, Raw
from scapy.layers.http import HTTPRequest



NETWORK_INTERFACE = r"\Device\NPF_{C22FD80A-F612-4AD1-9A09-6B940C6353B7}"  

SENDER_EMAIL = os.getenv("ALERT_SENDER_EMAIL")
SENDER_PASSWORD = os.getenv("ALERT_SENDER_PASSWORD")
RECIPIENT_EMAILS = [e.strip() for e in os.getenv("ALERT_RECIPIENT_EMAILS", "").split(",") if e.strip()]

DDOS_THRESHOLD = 300          
PORT_SCAN_THRESHOLD = 10     
SQL_INJECTION_THRESHOLD = 3   
XSS_THRESHOLD = 3             
SYN_FLOOD_THRESHOLD = 200
SYN_ACK_RATIO_THRESHOLD = 0.1

LOG_DIR = r"C:\projects\codes"
LOG_FILE = os.path.join(LOG_DIR, "realtime_logs.csv")



os.makedirs(LOG_DIR, exist_ok=True)

if not os.path.exists(LOG_FILE):
    with open(LOG_FILE, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            "Timestamp", "Threat Type",
            "Source IP", "Destination IP", "Ports"
        ])



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
        resp = requests.get(
            "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
            timeout=10
        )
        if resp.status_code == 200:
            MALICIOUS_IPS = {
                line.strip()
                for line in resp.text.splitlines()
                if line and not line.startswith("#")
            }
        dresp = requests.get(
            "https://urlhaus.abuse.ch/downloads/text/",
            timeout=10
        )
        if dresp.status_code == 200:
            MALICIOUS_DOMAINS = {
                line.strip()
                for line in dresp.text.splitlines()
                if line and not line.startswith("#") and line.strip()
            }
    except Exception as e:
        print(f"⚠️ OSINT fetch failed: {e}")

fetch_osint_data()



def send_alert(message, src_ip, attack_type):
    now = time.time()
    key = (src_ip, attack_type)

    if key in last_alert_time and now - last_alert_time[key] < 300:
        return

    if not SENDER_EMAIL or not SENDER_PASSWORD or not RECIPIENT_EMAILS:
        print("⚠️ Email credentials or recipients not configured. Set ALERT_SENDER_EMAIL, ALERT_SENDER_PASSWORD, ALERT_RECIPIENT_EMAILS.")
        return

    msg = MIMEMultipart()
    msg["From"] = SENDER_EMAIL
    msg["To"] = ", ".join(RECIPIENT_EMAILS)
    msg["Subject"] = f"🚨 Security Alert: {attack_type}"

    body = f"""
Threat Detected: {attack_type}
Source IP: {src_ip}
Details: {message}
Time: {datetime.datetime.now()}
"""
    msg.attach(MIMEText(body, "plain", "utf-8"))

    try:
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        server.sendmail(SENDER_EMAIL, RECIPIENT_EMAILS, msg.as_string())
        server.quit()
        last_alert_time[key] = now
        print(f"📧 Alert sent: {attack_type} from {src_ip}")
    except Exception as e:
        print(f"❌ Email error: {e}")



def log_to_csv(threat, src_ip, dst_ip, ports):
    with open(LOG_FILE, "a", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            threat, src_ip, dst_ip, ports
        ])



def detect_ddos(ip, port):
    if port is None:
        return

    now = time.time()
    ip_request_count[ip][port].append(now)
    ip_request_count[ip][port] = [
        t for t in ip_request_count[ip][port] if now - t < 10
    ]

    if len(ip_request_count[ip][port]) > DDOS_THRESHOLD:
        send_alert(
            f"High traffic on port {port}",
            ip, "DDoS"
        )
        log_to_csv("Possible DDoS", ip, "N/A", port)
        ip_request_count[ip][port].clear()

def detect_port_scan(ip, port):
    if port is None:
        return

    now = time.time()
    ip_ports_accessed[ip].append((port, now))
    ip_ports_accessed[ip] = [
        p for p in ip_ports_accessed[ip] if now - p[1] < 10
    ]

    unique_ports = {p[0] for p in ip_ports_accessed[ip]}
    total = len(ip_ports_accessed[ip])
    uniq = len(unique_ports)
    ratio = (uniq / total) if total > 0 else 0
    if uniq > PORT_SCAN_THRESHOLD and total > PORT_SCAN_THRESHOLD and ratio > 0.7:
        send_alert(
            f"Multiple ports accessed: {unique_ports}",
            ip, "Port Scan"
        )
        log_to_csv("Port Scanning", ip, "N/A", list(unique_ports))
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
        send_alert("Repeated SQL patterns detected", ip, "SQL Injection")
        log_to_csv("SQL Injection", ip, "Web Server", "HTTP")
        sql_injection_attempts[ip].clear()

    if len(xss_attempts[ip]) >= XSS_THRESHOLD:
        send_alert("Repeated XSS patterns detected", ip, "XSS")
        log_to_csv("XSS Attack", ip, "Web Server", "HTTP")
        xss_attempts[ip].clear()
    
    host = None
    try:
        m = re.search(r"\bHost:\s*([^\r\n]+)", payload, re.I)
        if m:
            host = m.group(1).strip().lower()
    except Exception:
        host = None
    if host and host in MALICIOUS_DOMAINS:
        send_alert("OSINT-listed domain detected", ip, "OSINT-Domain")
        log_to_csv("Malicious Domain (OSINT)", ip, host, "HTTP")

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
        send_alert("OSINT-listed IP detected", src_ip, "OSINT")
        log_to_csv("Malicious IP (OSINT)", src_ip, dst_ip, port)

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
            syn_events[src_ip] = [t for t in syn_events[src_ip] if now - t < 10]
        if is_ack:
            ack_events[src_ip].append(now)
            ack_events[src_ip] = [t for t in ack_events[src_ip] if now - t < 10]
        syn_count = len(syn_events[src_ip])
        ack_count = len(ack_events[src_ip])
        ratio = (ack_count / syn_count) if syn_count > 0 else 1
        if syn_count > SYN_FLOOD_THRESHOLD and ratio < SYN_ACK_RATIO_THRESHOLD:
            send_alert("SYN flood suspected", src_ip, "SYN Flood")
            log_to_csv("SYN Flood", src_ip, dst_ip, port)
            syn_events[src_ip].clear()
            ack_events[src_ip].clear()



def start_sniffing():
    print("🚀 Packet sniffing started")
    sniff(
        iface=NETWORK_INTERFACE,
        prn=detect_threat,
        store=False
    )

if __name__ == "__main__":
    start_sniffing()
