import os
import scapy.all as scapy
from scapy.all import sniff, IP, TCP, UDP, Raw
import time
import threading
import smtplib
import datetime
import pandas as pd
import requests
import re  # Add missing import for regex
from collections import defaultdict
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from scapy.layers.http import HTTPRequest, HTTPResponse

# 🚀 Configuration
NETWORK_INTERFACE = "Wi-Fi" or 5 # Change to your network interface
SENDER_EMAIL = "yuvabhargav.mandhapati9220@gmail.com"
SENDER_PASSWORD = "t****************"
RECIPIENT_EMAILS = ["yuvaybhhh@gmail.com","mehulbhatt2705@gmail.com"]

# 🚨 Attack Thresholds
DDOS_THRESHOLD = 100  # Requests per 10 seconds per IP to the same port
PORT_SCAN_THRESHOLD = 10  # Unique ports accessed per IP within 10 seconds
SQL_INJECTION_THRESHOLD = 3  # Number of suspicious SQL patterns in 60 seconds
XSS_THRESHOLD = 3  # Number of suspicious XSS patterns in 60 seconds

# 📌 Log File Path (CSV)
LOG_DIR = r"C:\captures\codes"
LOG_FILE = os.path.join(LOG_DIR, "realtime_logs.csv")

if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR)
if not os.path.exists(LOG_FILE):
    pd.DataFrame(columns=["Timestamp", "Threat Type", "Source IP", "Destination IP", "Ports"]).to_csv(LOG_FILE, index=False)

# 🕵️‍♂️ Attack Tracking Structures
ip_request_count = defaultdict(lambda: defaultdict(list))  # {IP: {Port: [timestamps]}}
ip_ports_accessed = defaultdict(lambda: [])  # {IP: [unique_ports]}
sql_injection_attempts = defaultdict(list)  # {IP: [timestamps]}
xss_attempts = defaultdict(list)  # {IP: [timestamps]}
# 🕒 Tracks last alert sent time per IP
last_alert_time = {}  # {IP: timestamp}

# Add pattern detection for web attacks
SQL_PATTERNS = [
    r"(\%27)|(\')|(\-\-)|(\%23)|(#)",
    r"((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))",
    r"((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))",
    r"((\%27)|(\'))union",
    r"exec(\s|\+)+(s|x)p\w+",
    r"UNION(\s+)ALL(\s+)SELECT"
]

XSS_PATTERNS = [
    r"<script[^>]*>.*?</script>",
    r"javascript:",
    r"onload\s*=",
    r"onerror\s*=",
    r"onclick\s*=",
    r"eval\s*\(",
    r"alert\s*\("
]

# 📌 Fetch OSINT Threat Intelligence Feeds
def fetch_osint_data():
    global MALICIOUS_IPS, MALICIOUS_DOMAINS
    try:
        response = requests.get("https://feodotracker.abuse.ch/downloads/ipblocklist.txt")
        if response.status_code == 200:
            MALICIOUS_IPS = set(response.text.split("\n")[9:])
        response = requests.get("https://urlhaus.abuse.ch/downloads/text/")
        if response.status_code == 200:
            MALICIOUS_DOMAINS = set(line.strip() for line in response.text.split("\n") if not line.startswith("#"))
        print("✅ OSINT threat data updated successfully!")
    except Exception as e:
        print(f"⚠️ Failed to fetch OSINT data: {e}")

MALICIOUS_IPS = set()
MALICIOUS_DOMAINS = set()
fetch_osint_data()

# Add new detection function for web attacks - MOVED UP before it's called
def detect_web_attacks(packet):
    if packet.haslayer(HTTPRequest):
        # Extract IP and payload
        ip = packet[IP].src
        current_time = time.time()
        
        # Extract URL and potential parameters
        if packet.haslayer(Raw):
            payload = packet[Raw].load.decode('utf-8', errors='ignore')
            
            # Check for SQL Injection
            for pattern in SQL_PATTERNS:
                if re.search(pattern, payload, re.IGNORECASE):
                    sql_injection_attempts[ip].append(current_time)
                    break
            
            # Check for XSS
            for pattern in XSS_PATTERNS:
                if re.search(pattern, payload, re.IGNORECASE):
                    xss_attempts[ip].append(current_time)
                    break
            
            # Clean old attempts (older than 60 seconds)
            sql_injection_attempts[ip] = [t for t in sql_injection_attempts[ip] if current_time - t < 60]
            xss_attempts[ip] = [t for t in xss_attempts[ip] if current_time - t < 60]
            
            # Alert if thresholds exceeded
            if len(sql_injection_attempts[ip]) >= SQL_INJECTION_THRESHOLD:
                send_alert(f"🚨 Possible SQL Injection attempts from {ip}", ip)
                log_to_csv("🚨 Possible SQL Injection", ip, "Web Server", "HTTP")
                sql_injection_attempts[ip] = []  # Reset after alert
                
            if len(xss_attempts[ip]) >= XSS_THRESHOLD:
                send_alert(f"🚨 Possible XSS attempts from {ip}", ip)
                log_to_csv("🚨 Possible XSS Attack", ip, "Web Server", "HTTP")
                xss_attempts[ip] = []  # Reset after alert

# 📌 Threat Detection Function
def detect_threat(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        dst_port = packet[TCP].dport if packet.haslayer(TCP) else (packet[UDP].dport if packet.haslayer(UDP) else None)

        threat_type = None

        # 🚨 OSINT Check
        if src_ip in MALICIOUS_IPS or dst_ip in MALICIOUS_IPS:
            threat_type = "Malicious IP (OSINT)"
            send_alert(f"Malicious IP detected: {src_ip}", src_ip)

        # 🔥 Detect DDoS
        detect_ddos(src_ip, dst_port)

        # 🔥 Detect Port Scanning
        detect_port_scan(src_ip, dst_port)
        
        # 🔥 Detect Web Attacks
        detect_web_attacks(packet)

        # 📝 Log Threat if Detected
        if threat_type:
            log_to_csv(threat_type, src_ip, dst_ip, f"{dst_port}")

# 📌 DDoS Detection Function
def detect_ddos(ip, port):
    current_time = time.time()

    # Record request timestamp for the specific IP & port
    ip_request_count[ip][port].append(current_time)

    # Remove old requests (older than 10 sec)
    ip_request_count[ip][port] = [t for t in ip_request_count[ip][port] if current_time - t < 10]

    # 🚨 Alert if same port is hit too frequently (DDoS)
    if len(ip_request_count[ip][port]) > DDOS_THRESHOLD:
        send_alert(f"🚨 Possible DDoS Attack from {ip} on port {port}", ip)
        log_to_csv("🚨 Possible DDoS Attack", ip, "N/A", f"Port {port}")
        ip_request_count[ip][port] = []  # Reset after alert

# 📌 Port Scan Detection Function
def detect_port_scan(ip, port):
    current_time = time.time()

    # Record the unique port access with timestamp
    if port not in [p[0] for p in ip_ports_accessed[ip]]:
        ip_ports_accessed[ip].append((port, current_time))

    # Remove old ports (older than 10 sec)
    ip_ports_accessed[ip] = [p for p in ip_ports_accessed[ip] if current_time - p[1] < 10]

    # 🚨 Alert if too many unique ports are accessed (Port Scanning)
    if len(ip_ports_accessed[ip]) > PORT_SCAN_THRESHOLD:
        ports = [p[0] for p in ip_ports_accessed[ip]]
        send_alert(f"🚨 Possible Port Scanning from {ip}", ip)
        log_to_csv("🚨 Possible Port Scanning", ip, "N/A", f"Ports: {ports}")
        ip_ports_accessed[ip] = []  # Reset after alert

# 📌 Real-Time Packet Sniffing
def start_packet_sniffing():
    print("🚀 Real-Time Packet Sniffing Started... Press Ctrl+C to stop.")
    sniff(iface=NETWORK_INTERFACE, prn=detect_threat, store=False)

# 📨 Email Alert Function
def send_alert(message, src_ip):
    global last_alert_time

    # 🛑 Spam Prevention: Rate limit emails (1 email per 5 minutes per source IP)
    current_time = time.time()
    if src_ip in last_alert_time and (current_time - last_alert_time[src_ip] < 400):
        print(f"⚠️ Email suppressed to prevent spam (last sent {current_time - last_alert_time[src_ip]:.2f} sec ago)")
        return  # Skip sending

    subject = f"🚨 Security Alert: {message}"
    body = f"""
    Threat Alert: {message}
    Timestamp: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

    Please take immediate action!
    """

    msg = MIMEMultipart()
    msg["From"] = SENDER_EMAIL
    msg["To"] = ", ".join(RECIPIENT_EMAILS)  # Convert list to a single string
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain", "utf-8"))

    try:
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        server.sendmail(SENDER_EMAIL, RECIPIENT_EMAILS, msg.as_string())  # Fixed here
        server.quit()
        print(f"📧 Alert Sent: {message} to {', '.join(RECIPIENT_EMAILS)}")

        last_alert_time[src_ip] = current_time  # Update last alert timestamp
    except Exception as e:
        print(f"❌ Failed to send alert: {e}")


# 📌 Log Threat Data to CSV
def log_to_csv(threat_type, src_ip, dst_ip, ports):
    log_entry = {
        "Timestamp": datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        "Threat Type": threat_type,
        "Source IP": src_ip,
        "Destination IP": dst_ip,
        "Ports": ports
    }

    df = pd.DataFrame([log_entry])
    df.to_csv(LOG_FILE, mode="a", index=False, header=False)
    with open(LOG_FILE, 'a') as f:  # Add explicit flush
        f.flush()
    print(f"📝 Logged: {threat_type} - {src_ip}")

# 🚀 Start Sniffing in a Separate Thread
if __name__ == "__main__":
    sniff_thread = threading.Thread(target=start_packet_sniffing, daemon=True)
    sniff_thread.start()
    sniff_thread.join()
