# Network Threat Detection & Analytics Platform

A real-time network threat detection and analytics project built to understand how security monitoring systems work end-to-end.  
The system captures live network traffic, detects common attack patterns, enriches events using OSINT feeds, and visualizes threats through a live web dashboard.

This project was developed as part of a **B.Tech final semester project**, with a focus on learning detection engineering, packet analysis, and real-time security data pipelines rather than building a production-grade IDS.

---

## Features

### Threat Detection
- DDoS and SYN flood detection (volume and ratio based)
- Port scanning detection
- SQL Injection and XSS detection (pattern-based)
- OSINT enrichment using public threat intelligence feeds

### Analytics & Visualization
- Real-time threat streaming using Server-Sent Events (SSE)
- Interactive dashboard with:
  - Threat counters
  - Time-series trends
  - Threat distribution charts
  - Filtering, sorting, and pagination
- Dark/light theme toggle

### Alerting
- Email alerts for high-confidence detections
- Alert throttling to prevent notification spam

---

## Tech Stack

### Detection Engine
- Python
- Scapy

### Backend API
- Flask
- Flask-CORS
- pandas
- numpy
- Server-Sent Events (SSE)

### Frontend
- React
- Recharts

### Threat Intelligence
- Feodo Tracker (malicious IPs)
- URLhaus (malicious domains)

### Data Pipeline
- CSV-based log ingestion (used for simplicity and learning purposes)

---

## Architecture

flowchart TD
    A[Network Traffic] --> B[Scapy Detection Engine]
    B --> C[Threat Detection Logic]
    C -->|Detected Events| D[CSV Threat Logs]
    C -->|High Severity| E[Email Alerts]
    C -->|Threat Intel Lookup| F[OSINT Feeds (Feodo, URLhaus)]
    D --> G[Flask Backend API]
    G -->|REST API| H[React Dashboard]
    G -->|Server-Sent Events| H
    H --> I[Live Charts & Analytics]



Network Traffic
|
v
[ Scapy Detection Engine ]
|
v
[ CSV Threat Logs ]
|
v
[ Flask API ]
| |
| REST | SSE
v v
[ React Analytics Dashboard ]

OSINT Feeds → Detection Engine
Detection Engine → Email Alerts


---

## Project Structure



network-threat-detection-platform/
│
├── backend/
│ ├── api/
│ │ └── server.py
│ ├── detectors/
│ │ └── detector.py
│ ├── data/
│ │ └── realtime_logs.csv (gitignored)
│ └── requirements.txt
│
├── frontend/
│ └── threat-analytics-ui/
│ ├── src/
│ ├── public/
│ └── package.json
│
├── README.md
├── LICENSE
└── .gitignore


---

## Setup Instructions

### Prerequisites
- Python 3.10+
- Node.js 18–20 (LTS recommended)
- Npcap (for packet capture on Windows)

---

### 1. Clone the Repository
```bash
git clone https://github.com/<your-username>/network-threat-detection-platform.git
cd network-threat-detection-platform

2. Backend Setup
pip install -r backend/requirements.txt
python -m backend.api.server


The Flask API runs on:

http://localhost:5000

3. Start Detection Engine
python -m backend.detectors.detector


Note: Packet capture requires appropriate privileges and a valid network interface.

4. Frontend Setup
cd frontend/threat-analytics-ui
npm install
npm start


The dashboard runs on:

http://localhost:3000

Configuration

Example environment variables:

ALERT_SENDER_EMAIL=your_email@gmail.com
ALERT_SENDER_PASSWORD=your_app_password
ALERT_RECIPIENT_EMAILS=security@example.com
REACT_APP_API_BASE=http://localhost:5000

Limitations

SQL Injection and XSS detection is regex-based and may produce false positives

Static thresholds are used for volumetric attacks

CSV storage is not suitable for high-scale or concurrent environments

No authentication or access control

Not designed for production deployment

These trade-offs were made intentionally to prioritize learning and clarity.

Learning Outcomes

Through this project, I gained hands-on experience with:

Packet-level network traffic analysis

Detection logic design and trade-offs

Real-time backend-to-frontend data streaming

Security analytics dashboard design

OSINT integration in detection pipelines

License

This project is licensed under the MIT License.

Disclaimer

This project is for educational and research purposes only.
Do not deploy this system in production or expose it to the public internet.