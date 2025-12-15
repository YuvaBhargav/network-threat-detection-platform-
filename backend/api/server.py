from flask import Flask, Response, jsonify
from flask_cors import CORS
import time
import json
import pandas as pd
import os
from pathlib import Path
import numpy as np

app = Flask(__name__)
CORS(app)

# 🚀 Configuration - Add this section
LOG_DIR = Path("C:/projects/codes")  # Using forward slashes works on Windows too
LOG_FILE = LOG_DIR / "realtime_logs.csv"

# Ensure log directory exists
LOG_DIR.mkdir(parents=True, exist_ok=True)

def get_threats_from_csv():
    if os.path.exists(LOG_FILE):
        try:
            df = pd.read_csv(LOG_FILE)
            # Standardize column names for React frontend
            df = df.rename(columns={
                "Timestamp": "timestamp",
                "Threat Type": "threatType", 
                "Source IP": "sourceIP",
                "Destination IP": "destinationIP",
                "Ports": "ports"
            })
            
            # Replace NaN values with empty strings to avoid JSON serialization issues
            df = df.fillna("")
            
            return df.to_dict('records')
        except Exception as e:
            print(f"Error reading CSV: {e}")
            return []
    return []

# Custom JSON encoder to handle NaN values
class NpEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, np.integer):
            return int(obj)
        if isinstance(obj, np.floating):
            return float(obj)
        if isinstance(obj, np.ndarray):
            return obj.tolist()
        if pd.isna(obj):
            return ""
        return super(NpEncoder, self).default(obj)

@app.route('/api/threats', methods=['GET'])
def get_threats():
    threats = get_threats_from_csv()
    return jsonify(threats)

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
                    # Use custom encoder to handle NaN values
                    yield f"data: {json.dumps(threats[-1], cls=NpEncoder)}\n\n"
                last_size = current_size
            now = time.time()
            if now - last_heartbeat > 15:
                # SSE comment keepalive
                yield ": keepalive\n\n"
                last_heartbeat = now
            time.sleep(1)  # Check for new entries every second

    response = Response(event_stream(), content_type='text/event-stream')
    response.headers['Cache-Control'] = 'no-cache'
    response.headers['Connection'] = 'keep-alive'
    response.headers['Access-Control-Allow-Origin'] = '*'  # Add this line
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

if __name__ == '__main__':
    app.run(debug=True, port=5000)
