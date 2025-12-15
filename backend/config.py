"""
Configuration management for Network Threat Detection System
Supports both environment variables and config file
"""
import os
import json
from pathlib import Path

BASE_DIR = Path(__file__).parent
CONFIG_FILE = BASE_DIR / "config.json"
DEFAULT_CONFIG = {
    "network_interface": r"\Device\NPF_{C22FD80A-F612-4AD1-9A09-6B940C6353B7}",
    "detection": {
        "ddos_threshold": 300,
        "port_scan_threshold": 10,
        "sql_injection_threshold": 3,
        "xss_threshold": 3,
        "syn_flood_threshold": 200,
        "syn_ack_ratio_threshold": 0.1,
        "time_window_seconds": 10
    },
    "alerts": {
        "enabled": True,
        "throttle_seconds": 300,
        "smtp_server": "smtp.gmail.com",
        "smtp_port": 587
    },
    "osint": {
        "feodo_tracker_url": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
        "urlhaus_url": "https://urlhaus.abuse.ch/downloads/text/",
        "update_interval_hours": 24
    },
    "geolocation": {
        "enabled": True,
        "api_provider": "ipapi",  # Options: "ipapi", "ip-api", "ipinfo"
        "api_key": None  # Optional API key for premium services
    },
    "storage": {
        "log_file": "data/realtime_logs.csv",
        "alert_history_file": "data/alert_history.json"
    }
}

def load_config():
    """Load configuration from file or create default"""
    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE, 'r') as f:
                config = json.load(f)
            # Merge with defaults to ensure all keys exist
            merged = DEFAULT_CONFIG.copy()
            merged.update(config)
            # Deep merge for nested dicts
            if "detection" in config:
                merged["detection"].update(config["detection"])
            if "alerts" in config:
                merged["alerts"].update(config["alerts"])
            if "osint" in config:
                merged["osint"].update(config["osint"])
            if "geolocation" in config:
                merged["geolocation"].update(config["geolocation"])
            if "storage" in config:
                merged["storage"].update(config["storage"])
            return merged
        except Exception as e:
            print(f"⚠️ Error loading config file: {e}. Using defaults.")
            return DEFAULT_CONFIG
    else:
        # Create default config file
        save_config(DEFAULT_CONFIG)
        return DEFAULT_CONFIG

def save_config(config):
    """Save configuration to file"""
    try:
        with open(CONFIG_FILE, 'w') as f:
            json.dump(config, f, indent=2)
    except Exception as e:
        print(f"⚠️ Error saving config file: {e}")

def get_config():
    """Get current configuration (singleton pattern)"""
    if not hasattr(get_config, '_config'):
        get_config._config = load_config()
    return get_config._config

# Environment variable overrides (highest priority)
def get_network_interface():
    return os.getenv("NETWORK_INTERFACE") or get_config()["network_interface"]

def get_alert_email_config():
    config = get_config()
    return {
        "sender_email": os.getenv("ALERT_SENDER_EMAIL") or None,
        "sender_password": os.getenv("ALERT_SENDER_PASSWORD") or None,
        "recipient_emails": [
            e.strip() for e in os.getenv("ALERT_RECIPIENT_EMAILS", "").split(",") 
            if e.strip()
        ] or []
    }

