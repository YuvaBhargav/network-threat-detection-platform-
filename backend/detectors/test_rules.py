import os
import sys
from pathlib import Path
from contextlib import contextmanager

from scapy.all import IP, TCP, Raw

BASE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE_DIR))

os.environ.setdefault("DEBUG_HTTP_PAYLOADS", "1")

import detector


def reset_state():
    detector.sql_injection_attempts.clear()
    detector.xss_attempts.clear()
    detector.sql_request_fingerprints.clear()
    detector.xss_request_fingerprints.clear()
    detector.ip_request_count.clear()
    detector.ddos_sources.clear()
    detector.ddos_source_ports.clear()
    detector.ip_ports_accessed.clear()
    detector.syn_flow_events.clear()
    detector.synack_flow_events.clear()
    detector.last_alert_time.clear()


def make_http_packet(src_ip, dst_ip, sport, dport, request_text):
    return IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=dport, flags="PA") / Raw(
        load=request_text.encode("utf-8")
    )


def make_tcp_packet(src_ip, dst_ip, sport, dport, flags="S", payload=None):
    packet = IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=dport, flags=flags)
    if payload is not None:
        packet = packet / Raw(load=payload.encode("utf-8"))
    return packet


@contextmanager
def isolated_side_effects():
    original_send_alert = detector.send_alert
    original_log_threat = detector.log_threat_to_db

    def fake_send_alert(*args, **kwargs):
        print("Alert emitted:", args[2], "src=", args[1])

    def fake_log_threat(*args, **kwargs):
        print("Threat logged:", args[0], "src=", args[1], "dst=", args[2], "ports=", args[3])

    detector.send_alert = fake_send_alert
    detector.log_threat_to_db = fake_log_threat
    try:
        yield
    finally:
        detector.send_alert = original_send_alert
        detector.log_threat_to_db = original_log_threat


def run_sqli_test():
    print("Running SQL injection rule test...")
    reset_state()
    src_ip = "10.10.10.50"
    dst_ip = "192.168.1.105"
    payloads = [
        "GET /?q=' OR 1=1 HTTP/1.1\r\nHost: test.local\r\n\r\n",
        "GET /?q=' UNION SELECT 1 HTTP/1.1\r\nHost: test.local\r\n\r\n",
        "GET /?q=' OR 1=1-- HTTP/1.1\r\nHost: test.local\r\n\r\n",
    ]
    with isolated_side_effects():
        for index, payload in enumerate(payloads, start=1):
            packet = make_http_packet(src_ip, dst_ip, 40000 + index, 8080, payload)
            detector.detect_web_attacks(packet)

    print("SQLi counter:", len(detector.sql_injection_attempts[src_ip]))


def run_xss_test():
    print("Running XSS rule test...")
    reset_state()
    src_ip = "10.10.10.51"
    dst_ip = "192.168.1.105"
    payloads = [
        "GET /?q=<script>alert(1)</script> HTTP/1.1\r\nHost: test.local\r\n\r\n",
        "GET /?q=javascript:alert(1) HTTP/1.1\r\nHost: test.local\r\n\r\n",
        "GET /?q=<img src=x onerror=alert(1)> HTTP/1.1\r\nHost: test.local\r\n\r\n",
    ]
    with isolated_side_effects():
        for index, payload in enumerate(payloads, start=1):
            packet = make_http_packet(src_ip, dst_ip, 41000 + index, 8080, payload)
            detector.detect_web_attacks(packet)

    print("XSS counter:", len(detector.xss_attempts[src_ip]))


def run_port_scan_test():
    print("Running port scan rule test...")
    reset_state()
    src_ip = "10.10.10.60"
    dst_ip = "192.168.1.105"
    with isolated_side_effects():
        for port in range(20, 36):
            detector.detect_port_scan(src_ip, dst_ip, port)
    tracked = detector.ip_ports_accessed.get((src_ip, dst_ip), [])
    print("Tracked port scan entries after alert:", len(tracked))


def run_ddos_test():
    print("Running DDoS rule test...")
    reset_state()
    dst_ip = "192.168.1.105"
    dport = 80
    original_threshold = detector.DDOS_THRESHOLD
    detector.DDOS_THRESHOLD = 5
    try:
        with isolated_side_effects():
            for index, src_ip in enumerate(["10.10.10.70", "10.10.10.71", "10.10.10.72"]):
                for offset in range(2):
                    packet = make_tcp_packet(src_ip, dst_ip, 50000 + index * 10 + offset, dport, flags="S")
                    detector.detect_ddos(packet, src_ip, dst_ip, dport)
        key = (dst_ip, dport, "TCP")
        print("DDoS state after alert:", len(detector.ip_request_count.get(key, [])))
    finally:
        detector.DDOS_THRESHOLD = original_threshold


def run_syn_flood_test():
    print("Running SYN flood rule test...")
    reset_state()
    src_ip = "10.10.10.80"
    dst_ip = "192.168.1.105"
    port = 443
    original_threshold = detector.SYN_FLOOD_THRESHOLD
    detector.SYN_FLOOD_THRESHOLD = 5
    try:
        with isolated_side_effects():
            for offset in range(6):
                packet = make_tcp_packet(src_ip, dst_ip, 51000 + offset, port, flags="S")
                detector.detect_threat(packet)
        syn_count, synack_count, ratio = detector.summarize_source_syn_state(src_ip, __import__("time").time())
        print("SYN state:", {"syn_count": syn_count, "synack_count": synack_count, "ratio": ratio})
    finally:
        detector.SYN_FLOOD_THRESHOLD = original_threshold


if __name__ == "__main__":
    run_sqli_test()
    run_xss_test()
    run_port_scan_test()
    run_ddos_test()
    run_syn_flood_test()
    print("Done. These tests validate detector logic without writing alerts or threats to the database.")
