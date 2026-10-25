# sniffer.py — Advanced Multi-Vector Threat Detection Engine
"""
Real network packet sniffer with multiple attack detection patterns:
1. SYN Flood Detection (high-rate incomplete TCP handshakes)
2. Port Scan Detection (single IP probing multiple ports)
3. HTTP Brute Force (rapid-fire requests to common ports)

Requires: pip install scapy requests
Must run as Administrator/root for raw packet capture.
"""

import os
import json
import time
import threading
from collections import defaultdict
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, Raw
import requests

# Configuration
API_URL = os.getenv("NSMS_API_URL", "http://localhost:4000/api/mitigation/alert")
MONITOR_INTERFACE = os.getenv("NSMS_IFACE", None)  # None = all interfaces

# Detection Thresholds
SYN_FLOOD_THRESHOLD = 30       # SYN packets per second from single IP
PORT_SCAN_THRESHOLD = 10       # unique ports probed by single IP in 5 seconds
BRUTE_FORCE_THRESHOLD = 20     # requests per second to auth-like ports (80, 443, 8080)

# Tracking windows
syn_tracker = defaultdict(list)     # {src_ip: [timestamps]}
port_tracker = defaultdict(set)     # {src_ip: {ports}}
brute_tracker = defaultdict(list)   # {src_ip: [timestamps]}
alerted_ips = {}                    # {src_ip: last_alert_time} — cooldown

ALERT_COOLDOWN_SEC = 60  # Don't re-alert same IP within 60 seconds


def send_alert(source_ip, target_ip, severity, threat_type):
    """Send threat alert to NSMS SOAR engine."""
    # Cooldown check
    now = time.time()
    key = f"{source_ip}:{threat_type}"
    if key in alerted_ips and (now - alerted_ips[key]) < ALERT_COOLDOWN_SEC:
        return
    alerted_ips[key] = now

    payload = {
        "sourceIp": source_ip,
        "targetIp": target_ip,
        "severity": severity,
        "threatType": threat_type,
        "detectedAt": datetime.utcnow().isoformat() + "Z"
    }

    def _send():
        try:
            resp = requests.post(API_URL, json=payload, timeout=5)
            result = resp.json()
            status = result.get("status", "unknown")
            color = "\033[91m" if status == "blocked" else "\033[92m" if status == "allowed" else "\033[93m"
            print(f"  {color}[ALERT SENT] {threat_type} | {source_ip} → {target_ip} | Response: {status}\033[0m")
        except Exception as e:
            print(f"  \033[91m[ALERT FAILED] {e}\033[0m")

    threading.Thread(target=_send, daemon=True).start()


def cleanup_old_entries():
    """Remove stale tracking data older than 5 seconds."""
    now = time.time()
    cutoff = now - 5

    for ip in list(syn_tracker.keys()):
        syn_tracker[ip] = [t for t in syn_tracker[ip] if t > cutoff]
        if not syn_tracker[ip]:
            del syn_tracker[ip]

    for ip in list(brute_tracker.keys()):
        brute_tracker[ip] = [t for t in brute_tracker[ip] if t > cutoff]
        if not brute_tracker[ip]:
            del brute_tracker[ip]

    # Port tracker resets every 5 seconds
    for ip in list(port_tracker.keys()):
        if len(port_tracker[ip]) > PORT_SCAN_THRESHOLD:
            port_tracker[ip] = set()


def detect_syn_flood(pkt):
    """Detect SYN flood: many SYN-only packets from same source."""
    if TCP in pkt and pkt[TCP].flags == "S":
        src = pkt[IP].src
        dst = pkt[IP].dst
        now = time.time()
        syn_tracker[src].append(now)

        # Count SYNs in last 1 second
        recent = [t for t in syn_tracker[src] if t > now - 1]
        if len(recent) >= SYN_FLOOD_THRESHOLD:
            print(f"\n\033[91m{'='*60}")
            print(f"  🚨 SYN FLOOD DETECTED: {src} ({len(recent)} SYN/sec)")
            print(f"{'='*60}\033[0m")
            send_alert(src, dst, "high", "syn_flood")
            syn_tracker[src] = []  # Reset after alert


def detect_port_scan(pkt):
    """Detect port scanning: single IP probing many different ports."""
    if TCP in pkt:
        src = pkt[IP].src
        dst = pkt[IP].dst
        dst_port = pkt[TCP].dport
        port_tracker[src].add(dst_port)

        if len(port_tracker[src]) >= PORT_SCAN_THRESHOLD:
            print(f"\n\033[93m{'='*60}")
            print(f"  ⚠️  PORT SCAN DETECTED: {src} (probed {len(port_tracker[src])} ports)")
            print(f"  Ports: {sorted(list(port_tracker[src]))[:15]}...")
            print(f"{'='*60}\033[0m")
            send_alert(src, dst, "high", "port_scan")
            port_tracker[src] = set()  # Reset


def detect_brute_force(pkt):
    """Detect brute force: rapid connections to common service ports."""
    if TCP in pkt and pkt[TCP].dport in (22, 80, 443, 3306, 8080, 8443):
        src = pkt[IP].src
        dst = pkt[IP].dst
        now = time.time()
        brute_tracker[src].append(now)

        recent = [t for t in brute_tracker[src] if t > now - 1]
        if len(recent) >= BRUTE_FORCE_THRESHOLD:
            print(f"\n\033[91m{'='*60}")
            print(f"  🔓 BRUTE FORCE DETECTED: {src} ({len(recent)} req/sec to port {pkt[TCP].dport})")
            print(f"{'='*60}\033[0m")
            send_alert(src, dst, "high", "brute_force")
            brute_tracker[src] = []


def packet_handler(pkt):
    """Main packet processing callback."""
    if not IP in pkt:
        return

    detect_syn_flood(pkt)
    detect_port_scan(pkt)
    detect_brute_force(pkt)


def periodic_cleanup():
    """Background thread for cleaning old tracking data."""
    while True:
        time.sleep(5)
        cleanup_old_entries()


def main():
    print("\033[96m" + "=" * 60)
    print("  NSMS — Advanced Network Threat Detection Engine")
    print("  Multi-vector: SYN Flood | Port Scan | Brute Force")
    print(f"  API Target: {API_URL}")
    print(f"  SYN Threshold: {SYN_FLOOD_THRESHOLD}/sec")
    print(f"  Port Scan Threshold: {PORT_SCAN_THRESHOLD} unique ports")
    print(f"  Brute Force Threshold: {BRUTE_FORCE_THRESHOLD}/sec")
    print("=" * 60 + "\033[0m")
    print("[Sniffer] Starting packet capture (Ctrl+C to stop)...\n")

    # Start cleanup thread
    threading.Thread(target=periodic_cleanup, daemon=True).start()

    # Start sniffing
    sniff(
        iface=MONITOR_INTERFACE,
        prn=packet_handler,
        store=False,
        filter="ip"
    )


if __name__ == "__main__":
    main()
