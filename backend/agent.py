"""
agent.py — Run this on each real IoT device/sensor
It collects network stats and sends to IoT Sentinel backend.

Usage:
    pip install psutil requests
    python agent.py --id DEV-0001 --type "Temperature Sensor" --server http://YOUR_SERVER_IP:5000
"""

import argparse
import time
import socket
import requests
import random

# ── Try to import psutil for real stats ──────
try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False
    print("[Agent] psutil not found — using simulated stats. Install with: pip install psutil")

# ── Config ────────────────────────────────────
parser = argparse.ArgumentParser(description='IoT Sentinel Device Agent')
parser.add_argument('--id',       default='DEV-0001',
                    help='Unique device ID')
parser.add_argument(
    '--type',     default='Temperature Sensor',  help='Device type')
parser.add_argument(
    '--server',   default='http://localhost:5000', help='Backend URL')
parser.add_argument('--interval', default=10, type=int,
                    help='Send interval in seconds')
parser.add_argument('--protocol', default='MQTT',
                    help='Device protocol')
args = parser.parse_args()

DEVICE_ID = args.id
DEVICE_TYPE = args.type
SERVER_URL = args.server
INTERVAL = args.interval
PROTOCOL = args.protocol

print(f"""
╔══════════════════════════════════════╗
  IoT Sentinel — Device Agent
  Device ID   : {DEVICE_ID}
  Device Type : {DEVICE_TYPE}
  Server      : {SERVER_URL}
  Interval    : every {INTERVAL}s
╚══════════════════════════════════════╝
""")

# Keep last 10 readings for time series
history = []


def get_ip():
    try:
        return socket.gethostbyname(socket.gethostname())
    except:
        return '0.0.0.0'


def collect_features():
    """Collect real network stats if psutil available, else simulate."""
    if HAS_PSUTIL:
        net = psutil.net_io_counters()
        cpu = psutil.cpu_percent()
        mem = psutil.virtual_memory().percent

        # Derive features from real system stats
        features = {
            'packet_size':          net.bytes_sent / max(net.packets_sent, 1),
            'inter_arrival_time':   1.0 / max(net.packets_sent / 60, 1),
            'flow_duration':        30.0,
            'packets_per_sec':      net.packets_sent / 60,
            'bytes_per_sec':        net.bytes_sent / 60,
            'tcp_flags':            24,
            'syn_count':            max(0, net.errin),
            'ack_count':            max(0, net.packets_recv % 60),
            'dst_port':             1883,
            'protocol':             1,
            'signal_strength': -65 + random.gauss(0, 3),
            'snr':                  25 + random.gauss(0, 2),
            'freq_drift':           2 + random.gauss(0, 0.5),
            'tx_power':             20 + random.gauss(0, 1),
            'channel_utilization':  cpu,
            'traffic_entropy':      1.5 + random.gauss(0, 0.2),
            'burst_count':          max(0, net.dropin),
            'idle_time':            max(0.1, 2 - cpu / 50),
            'retransmissions':      max(0, net.errout),
            'payload_entropy':      3.0 + random.gauss(0, 0.3)
        }
    else:
        # Pure simulation for devices without psutil
        features = {
            'packet_size':          random.gauss(200, 50),
            'inter_arrival_time':   random.gauss(0.8, 0.1),
            'flow_duration':        random.gauss(30, 5),
            'packets_per_sec':      random.gauss(15, 3),
            'bytes_per_sec':        random.gauss(3000, 500),
            'tcp_flags':            random.randint(16, 32),
            'syn_count':            max(0, random.gauss(1, 0.5)),
            'ack_count':            max(0, random.gauss(40, 5)),
            'dst_port':             1883,
            'protocol':             1,
            'signal_strength':      random.gauss(-65, 3),
            'snr':                  random.gauss(25, 2),
            'freq_drift':           abs(random.gauss(2, 0.5)),
            'tx_power':             random.gauss(20, 1),
            'channel_utilization':  random.gauss(30, 5),
            'traffic_entropy':      random.gauss(1.5, 0.2),
            'burst_count':          max(0, random.gauss(1, 0.3)),
            'idle_time':            abs(random.gauss(2, 0.3)),
            'retransmissions':      max(0, random.gauss(0.2, 0.1)),
            'payload_entropy':      random.gauss(3.0, 0.3)
        }

    return features


def send_to_backend(features):
    history.append(features)
    if len(history) > 10:
        history.pop(0)

    payload = {
        'device_id':   DEVICE_ID,
        'device_type': DEVICE_TYPE,
        'ip':          get_ip(),
        'protocol':    PROTOCOL,
        'features':    features,
        'time_series': history
    }

    try:
        res = requests.post(
            f"{SERVER_URL}/authenticate",
            json=payload,
            timeout=10,
            headers={'Content-Type': 'application/json'}
        )
        print(f"[Debug] Status: {res.status_code}")
        print(f"[Debug] Response: {res.text[:200]}")
        result = res.json()
        status = "✓ TRUSTED" if result['trusted'] else "⚑ FLAGGED"
        print(
            f"[{time.strftime('%H:%M:%S')}] {DEVICE_ID} → Mean: {result['mean_score']:.1f}% → {status}")
        return result
    except Exception as e:
        print(f"[{time.strftime('%H:%M:%S')}] ERROR: {e}")
        return None


# ── Main Loop ─────────────────────────────────
print(f"[Agent] Starting — sending to {SERVER_URL} every {INTERVAL}s\n")

while True:
    features = collect_features()
    send_to_backend(features)
    time.sleep(INTERVAL)
