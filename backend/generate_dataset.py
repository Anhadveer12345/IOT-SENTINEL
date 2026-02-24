"""
generate_dataset.py
Generates a synthetic dataset matching EdgeIIoT-Set structure.
If you have the real Kaggle dataset, place 'DNN-EdgeIIoT-dataset.csv' 
in the backend/ folder and set USE_REAL_DATASET = True below.
"""

import numpy as np
import pandas as pd
from pathlib import Path

USE_REAL_DATASET = False  # Set True if you have the Kaggle CSV
REAL_DATASET_PATH = "DNN-EdgeIIoT-dataset.csv"

ATTACK_TYPES = [
    'Normal', 'Normal', 'Normal', 'Normal', 'Normal',  # 5x normal weight
    'DoS', 'MITM', 'Spoofing', 'Replay_Attack',
    'Eavesdropping', 'Port_Scan', 'ARP_Spoofing', 'Ransomware', 'XSS'
]

DEVICE_TYPES = [
    'Temperature_Sensor', 'Humidity_Sensor', 'Pressure_Sensor',
    'Motion_Detector', 'GPS_Tracker', 'Smart_Meter',
    'Industrial_PLC', 'Network_Gateway', 'Camera_Module',
    'Vibration_Sensor', 'Gas_Detector', 'Light_Sensor'
]

def generate_synthetic_dataset(n_samples=5000, seed=42):
    np.random.seed(seed)
    print(f"[DataGen] Generating {n_samples} synthetic EdgeIIoT samples...")

    labels = np.random.choice(ATTACK_TYPES, size=n_samples)
    is_attack = labels != 'Normal'

    def noise(size, scale=1.0):
        return np.random.randn(size) * scale

    # Network traffic features
    packet_size     = np.where(is_attack, np.abs(noise(n_samples, 400) + 900), np.abs(noise(n_samples, 100) + 200))
    inter_arrival   = np.where(is_attack, np.abs(noise(n_samples, 0.5) + 0.1), np.abs(noise(n_samples, 0.2) + 0.8))
    flow_duration   = np.where(is_attack, np.abs(noise(n_samples, 5) + 2), np.abs(noise(n_samples, 10) + 30))
    pkt_per_sec     = np.where(is_attack, np.abs(noise(n_samples, 500) + 1000), np.abs(noise(n_samples, 20) + 10))
    bytes_per_sec   = np.where(is_attack, np.abs(noise(n_samples, 50000) + 100000), np.abs(noise(n_samples, 2000) + 3000))
    tcp_flags       = np.where(is_attack, np.random.randint(0, 255, n_samples), np.random.randint(16, 32, n_samples)).astype(float)
    syn_count       = np.where(is_attack, np.abs(noise(n_samples, 50) + 100), np.abs(noise(n_samples, 2) + 1))
    ack_count       = np.where(is_attack, np.abs(noise(n_samples, 30) + 20), np.abs(noise(n_samples, 5) + 40))
    port_dst        = np.where(is_attack, np.random.randint(0, 1024, n_samples), np.random.randint(1024, 65535, n_samples)).astype(float)
    protocol        = np.random.randint(0, 5, n_samples).astype(float)

    # RF / Physical layer features
    signal_strength = np.where(is_attack, noise(n_samples, 15) - 85, noise(n_samples, 5) - 60)
    snr             = np.where(is_attack, np.abs(noise(n_samples, 10) + 5), np.abs(noise(n_samples, 5) + 25))
    freq_drift      = np.where(is_attack, np.abs(noise(n_samples, 50) + 100), np.abs(noise(n_samples, 5) + 2))
    tx_power        = np.where(is_attack, noise(n_samples, 5) + 10, noise(n_samples, 2) + 20)
    channel_util    = np.where(is_attack, np.abs(noise(n_samples, 20) + 80), np.abs(noise(n_samples, 10) + 30))

    # LSTM / Temporal features (behavioral)
    traffic_entropy = np.where(is_attack, np.abs(noise(n_samples, 0.5) + 3.5), np.abs(noise(n_samples, 0.3) + 1.5))
    burst_count     = np.where(is_attack, np.abs(noise(n_samples, 10) + 20), np.abs(noise(n_samples, 1) + 1))
    idle_time       = np.where(is_attack, np.abs(noise(n_samples, 0.1) + 0.05), np.abs(noise(n_samples, 0.5) + 2))
    retransmissions = np.where(is_attack, np.abs(noise(n_samples, 5) + 10), np.abs(noise(n_samples, 0.5) + 0.2))
    payload_entropy = np.where(is_attack, np.abs(noise(n_samples, 0.5) + 6.5), np.abs(noise(n_samples, 0.5) + 3.0))

    df = pd.DataFrame({
        'packet_size': packet_size,
        'inter_arrival_time': inter_arrival,
        'flow_duration': flow_duration,
        'packets_per_sec': pkt_per_sec,
        'bytes_per_sec': bytes_per_sec,
        'tcp_flags': tcp_flags,
        'syn_count': syn_count,
        'ack_count': ack_count,
        'dst_port': port_dst,
        'protocol': protocol,
        'signal_strength': signal_strength,
        'snr': snr,
        'freq_drift': freq_drift,
        'tx_power': tx_power,
        'channel_utilization': channel_util,
        'traffic_entropy': traffic_entropy,
        'burst_count': burst_count,
        'idle_time': idle_time,
        'retransmissions': retransmissions,
        'payload_entropy': payload_entropy,
        'attack_type': labels,
        'label': is_attack.astype(int)  # 0=Normal, 1=Attack
    })

    print(f"[DataGen] Dataset shape: {df.shape}")
    print(f"[DataGen] Class distribution:\n{df['attack_type'].value_counts()}")
    return df


def load_or_generate():
    if USE_REAL_DATASET and Path(REAL_DATASET_PATH).exists():
        print(f"[DataGen] Loading real dataset from {REAL_DATASET_PATH}")
        df = pd.read_csv(REAL_DATASET_PATH)
        # Normalize column names for real dataset
        df['label'] = (df['Attack_label'] if 'Attack_label' in df.columns else df['label']).astype(int)
        return df
    else:
        return generate_synthetic_dataset()


if __name__ == '__main__':
    df = load_or_generate()
    df.to_csv('dataset.csv', index=False)
    print("[DataGen] Saved to dataset.csv")
