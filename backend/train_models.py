"""
train_models.py — Sklearn-only version (no TensorFlow)
Models:
  1. Random Forest     (RF fingerprinting)
  2. Gradient Boosting (replaces CNN spectrogram)
  3. MLP Classifier    (replaces LSTM behavioral)
"""

import numpy as np
import pandas as pd
import joblib
import os
import json
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, classification_report, f1_score
from generate_dataset import load_or_generate

os.makedirs('models', exist_ok=True)

RF_FEATURES = [
    'packet_size', 'inter_arrival_time', 'flow_duration',
    'packets_per_sec', 'bytes_per_sec', 'tcp_flags',
    'syn_count', 'ack_count', 'dst_port', 'protocol',
    'signal_strength', 'snr', 'freq_drift', 'tx_power', 'channel_utilization'
]

LSTM_FEATURES = [
    'traffic_entropy', 'burst_count', 'idle_time',
    'retransmissions', 'payload_entropy',
    'packets_per_sec', 'bytes_per_sec', 'inter_arrival_time'
]

print("\n" + "="*60)
print("  IoT Sentinel — Model Training (sklearn)")
print("="*60)

df = load_or_generate()
y = df['label']
print(f"\n[Data] {len(df)} samples loaded\n")

# ── 1. RANDOM FOREST ──────────────────────────
print("[1/3] Training Random Forest...")

scaler_rf = StandardScaler()
X_rf = scaler_rf.fit_transform(df[RF_FEATURES].fillna(0))
X_tr, X_te, y_tr, y_te = train_test_split(
    X_rf, y, test_size=0.2, random_state=42, stratify=y
)

rf = RandomForestClassifier(
    n_estimators=150,
    max_depth=12,
    min_samples_leaf=5,
    max_features='sqrt',
    n_jobs=-1,
    random_state=42,
    class_weight='balanced'
)
rf.fit(X_tr, y_tr)
y_pred = rf.predict(X_te)
rf_acc = accuracy_score(y_te, y_pred)
rf_f1 = f1_score(y_te, y_pred, average='weighted')

print(f"\n  Accuracy : {rf_acc*100:.2f}%")
print(f"  F1 Score : {rf_f1:.4f}")
print(classification_report(y_te, y_pred, target_names=['Normal', 'Attack']))

joblib.dump(rf,         'models/rf_model.pkl')
joblib.dump(scaler_rf,  'models/scaler_rf.pkl')
joblib.dump(RF_FEATURES, 'models/rf_features.pkl')
print("  Saved → models/rf_model.pkl")

# ── 2. GRADIENT BOOSTING (CNN) ────────────────
print("\n[2/3] Training Gradient Boosting (CNN replacement)...")

scaler_cnn = StandardScaler()
X_cnn = scaler_cnn.fit_transform(df[RF_FEATURES].fillna(0))
X_tr2, X_te2, y_tr2, y_te2 = train_test_split(
    X_cnn, y, test_size=0.2, random_state=42, stratify=y
)

gb = GradientBoostingClassifier(
    n_estimators=120,
    max_depth=4,
    learning_rate=0.08,
    subsample=0.8,
    min_samples_leaf=10,
    random_state=42
)
gb.fit(X_tr2, y_tr2)
y_pred2 = gb.predict(X_te2)
cnn_acc = accuracy_score(y_te2, y_pred2)
cnn_f1 = f1_score(y_te2, y_pred2, average='weighted')

print(f"\n  Accuracy : {cnn_acc*100:.2f}%")
print(f"  F1 Score : {cnn_f1:.4f}")
print(classification_report(y_te2, y_pred2, target_names=['Normal', 'Attack']))

joblib.dump(gb,          'models/cnn_model.pkl')
joblib.dump(scaler_cnn,  'models/scaler_cnn.pkl')
joblib.dump(RF_FEATURES, 'models/cnn_features.pkl')
print("  Saved → models/cnn_model.pkl")

# ── 3. MLP BEHAVIORAL (LSTM) ──────────────────
print("\n[3/3] Training MLP Behavioral Classifier (LSTM replacement)...")

scaler_lstm = StandardScaler()
X_lstm = scaler_lstm.fit_transform(df[LSTM_FEATURES].fillna(0))
X_tr3, X_te3, y_tr3, y_te3 = train_test_split(
    X_lstm, y, test_size=0.2, random_state=42, stratify=y
)

mlp = MLPClassifier(
    hidden_layer_sizes=(128, 64, 32),
    activation='relu',
    solver='adam',
    alpha=0.01,
    learning_rate='adaptive',
    max_iter=200,
    early_stopping=True,
    validation_fraction=0.1,
    random_state=42,
    verbose=False
)
mlp.fit(X_tr3, y_tr3)
y_pred3 = mlp.predict(X_te3)
lstm_acc = accuracy_score(y_te3, y_pred3)
lstm_f1 = f1_score(y_te3, y_pred3, average='weighted')

print(f"\n  Accuracy : {lstm_acc*100:.2f}%")
print(f"  F1 Score : {lstm_f1:.4f}")
print(classification_report(y_te3, y_pred3, target_names=['Normal', 'Attack']))

joblib.dump(mlp,          'models/lstm_model.pkl')
joblib.dump(scaler_lstm,  'models/scaler_lstm.pkl')
joblib.dump(LSTM_FEATURES, 'models/lstm_features.pkl')
print("  Saved → models/lstm_model.pkl")

# ── SUMMARY ───────────────────────────────────
print("\n" + "="*60)
print("  TRAINING COMPLETE")
print("="*60)
print(f"  Random Forest  — Accuracy: {rf_acc*100:.2f}%  F1: {rf_f1:.4f}")
print(f"  CNN / GB       — Accuracy: {cnn_acc*100:.2f}%  F1: {cnn_f1:.4f}")
print(f"  LSTM / MLP     — Accuracy: {lstm_acc*100:.2f}%  F1: {lstm_f1:.4f}")
print(f"  Models saved in: backend/models/")
print("="*60)
print("\n  Next: python api.py\n")

meta = {
    'rf_accuracy':    round(rf_acc * 100, 2),
    'cnn_accuracy':   round(cnn_acc * 100, 2),
    'lstm_accuracy':  round(lstm_acc * 100, 2),
    'rf_f1':          round(rf_f1, 4),
    'cnn_f1':         round(cnn_f1, 4),
    'lstm_f1':        round(lstm_f1, 4),
    'threshold':      70,
    'rf_features':    RF_FEATURES,
    'lstm_features':  LSTM_FEATURES,
    'backend':        'sklearn'
}
with open('models/meta.json', 'w') as f:
    json.dump(meta, f, indent=2)
print("[Meta] Saved → models/meta.json")
