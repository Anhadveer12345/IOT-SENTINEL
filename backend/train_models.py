import numpy as np
import pandas as pd
import joblib
import os
import json
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, classification_report
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

print("Loading dataset...")
df = load_or_generate()
y = df['label']

print("\n[1/3] Training Random Forest...")
scaler_rf = StandardScaler()
X_rf = scaler_rf.fit_transform(df[RF_FEATURES].fillna(0))
X_tr, X_te, y_tr, y_te = train_test_split(
    X_rf, y, test_size=0.2, random_state=42)
rf = RandomForestClassifier(n_estimators=100, n_jobs=-1, random_state=42)
rf.fit(X_tr, y_tr)
rf_acc = accuracy_score(y_te, rf.predict(X_te))
print(f"RF Accuracy: {rf_acc*100:.1f}%")
joblib.dump(rf, 'models/rf_model.pkl')
joblib.dump(scaler_rf, 'models/scaler_rf.pkl')
joblib.dump(RF_FEATURES, 'models/rf_features.pkl')

print("\n[2/3] Training Gradient Boosting (CNN)...")
scaler_cnn = StandardScaler()
X_cnn = scaler_cnn.fit_transform(df[RF_FEATURES].fillna(0))
X_tr2, X_te2, y_tr2, y_te2 = train_test_split(
    X_cnn, y, test_size=0.2, random_state=42)
gb = GradientBoostingClassifier(n_estimators=100, random_state=42)
gb.fit(X_tr2, y_tr2)
cnn_acc = accuracy_score(y_te2, gb.predict(X_te2))
print(f"GB Accuracy: {cnn_acc*100:.1f}%")
joblib.dump(gb, 'models/cnn_model.pkl')
joblib.dump(scaler_cnn, 'models/scaler_cnn.pkl')
joblib.dump(RF_FEATURES, 'models/cnn_features.pkl')

print("\n[3/3] Training MLP (LSTM)...")
scaler_lstm = StandardScaler()
X_lstm = scaler_lstm.fit_transform(df[LSTM_FEATURES].fillna(0))
X_tr3, X_te3, y_tr3, y_te3 = train_test_split(
    X_lstm, y, test_size=0.2, random_state=42)
mlp = MLPClassifier(hidden_layer_sizes=(64, 32), max_iter=100, random_state=42)
mlp.fit(X_tr3, y_tr3)
lstm_acc = accuracy_score(y_te3, mlp.predict(X_te3))
print(f"MLP Accuracy: {lstm_acc*100:.1f}%")
joblib.dump(mlp, 'models/lstm_model.pkl')
joblib.dump(scaler_lstm, 'models/scaler_lstm.pkl')
joblib.dump(LSTM_FEATURES, 'models/lstm_features.pkl')

meta = {
    'rf_accuracy': round(rf_acc*100, 2),
    'cnn_accuracy': round(cnn_acc*100, 2),
    'lstm_accuracy': round(lstm_acc*100, 2),
    'threshold': 70,
    'rf_features': RF_FEATURES,
    'lstm_features': LSTM_FEATURES
}
with open('models/meta.json', 'w') as f:
    json.dump(meta, f, indent=2)

print("\n" + "="*40)
print(f"  RF  : {rf_acc*100:.1f}%")
print(f"  CNN : {cnn_acc*100:.1f}%")
print(f"  LSTM: {lstm_acc*100:.1f}%")
print("  Models saved to backend/models/")
print("="*40)
print("\n  Next: python api.py")
