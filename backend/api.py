"""
api.py — IoT Sentinel Flask Backend with User Auth
Run: python api.py
"""

import os
import json
import time
import numpy as np
import joblib
from pathlib import Path
from flask import Flask, request, jsonify
from flask_cors import CORS
from database import (
    init_db, create_user, login_user, create_session,
    get_user_by_token, get_user_by_api_key, delete_session,
    register_device, save_auth_result, get_all_devices,
    get_alerts, dismiss_alert, get_stats, get_auth_history
)

app = Flask(__name__)
CORS(app)

MODELS_DIR = Path('models')
models_loaded = False
rf_model = cnn_model = lstm_model = None
scaler_rf = scaler_cnn = scaler_lstm = None
rf_features = cnn_features = lstm_features = None
meta = {}

# ── Load Models ───────────────────────────────


def load_models():
    global rf_model, cnn_model, lstm_model
    global scaler_rf, scaler_cnn, scaler_lstm
    global rf_features, cnn_features, lstm_features
    global meta, models_loaded
    if not MODELS_DIR.exists():
        print("[API] ERROR: models/ not found. Run train_models.py first!")
        return False
    try:
        print("[API] Loading models...")
        rf_model = joblib.load(MODELS_DIR / 'rf_model.pkl')
        scaler_rf = joblib.load(MODELS_DIR / 'scaler_rf.pkl')
        rf_features = joblib.load(MODELS_DIR / 'rf_features.pkl')
        cnn_model = joblib.load(MODELS_DIR / 'cnn_model.pkl')
        scaler_cnn = joblib.load(MODELS_DIR / 'scaler_cnn.pkl')
        cnn_features = joblib.load(MODELS_DIR / 'cnn_features.pkl')
        lstm_model = joblib.load(MODELS_DIR / 'lstm_model.pkl')
        scaler_lstm = joblib.load(MODELS_DIR / 'scaler_lstm.pkl')
        lstm_features = joblib.load(MODELS_DIR / 'lstm_features.pkl')
        with open(MODELS_DIR / 'meta.json') as f:
            meta = json.load(f)
        models_loaded = True
        print("[API] All models loaded.")
        return True
    except Exception as e:
        print(f"[API] Failed: {e}")
        return False

# ── Auth Helpers ──────────────────────────────


def get_current_user():
    """Get user from Bearer token in Authorization header."""
    auth = request.headers.get('Authorization', '')
    if auth.startswith('Bearer '):
        token = auth[7:]
        return get_user_by_token(token)
    return None


def require_auth():
    user = get_current_user()
    if not user:
        return None, jsonify({'error': 'Unauthorized. Please login.'}), 401
    return user, None, None

# ── ML Helpers ────────────────────────────────


def run_rf(features_dict):
    row = np.array([features_dict.get(f, 0.0)
                   for f in rf_features]).reshape(1, -1)
    prob = rf_model.predict_proba(scaler_rf.transform(row))[0]
    return round(float(prob[0]) * 100, 2)


def run_cnn(features_dict):
    row = np.array([features_dict.get(f, 0.0)
                   for f in cnn_features]).reshape(1, -1)
    prob = cnn_model.predict_proba(scaler_cnn.transform(row))[0]
    return round(float(prob[0]) * 100, 2)


def run_lstm(time_series):
    last = time_series[-1] if time_series else {}
    row = np.array([last.get(f, 0.0) for f in lstm_features]).reshape(1, -1)
    row_s = scaler_lstm.transform(row)
    prob = lstm_model.predict_proba(row_s)[0]
    score = round(float(prob[0]) * 100, 2)
    return {
        'lstm_score':          score,
        'behavioral_entropy':  round(float(np.std(row_s)), 4),
        'anomaly_probability': round(float(1 - score / 100), 4)
    }

# ── Auth Routes ───────────────────────────────


@app.route('/auth/signup', methods=['POST'])
def signup():
    data = request.get_json()
    email = data.get('email', '').strip()
    name = data.get('name', '').strip()
    password = data.get('password', '')
    if not email or not name or not password:
        return jsonify({'error': 'Email, name and password required'}), 400
    if len(password) < 6:
        return jsonify({'error': 'Password must be at least 6 characters'}), 400
    user, error = create_user(email, name, password)
    if error:
        return jsonify({'error': error}), 400
    token = create_session(user['id'])
    return jsonify({
        'token':   token,
        'user':    {'id': user['id'], 'email': user['email'], 'name': user['name']},
        'api_key': user['api_key']
    })


@app.route('/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email', '')
    password = data.get('password', '')
    user, error = login_user(email, password)
    if error:
        return jsonify({'error': error}), 401
    token = create_session(user['id'])
    return jsonify({
        'token':   token,
        'user':    {'id': user['id'], 'email': user['email'], 'name': user['name']},
        'api_key': user['api_key']
    })


@app.route('/auth/logout', methods=['POST'])
def logout():
    auth = request.headers.get('Authorization', '')
    if auth.startswith('Bearer '):
        delete_session(auth[7:])
    return jsonify({'status': 'logged out'})


@app.route('/auth/me', methods=['GET'])
def me():
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401
    return jsonify({'user': {'id': user['id'], 'email': user['email'],
                             'name': user['name'], 'api_key': user['api_key']}})

# ── Core Routes ───────────────────────────────


@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'ok', 'models_loaded': models_loaded,
                    'threshold': 70, 'meta': meta})


@app.route('/authenticate', methods=['POST'])
def authenticate():
    if not models_loaded:
        return jsonify({'error': 'Models not loaded'}), 503

    data = request.get_json()
    if not data:
        return jsonify({'error': 'No JSON body'}), 400

    # Support both token auth and api_key auth (for agents)
    user = get_current_user()
    if not user:
        api_key = data.get('api_key') or request.headers.get('X-API-Key')
        user = get_user_by_api_key(api_key)
    if not user:
        return jsonify({'error': 'Unauthorized. Provide token or api_key'}), 401

    device_id = data.get('device_id', 'UNKNOWN')
    device_type = data.get('device_type', 'Unknown')
    features = data.get('features', {})
    time_series = data.get('time_series', [features])

    start = time.time()
    rf_score = run_rf(features)
    cnn_score = run_cnn(features)
    lstm_res = run_lstm(time_series)
    mean_score = round((rf_score + cnn_score) / 2, 2)
    trusted = bool(mean_score >= 70)

    result = {
        'device_id':   device_id,
        'device_type': device_type,
        'rf_score':    rf_score,
        'cnn_score':   cnn_score,
        'lstm_score':  lstm_res['lstm_score'],
        'mean_score':  mean_score,
        'trusted':     trusted,
        'threshold':   70,
        'behavioral': {
            'entropy':             lstm_res['behavioral_entropy'],
            'anomaly_probability': lstm_res['anomaly_probability'],
            'traffic_pattern':     'Normal' if trusted else 'Anomalous',
            'behavioral_drift':    f"{round(lstm_res['anomaly_probability']*100,1)}%"
        },
        'latency_ms': round((time.time() - start) * 1000, 2),
        'timestamp':  time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
    }

    register_device(device_id, user['id'], device_type,
                    data.get('ip', ''), data.get('protocol', ''), data.get('mac', ''))
    save_auth_result(result, user['id'])
    return jsonify(result)


@app.route('/devices', methods=['GET'])
def devices():
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401
    return jsonify({'devices': get_all_devices(user['id'])})


@app.route('/devices/register', methods=['POST'])
def register_dev():
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401
    d = request.get_json()
    register_device(d.get('device_id'), user['id'],
                    d.get('device_type', 'Unknown'),
                    d.get('ip', ''), d.get('protocol', ''), d.get('mac', ''))
    return jsonify({'status': 'registered'})


@app.route('/alerts', methods=['GET'])
def get_alert_list():
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401
    return jsonify({'alerts': get_alerts(user['id'])})


@app.route('/alerts/<int:alert_id>/dismiss', methods=['POST'])
def dismiss(alert_id):
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401
    dismiss_alert(alert_id, user['id'])
    return jsonify({'status': 'dismissed'})


@app.route('/stats', methods=['GET'])
def stats():
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401
    return jsonify(get_stats(user['id']))


@app.route('/history', methods=['GET'])
def history():
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401
    limit = request.args.get('limit', 100, type=int)
    return jsonify({'history': get_auth_history(user['id'], limit)})


@app.route('/model_info', methods=['GET'])
def model_info():
    return jsonify(meta)


# ── Main ──────────────────────────────────────
if __name__ == '__main__':
    print("\n" + "="*60)
    print("  IoT Sentinel — Backend API")
    print("="*60)
    init_db()
    load_models()
    print("\n[API] Starting on http://localhost:8080")
    print("[API] Press Ctrl+C to stop\n")
    app.run(host='0.0.0.0', port=8080, debug=False)
