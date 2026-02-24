"""
database.py — SQLite storage with user accounts
"""
import sqlite3
import hashlib
import secrets
from pathlib import Path

DB_PATH = 'sentinel.db'


def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_conn()
    conn.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            email       TEXT UNIQUE NOT NULL,
            name        TEXT NOT NULL,
            password    TEXT NOT NULL,
            api_key     TEXT UNIQUE NOT NULL,
            created     TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS devices (
            device_id   TEXT NOT NULL,
            user_id     INTEGER NOT NULL,
            device_type TEXT,
            ip          TEXT,
            protocol    TEXT,
            mac         TEXT,
            registered  TEXT DEFAULT (datetime('now')),
            last_seen   TEXT,
            PRIMARY KEY (device_id, user_id),
            FOREIGN KEY (user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS auth_log (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id   TEXT,
            user_id     INTEGER,
            rf_score    REAL,
            cnn_score   REAL,
            lstm_score  REAL,
            mean_score  REAL,
            trusted     INTEGER,
            timestamp   TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS alerts (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id   TEXT,
            user_id     INTEGER,
            mean_score  REAL,
            timestamp   TEXT DEFAULT (datetime('now')),
            dismissed   INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS sessions (
            token       TEXT PRIMARY KEY,
            user_id     INTEGER NOT NULL,
            created     TEXT DEFAULT (datetime('now')),
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
    ''')
    conn.commit()
    conn.close()
    print("[DB] Database initialized → sentinel.db")


def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


def create_user(email, name, password):
    conn = get_conn()
    try:
        api_key = secrets.token_hex(24)
        conn.execute(
            'INSERT INTO users (email, name, password, api_key) VALUES (?,?,?,?)',
            (email.lower().strip(), name.strip(), hash_password(password), api_key)
        )
        conn.commit()
        user = conn.execute('SELECT * FROM users WHERE email=?',
                            (email.lower().strip(),)).fetchone()
        return dict(user), None
    except sqlite3.IntegrityError:
        return None, 'Email already registered'
    finally:
        conn.close()


def login_user(email, password):
    conn = get_conn()
    user = conn.execute(
        'SELECT * FROM users WHERE email=? AND password=?',
        (email.lower().strip(), hash_password(password))
    ).fetchone()
    conn.close()
    if user:
        return dict(user), None
    return None, 'Invalid email or password'


def create_session(user_id):
    token = secrets.token_hex(32)
    conn = get_conn()
    conn.execute(
        'INSERT INTO sessions (token, user_id) VALUES (?,?)', (token, user_id))
    conn.commit()
    conn.close()
    return token


def get_user_by_token(token):
    if not token:
        return None
    conn = get_conn()
    row = conn.execute(
        'SELECT u.* FROM users u JOIN sessions s ON s.user_id=u.id WHERE s.token=?',
        (token,)
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def get_user_by_api_key(api_key):
    if not api_key:
        return None
    conn = get_conn()
    row = conn.execute('SELECT * FROM users WHERE api_key=?',
                       (api_key,)).fetchone()
    conn.close()
    return dict(row) if row else None


def delete_session(token):
    conn = get_conn()
    conn.execute('DELETE FROM sessions WHERE token=?', (token,))
    conn.commit()
    conn.close()


def register_device(device_id, user_id, device_type, ip='', protocol='', mac=''):
    conn = get_conn()
    conn.execute('''
        INSERT INTO devices (device_id, user_id, device_type, ip, protocol, mac, last_seen)
        VALUES (?,?,?,?,?,?,datetime('now'))
        ON CONFLICT(device_id, user_id) DO UPDATE SET
            last_seen=datetime('now'), ip=excluded.ip
    ''', (device_id, user_id, device_type, ip, protocol, mac))
    conn.commit()
    conn.close()


def save_auth_result(result, user_id):
    conn = get_conn()
    conn.execute('''
        INSERT INTO auth_log (device_id, user_id, rf_score, cnn_score, lstm_score, mean_score, trusted)
        VALUES (?,?,?,?,?,?,?)
    ''', (result['device_id'], user_id, result['rf_score'], result['cnn_score'],
          result['lstm_score'], result['mean_score'], 1 if result['trusted'] else 0))
    if not result['trusted']:
        conn.execute(
            'INSERT INTO alerts (device_id, user_id, mean_score) VALUES (?,?,?)',
            (result['device_id'], user_id, result['mean_score'])
        )
    conn.commit()
    conn.close()


def get_all_devices(user_id):
    conn = get_conn()
    rows = conn.execute('''
        SELECT d.*,
               a.mean_score, a.trusted, a.timestamp as last_auth,
               a.rf_score, a.cnn_score, a.lstm_score
        FROM devices d
        LEFT JOIN auth_log a ON a.device_id=d.device_id AND a.user_id=d.user_id
            AND a.id=(SELECT MAX(id) FROM auth_log WHERE device_id=d.device_id AND user_id=d.user_id)
        WHERE d.user_id=?
        ORDER BY d.registered DESC
    ''', (user_id,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_alerts(user_id, limit=50):
    conn = get_conn()
    rows = conn.execute('''
        SELECT a.*, d.device_type, d.ip
        FROM alerts a
        LEFT JOIN devices d ON d.device_id=a.device_id AND d.user_id=a.user_id
        WHERE a.user_id=? AND a.dismissed=0
        ORDER BY a.id DESC LIMIT ?
    ''', (user_id, limit)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def dismiss_alert(alert_id, user_id):
    conn = get_conn()
    conn.execute(
        'UPDATE alerts SET dismissed=1 WHERE id=? AND user_id=?', (alert_id, user_id))
    conn.commit()
    conn.close()


def get_stats(user_id):
    conn = get_conn()
    total = conn.execute(
        'SELECT COUNT(*) FROM devices WHERE user_id=?', (user_id,)).fetchone()[0]
    trusted = conn.execute(
        'SELECT COUNT(DISTINCT device_id) FROM auth_log WHERE user_id=? AND trusted=1', (user_id,)).fetchone()[0]
    flagged = conn.execute(
        'SELECT COUNT(*) FROM alerts WHERE user_id=? AND dismissed=0', (user_id,)).fetchone()[0]
    conn.close()
    return {'total_devices': total, 'trusted': trusted, 'flagged': flagged}


def get_auth_history(user_id, limit=100):
    conn = get_conn()
    rows = conn.execute(
        'SELECT * FROM auth_log WHERE user_id=? ORDER BY id DESC LIMIT ?',
        (user_id, limit)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]
