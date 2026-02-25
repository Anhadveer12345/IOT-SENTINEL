// data.js — Auth helpers, API URL, device pool

const API_URL = 'https://backend-iot-sentinel-1.onrender.com';

// Wake up Render backend on page load
fetch(`${API_URL}/health`).catch(() => { });

// ── Auth Helpers ──────────────────────────────
function getToken() { return localStorage.getItem('iot_token'); }
function getApiKey() { return localStorage.getItem('iot_api_key'); }
function getUser() {
  try { return JSON.parse(localStorage.getItem('iot_user')); }
  catch { return null; }
}
function authHeaders() {
  return {
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${getToken()}`
  };
}

// ── Device Types ──────────────────────────────
const DEVICE_TYPES = [
  'Temperature Sensor', 'Humidity Sensor', 'Pressure Sensor',
  'Motion Detector', 'GPS Tracker', 'Smart Meter',
  'Industrial PLC', 'Network Gateway', 'Camera Module',
  'Vibration Sensor', 'Gas Detector', 'Light Sensor',
  'RFID Reader', 'Accelerometer', 'Barometer'
];

const PROTOCOLS = ['MQTT', 'CoAP', 'HTTP', 'TCP', 'UDP'];

const ATTACK_TYPES = [
  'Normal', 'Normal', 'Normal', 'Normal', 'Normal', 'Normal',
  'DoS', 'MITM', 'Spoofing', 'Replay_Attack', 'Eavesdropping'
];

function generateDevicePool(count = 24) {
  return Array.from({ length: count }, (_, i) => ({
    id: `DEV-${String(i + 1).padStart(2, '0')}`,
    type: DEVICE_TYPES[i % DEVICE_TYPES.length],
    protocol: PROTOCOLS[i % PROTOCOLS.length],
    ip: `192.168.${Math.floor(i / 10)}.${(i % 254) + 1}`,
    mac: Array.from({ length: 6 }, () => Math.floor(Math.random() * 256).toString(16).padStart(2, '0')).join(':'),
    attackType: ATTACK_TYPES[Math.floor(Math.random() * ATTACK_TYPES.length)],
    features: generateFeatures(ATTACK_TYPES[Math.floor(Math.random() * ATTACK_TYPES.length)]),
    timeSeries: generateTimeSeries(ATTACK_TYPES[Math.floor(Math.random() * ATTACK_TYPES.length)]),
    rfScore: null, cnnScore: null, lstmScore: null, meanScore: null,
    status: 'idle', lastAuth: null, behavioral: null
  }));
}

function generateFeatures(attackType) {
  const isAttack = attackType !== 'Normal';
  const g = (m, s) => Math.max(0, m + (Math.random() - 0.5) * 2 * s);
  return {
    packet_size: isAttack ? g(900, 400) : g(200, 100),
    inter_arrival_time: isAttack ? g(0.1, 0.5) : g(0.8, 0.2),
    flow_duration: isAttack ? g(2, 5) : g(30, 10),
    packets_per_sec: isAttack ? g(1000, 500) : g(10, 20),
    bytes_per_sec: isAttack ? g(100000, 50000) : g(3000, 2000),
    tcp_flags: isAttack ? Math.random() * 255 : 24,
    syn_count: isAttack ? g(100, 50) : g(1, 2),
    ack_count: isAttack ? g(20, 30) : g(40, 5),
    dst_port: isAttack ? Math.floor(Math.random() * 1024) : 1883,
    protocol: Math.floor(Math.random() * 5),
    signal_strength: isAttack ? g(-85, 15) : g(-60, 5),
    snr: isAttack ? g(5, 10) : g(25, 5),
    freq_drift: isAttack ? g(100, 50) : g(2, 5),
    tx_power: isAttack ? g(10, 5) : g(20, 2),
    channel_utilization: isAttack ? g(80, 20) : g(30, 10),
    traffic_entropy: isAttack ? g(3.5, 0.5) : g(1.5, 0.3),
    burst_count: isAttack ? g(20, 10) : g(1, 1),
    idle_time: isAttack ? g(0.05, 0.1) : g(2, 0.5),
    retransmissions: isAttack ? g(10, 5) : g(0.2, 0.5),
    payload_entropy: isAttack ? g(6.5, 0.5) : g(3.0, 0.5)
  };
}

function generateTimeSeries(attackType, length = 10) {
  return Array.from({ length }, () => generateFeatures(attackType));
}

function generateLSTMSeries(device) {
  const isAttack = device.attackType !== 'Normal';
  const base = device.meanScore ?? (isAttack ? 45 : 80);
  return Array.from({ length: 30 }, (_, i) => {
    const trend = isAttack ? -0.3 : 0.1;
    return Math.min(99, Math.max(1, base + trend * i + (Math.random() - 0.5) * 12));
  });
}