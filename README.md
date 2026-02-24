# IoT Sentinel — ML-Based Device Authentication

**Machine Learning-Based Behavioral Authentication for Secure Access Control in Massive IoT Wireless Networks**

Dataset: [EdgeIIoT-Set on Kaggle](https://www.kaggle.com/datasets/mohamedamineferrag/edgeiiotset-cyber-security-dataset-of-iot-iiot)

---

## Authentication Pipeline

```
IoT Device
    ↓
[Random Forest]  → RF Score
    ↓
[CNN Spectrogram] → CNN Score  
    ↓
Mean Score = (RF + CNN) / 2
    ↓
[LSTM Behavioral Profiler]
    ↓
Mean ≥ 70% → ✓ TRUSTED
Mean < 70% → ⚑ FLAG (alert raised)
```

---

## Project Structure

```
iot-sentinel-full/
├── backend/
│   ├── requirements.txt       ← Python dependencies
│   ├── generate_dataset.py    ← Dataset generator
│   ├── train_models.py        ← Train RF + CNN + LSTM
│   ├── api.py                 ← Flask REST API
│   └── models/                ← Saved models (after training)
│       ├── rf_model.pkl
│       ├── cnn_model.keras
│       ├── lstm_model.keras
│       └── meta.json
└── frontend/
    ├── index.html
    ├── css/style.css
    └── js/
        ├── data.js
        ├── charts.js
        ├── auth.js
        └── app.js
```

---

## Setup & Run

### Step 1 — Install Python dependencies

```bash
cd backend
pip install -r requirements.txt
```

> Requires Python 3.9+. TensorFlow may take a few minutes to install.

### Step 2 — Train models

```bash
python train_models.py
```

This will:
- Generate synthetic EdgeIIoT-style dataset (5000 samples)
- Train Random Forest classifier
- Train CNN on RF spectrograms
- Train LSTM on behavioral sequences
- Save all models to `models/` folder
- Print accuracy for each model

> Takes ~5-10 minutes. Typical accuracies: RF 92%+, CNN 89%+, LSTM 87%+

### Step 3 — Start Flask backend

```bash
python api.py
```

Backend runs at: `http://localhost:5000`

### Step 4 — Open frontend

```bash
cd ../frontend
open index.html        # macOS
start index.html       # Windows
xdg-open index.html   # Linux
```

Or use VS Code Live Server (right-click index.html → Open with Live Server).

---

## Using the Real Kaggle Dataset

1. Download `DNN-EdgeIIoT-dataset.csv` from Kaggle
2. Place it in `backend/`
3. Open `generate_dataset.py` and set:
   ```python
   USE_REAL_DATASET = True
   ```
4. Run `python train_models.py` again

---

## API Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/health` | GET | Check backend status & model accuracies |
| `/authenticate` | POST | Authenticate one device |
| `/batch_authenticate` | POST | Authenticate multiple devices |
| `/model_info` | GET | Get model metadata |
| `/spectrogram` | POST | Get spectrogram data |

### Example API call
```bash
curl -X POST http://localhost:5000/authenticate \
  -H "Content-Type: application/json" \
  -d '{"device_id": "DEV-0001", "device_type": "Temperature Sensor", "features": {"packet_size": 200, "snr": 28, ...}}'
```

---

## Frontend Features

- **Dashboard** — Live sensor grid, RF spectrogram, LSTM behavioral chart
- **Sensors** — Full device registry with all scores
- **Analytics** — Auth history, attack distribution, model trends
- **Alerts** — Real-time security flag log

The frontend automatically falls back to simulation mode if the backend is offline.

---

## Threshold Configuration

Change trust threshold in `backend/api.py`:
```python
threshold = 70  # line ~100
```

And in `frontend/js/auth.js`:
```javascript
const THRESHOLD = 70;
```
# IOT-SENTINEL
