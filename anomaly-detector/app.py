"""Flask REST API for NIDS anomaly detection."""

"""
Flask application for the Network Anomaly Detection Machine Learning Engine.
"""
from flask import Flask, request, jsonify
import numpy as np
import joblib
import os

app = Flask(__name__)

# ── Load model once at startup ────────────────────────────────────────────
MODEL_PATH = 'model.pkl'

if not os.path.exists(MODEL_PATH):
    raise RuntimeError("model.pkl not found. Run train.py first.")

model = joblib.load(MODEL_PATH)
print("Model loaded successfully.")

FEATURES = [
    'packets_per_second',
    'unique_ports',
    'syn_count',
    'avg_packet_size',
    'duration'
]


# ── Health check ──────────────────────────────────────────────────────────
@app.route('/health', methods=['GET'])
def health():
    return jsonify({
        'status'  : 'ok',
        'model'   : MODEL_PATH,
        'features': FEATURES
    })

# ── Single predict ────────────────────────────────────────────────────────
@app.route('/predict', methods=['POST'])
def predict():
    body = request.get_json()

    if not body:
        return jsonify({'error': 'Request body must be JSON'}), 400

    missing = [f for f in FEATURES if f not in body]
    if missing:
        return jsonify({'error': 'Missing features', 'missing': missing}), 400

    for f in FEATURES:
        if not isinstance(body[f], (int, float)):
            return jsonify({
                'error': f"Feature '{f}' must be a number"
            }), 400

    features       = np.array([[body[f] for f in FEATURES]])
    raw_prediction = model.predict(features)[0]
    anomaly_score  = model.score_samples(features)[0]

    # Cast numpy types → native Python types (required for Python 3.14+)
    is_anomaly = bool(raw_prediction == -1)

    return jsonify({
        'input'         : {f: body[f] for f in FEATURES},
        'prediction'    : 'ANOMALY' if is_anomaly else 'NORMAL',
        'is_anomaly'    : is_anomaly,
        'anomaly_score' : float(round(float(anomaly_score), 4)),
        'score_meaning' : 'More negative = more anomalous. Threshold ~ -0.1'
    })

# ── Batch predict ─────────────────────────────────────────────────────────
@app.route('/predict/batch', methods=['POST'])
def predict_batch():
    body = request.get_json()

    if not body or 'samples' not in body:
        return jsonify({'error': "Body must have a 'samples' list"}), 400

    samples = body['samples']

    if not isinstance(samples, list) or len(samples) == 0:
        return jsonify({'error': "'samples' must be a non-empty list"}), 400

    results = []

    for i, sample in enumerate(samples):
        missing = [f for f in FEATURES if f not in sample]
        if missing:
            results.append({'index': i, 'error': f'Missing features: {missing}'})
            continue

        features      = np.array([[sample[f] for f in FEATURES]])
        raw_pred      = model.predict(features)[0]
        anomaly_score = model.score_samples(features)[0]

        # Cast numpy types → native Python types (required for Python 3.14+)
        is_anomaly = bool(raw_pred == -1)

        results.append({
            'index'         : i,
            'prediction'    : 'ANOMALY' if is_anomaly else 'NORMAL',
            'is_anomaly'    : is_anomaly,
            'anomaly_score' : float(round(float(anomaly_score), 4))
        })

    total     = len(results)
    anomalies = sum(1 for r in results if r.get('is_anomaly'))

    return jsonify({
        'results'      : results,
        'total_samples': total,
        'anomaly_count': anomalies,
        'normal_count' : total - anomalies
    })

if __name__ == '__main__':
    app.run(debug=True, port=5000)