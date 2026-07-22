"""Training workflow for the NIDS Isolation Forest model."""

import numpy as np
from sklearn.ensemble import IsolationForest
import joblib

# ── Generate dummy training data ──────────────────────────────────────────
# Features: [packets_per_sec, unique_ports, syn_count,
#            avg_packet_size, duration]

np.random.seed(42)

# Normal traffic
normal_data = np.random.normal(
    loc=[50,  10, 2,  500, 30],
    scale=[10,  3, 1,  100,  5],
    size=(1000, 5)
)

# Anomalous traffic
anomaly_data = np.random.normal(
    loc=[500, 100, 50, 1400, 1],
    scale=[50,  20, 10,  100, 1],
    size=(50, 5)
)

training_data = np.vstack([normal_data, anomaly_data])

# ── Train model ───────────────────────────────────────────────────────────
model = IsolationForest(
    n_estimators=100,
    contamination=0.05,
    random_state=42,
    max_samples='auto'
)

model.fit(training_data)

# ── Save model ────────────────────────────────────────────────────────────
joblib.dump(model, 'model.pkl')
print("Model trained and saved to model.pkl")

# ── Sanity check ──────────────────────────────────────────────────────────
test_normal  = [[50,  10,  2,  500, 30]]
test_anomaly = [[999, 200, 80, 1400,  1]]

print("Normal sample  :", "NORMAL"  if model.predict(test_normal)[0]  ==  1 else "ANOMALY")
print("Anomaly sample :", "ANOMALY" if model.predict(test_anomaly)[0] == -1 else "NORMAL")
