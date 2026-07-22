# 🛡️ NETscan
<div align="center">

# AI‑Enhanced Network Intrusion Detection System

**Real-time Hybrid Network Intrusion Detection System powered by Java, Python, Machine Learning and Live WebSocket Analytics**

![Java](https://img.shields.io/badge/Java-17-orange)
![Python](https://img.shields.io/badge/Python-3.x-blue)
![Maven](https://img.shields.io/badge/Maven-Build-red)
![Flask](https://img.shields.io/badge/Flask-API-black)
![Chart.js](https://img.shields.io/badge/Chart.js-Dashboard-green)
![License](https://img.shields.io/badge/License-MIT-success)

</div>

---

## 📌 Overview

NETscan is an **AI-enhanced Network Intrusion Detection System (NIDS)** that continuously monitors network traffic, extracts packet telemetry, applies both **rule-based detection** and an **Isolation Forest machine learning model**, then streams live analytics to an interactive dashboard.

Unlike a traditional signature-only IDS, NETscan combines deterministic heuristics with anomaly detection to identify suspicious behaviour in real time.

---

# ✨ Features

- 🚀 Live packet capture
- 🤖 AI anomaly detection (Isolation Forest)
- 🛡️ SYN Flood detection
- 🔎 Port Scan detection
- 📈 Live traffic analytics
- ⚡ WebSocket powered dashboard
- 🌐 REST communication between Java & Python
- 📊 Interactive Chart.js visualizations
- 🎯 Weighted alert severity (LOW / MEDIUM / HIGH)

---

# 🏗️ Architecture

```text
                 Internet Traffic
                        │
                        ▼
          Java Packet Capture Engine
                 (pcap4j)
                        │
        ┌───────────────┴───────────────┐
        ▼                               ▼
 Rule-Based Detection          Python ML Engine
  • SYN Flood                  Isolation Forest
  • Port Scan
  • Traffic Spike
        └───────────────┬───────────────┘
                        ▼
                  Alert Engine
                        │
                 WebSocket Server
                        │
                        ▼
          Live Security Dashboard
```

---

# ⚙️ Tech Stack

| Layer | Technology |
|-------|------------|
| Backend | Java 17 |
| Build | Maven |
| Packet Capture | pcap4j + Npcap |
| ML | Python, Scikit-Learn |
| API | Flask |
| Communication | REST + WebSocket |
| Frontend | HTML, CSS, JavaScript |
| Charts | Chart.js |

---

# 📂 Project Structure

```text
NETscan/
│
├── anomaly-detector/
│   ├── app.py
│   ├── train.py
│   ├── requirements.txt
│   └── model.pkl
│
├── netscan/
│   ├── src/
│   ├── pom.xml
│   └── Dashboard.html
│
├── screenshots/
├── README.md
└── LICENSE
```

---

# 🔄 Workflow

1. Capture packets using **pcap4j**.
2. Aggregate traffic statistics.
3. Send telemetry to the Flask ML API.
4. Predict anomalies using Isolation Forest.
5. Execute heuristic detection.
6. Merge results in the Alert Engine.
7. Broadcast updates over WebSocket.
8. Render live dashboard charts.

---

# 🚨 Detection Capabilities

| Detection | Method |
|-----------|--------|
| SYN Flood | Rule-based |
| Port Scanning | Rule-based |
| Traffic Spike | Rule-based |
| Unknown Behaviour | Machine Learning |

---

# 📋 Prerequisites

Before installing **NETscan**, make sure the following software is installed on your system.

| Software | Version | Purpose |
|----------|---------|---------|
| Java JDK | 17 or later | Runs the packet capture engine |
| Apache Maven | 3.9+ | Builds the Java application |
| Python | 3.10 or later | Runs the Machine Learning engine |
| Npcap | Latest | Enables packet capturing on Windows |
| Git | Latest | Clone the repository |
| Chrome / Edge / Firefox | Latest | View the live dashboard |

> **Important**
>
> During **Npcap** installation, enable **"Install Npcap in WinPcap API-compatible Mode"**. This is required for **pcap4j** to capture network packets correctly.

### Verify Java Installation

```bash
java -version
javac -version
mvn -version
```

### Verify Python Installation

```bash
python --version
pip --version
```

### Install Python Dependencies

Navigate to the ML Engine directory:

```bash
cd anomaly-detector
```

Install dependencies using the requirements file:

```bash
pip install -r requirements.txt
```

Or install them manually:

```bash
pip install flask numpy scikit-learn joblib
```

---

# 🚀 Installation

## Clone

```bash
git clone https://github.com/<your-username>/NETscan.git
cd NETscan
```

## Python

```bash
cd anomaly-detector
pip install -r requirements.txt
python train.py
python app.py
```

## Java

```bash
cd netscan
mvn clean package
java -jar target/packet-capture-1.0.jar
```

Open `Dashboard.html` in your browser.

---
```text
Dashboard Overview

Threat Feed

Traffic Analytics

Alert Panel
```

---

# 🎯 Why NETscan?

- Hybrid AI + heuristic detection
- Modular architecture
- Real-time visualization
- Lightweight deployment
- Easy to extend with additional ML models

---

# 🛣️ Roadmap

- [ ] Deep Learning models
- [ ] Docker deployment
- [ ] Linux support
- [ ] Threat intelligence integration
- [ ] Authentication
- [ ] Historical analytics
- [ ] Export reports

---

# 🤝 Contributing

Contributions, feature requests and improvements are welcome.

Fork the repository, create a feature branch and submit a pull request.

---

# 👨‍💻 Author

**Hamza**

Full Stack • Java • Python • AI

---

# ⭐ Support

If you found this project useful, consider giving it a **Star ⭐** on GitHub.



