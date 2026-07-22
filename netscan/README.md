# Project Setup Guide

This guide will help you set up the full two-part Network Intrusion Detection System (NIDS) project on a new Windows PC.

The project is split into two components:
1. **Python ML Engine** (`anomaly-detector`): A Flask API that classifies packet traffic.
2. **Java Packet Capture & WebSocket server** (`netscan`): Uses `pcap4j` to capture traffic, queries the ML Engine, and serves live statistics via WebSocket.

## 1. Prerequisites Needed

You will need to install the following software on the new PC:

- **Java 17+** (JDK) - Required to compile and run the Java `netscan` app.
- **Apache Maven** - For resolving dependencies and building the Java `.jar` file.
- **Python 3.x** - For running the ML Engine.
- **Npcap** - Crucial for packet capture on Windows. Ensure you tick the **"Install Npcap in WinPcap API-compatible Mode"** option during installation to ensure maximum compatibility with `pcap4j`.

---

## 2. Setup the ML Engine (`anomaly-detector`)

Before running the Java listener, the ML engine needs to be trained and started.

1. Open a terminal and navigate to the backend folder:
   ```bash
   cd D:\studies\anomaly-detector
   ```
2. Install the necessary Python packages:
   ```bash
   pip install flask numpy scikit-learn joblib
   ```
3. Generate the ML Model (`model.pkl`):
   ```bash
   python train.py
   ```
   *You should see `"Model trained and saved to model.pkl"`*.
4. Start the Flask Server:
   ```bash
   python app.py
   ```
   *Leave this terminal open. The server will run on `http://localhost:5000`*.

---

## 3. Setup the Packet Capture & Server (`netscan`)

With the Flask server running, you can now start capturing live packets.

1. Open a new terminal (preferably as **Administrator** because capturing packets usually requires elevated privileges).
2. Navigate to the Java folder:
   ```bash
   cd D:\studies\netscan
   ```
3. Build the project using Maven:
   ```bash
   mvn clean package
   ```
   *This compiles the project, downloads dependencies, and builds an executable jar under `target/packet-capture-1.0.jar`.*
4. Run the Packet Capture tool:
   ```bash
   java -jar target\packet-capture-1.0.jar
   ```
   *The Java program will auto-select your active network interface, start analyzing packets, sending data to the Flask ML Engine, and starting a WebSocket server on `ws://localhost:8080`.*

---

## 4. View the Dashboard

Once both the **Flask Server** and **Java Application** are running and capturing data:

1. Locate the `Dashboard.html` file inside `D:\studies\netscan`.
2. Double-click it to open it in Chrome, Edge, or Firefox.
3. The dashboard will connect to the local WebSocket server and start streaming the live analytics and any anomalies detected by the AI model.
