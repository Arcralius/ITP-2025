# Sensor Heartbeat Monitor (Proof of Concept)

This project is a **proof-of-concept (PoC)** system designed to monitor the heartbeat of sensors in real-time. It includes a simple server (`listener.py`) that validates and tracks sensor heartbeats, and a simulated sensor client (`sensor.py`) that sends periodic heartbeat messages.

---

## 🔧 Features

- **Sensor authentication** using HMAC signatures
- **Heartbeat tracking** with timestamps
- **Live status dashboard** to visualize healthy and missed sensors
- **REST API** to check sensor status programmatically

---

## 📁 Project Structure

├── listener.py # Flask server that receives and validates heartbeat signals
├── sensor.py # Simulated sensor that sends periodic heartbeats
├── requirements.txt # Required Python packages


---

## 🚀 Getting Started

### 1. Install dependencies
<pre><code>```
bash
pip install -r requirements.txt
```</code></pre>

### 2. Start the **heartbeat listener server**

In your terminal, run:

<pre><code>```
bash
python listener.py
```</code></pre>

This will start the server at http://localhost:5000.


### 3. Start the simulated sensor
In a separate terminal window, run:
<pre><code>```
bash
python sensor.py
```</code></pre>

The sensor will send a heartbeat every 5 seconds to the server.
You should see console output like:
<pre><code>```
bash
Sent heartbeat at 2025-05-23T12:00:00.123456 | Status: 200
[HEARTBEAT RECEIVED] Sensor UUID: f47ac10b-58cc-4372-a567-0e02b2c3d479 at 2025-05-23T12:00:00.123456
```</code></pre>

