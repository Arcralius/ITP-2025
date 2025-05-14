# ITP-2025
ITP 2025 May Materials

## DNS Traffic Sniffer & Web Viewer
A Python-based DNS traffic sniffer that captures DNS queries in real-time, logs them to a file, and sends the data to a Flask web server. Displays captured DNS queries grouped by timestamp on a simple web interface.

Certainly! Here's a **professional and clean version of the `README.md`**, without emojis or casual language — suitable for enterprise, academic, or production use.

---

# DNS Traffic Monitoring System

## Overview

This project provides a lightweight solution for capturing and analyzing DNS traffic in real time. It consists of two components:

1. **Packet Sniffer** – Captures DNS queries using Scapy.
2. **Web Viewer** – Displays captured DNS traffic via a Flask-based web interface.

The system is designed to be modular, extensible, and suitable for network monitoring, forensic analysis, or educational use.

---

## Key Features

- Real-time capture of DNS query traffic
- Accurate packet timestamping using Scapy
- Efficient logging with deduplication
- Web-based visualization with grouped display by timestamp
- Periodic transmission of new log data using HTTP POST
- Auto-refreshed web UI for continuous monitoring

---

## Architecture

The system operates as follows:

1. The sniffer captures DNS queries on UDP port 53.
2. Each query is logged into a local file with metadata including:
   - Timestamp (from packet)
   - Source and destination IP addresses
   - Domain name
   - Query type
3. At regular intervals, only newly added lines are transmitted to the Flask backend via HTTP POST.
4. The Flask application stores and organizes the received logs by timestamp.
5. A web interface displays the organized logs grouped by timestamp, ensuring clarity and readability.

---

## Installation & Setup

### Prerequisites

Ensure the following software is installed on your system:

- Python 3.x
- Pip package manager
- Npcap (for Windows; available at [https://nmap.org/npcap/](https://nmap.org/npcap/))

### Dependencies

Install required packages using pip:

```bash
pip install scapy flask requests
```

---

### Execution Instructions

#### 1. Start the Flask Application

Navigate to the project root directory and run:

```bash
python app.py
```

By default, the server runs on port 5000. Access the web interface at:

```
http://localhost:5000
```

#### 2. Start the DNS Sniffer

In a separate terminal window, execute:

```bash
python dns_sniffer.py
```

Ensure this process has sufficient privileges to capture packets (run as administrator/root if necessary).

---

## Directory Structure

```
dns-traffic-monitor/
│
├── app.py               # Flask backend server
├── dns_sniffer.py       # DNS packet capture and logger
├── templates/
│   └── index.html       # HTML template for web interface
├── dns_traffic.txt      # Log file containing captured DNS queries
└── README.md            # This documentation file
```

---

## Data Format

Each log entry contains the following fields:

```
YYYY-MM-DD HH:MM:SS | Src: <source_ip> | Dst: <destination_ip> | Domain: <domain_name> | Type: <query_type>
```

Example:

```
2025-04-05 12:34:22 | Src: 192.168.1.10 | Dst: 8.8.8.8 | Domain: google.com | Type: A
```

---

## Extensibility

This system is modular and can be extended to support:

- Database-backed storage (e.g., SQLite, PostgreSQL)
- REST API endpoints for integration with other systems
- Export functionality (CSV, JSON)
- Filtering and search capabilities in the web interface
- WebSocket-based real-time updates
- Containerization using Docker for deployment

---

## Licensing

This project is distributed under the MIT License. See the accompanying `LICENSE` file for full terms and conditions.

---

## Contact

For questions, suggestions, or contributions, please open an issue on GitHub or contact the project maintainer directly.

--- 

Let me know if you'd like this formatted as Markdown for GitHub, or need additional files such as `.gitignore`, `LICENSE`, or `requirements.txt`.
