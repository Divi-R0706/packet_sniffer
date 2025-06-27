# 🛡️ Network Packet Sniffer with Real-Time Alert System

A Python-based project that captures live network packets using Scapy, detects anomalies like DoS attacks or Port Scans, logs the data in SQLite, sends real-time email alerts, and visualizes traffic using a Flask dashboard.


## 📌 Features

- 📡 **Live Packet Capture** with `Scapy`
- 🧠 **Anomaly Detection**:
  - Detects potential **DoS attacks**
  - Detects **Port Scanning**
- 📬 **Email Alerts** for suspicious activity
- 🗃️ **SQLite Logging** for all traffic
- 🌐 **Flask Web Dashboard** with:
  - Latest captured packets
  - Suspicious IPs  
  - IP filter option


## 🛠 Tools & Technologies

- **Python 3**
- `Scapy` – Packet sniffing
- `SQLite3` – Local database
- `smtplib` – Sending email alerts
- `Flask` – Web dashboard


## ⚙️ Setup Instructions

### 🔸 1. Install Dependencies

pip install scapy flask
Update Email Credentials
In packet_sniffer_alert.py, set:

sender = 'your_email@gmail.com'
receiver = 'receiver_email@gmail.com'
app_password = 'your_app_password'
🛑 Gmail users: Enable App Passwords via Google Account > Security.

▶️ Running the Project
💻 Start the Sniffer

sudo python3 packet_sniffer_alert.py

🌐 Start the Flask Dashboard
cd dashboard_app
python3 app.py
Then open: http://127.0.0.1:5000

🧪 Test Anomalies

Ping Flood (DoS simulation):
ping 127.0.0.1 -f

Port Scan using Nmap:
nmap -p 1-100 127.0.0.1

You should see:
Packets getting logged
Email alert triggered
Suspicious IP listed in the dashboard

flow:
packet_sniffer_project/
├── packet_sniffer_alert.py # Core sniffer + alert system
├── app.py # Flask dashboard
├── packets.db # Auto-generated SQLite database
└── templates/
└── index.html # Web dashboard UI


