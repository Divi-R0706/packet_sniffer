from scapy.all import sniff, IP, TCP, UDP
import sqlite3
import smtplib
from email.mime.text import MIMEText
from datetime import datetime, timedelta
from collections import defaultdict

# === Configuration ===
PORT_SCAN_THRESHOLD = 10
DOS_PACKET_THRESHOLD = 50
TIME_WINDOW = timedelta(seconds=10)

# === Email Setup ===
SENDER_EMAIL = 'dv7227231@gmail.com'
RECEIVER_EMAIL = 'divi739767@gmail.com'
APP_PASSWORD = 'cjwm gdap hjuz fcvr'  # Use Gmail App Password

# === Setup SQLite DB ===
conn = sqlite3.connect('packets.db')
c = conn.cursor()
c.execute('''CREATE TABLE IF NOT EXISTS traffic_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    src_ip TEXT,
    dst_ip TEXT,
    src_port INT,
    dst_port INT,
    protocol TEXT,
    flags TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
)''')
conn.commit()

# === Email Function ===
def send_email_alert(subject, body):
    print(f"[DEBUG] Attempting to send email: {subject}")
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = SENDER_EMAIL
    msg['To'] = RECEIVER_EMAIL

    try:
        with smtplib.SMTP('smtp.gmail.com', 587) as server:
            server.starttls()
            server.login(SENDER_EMAIL, APP_PASSWORD)
            server.send_message(msg)
            print("[ALERT] Email sent successfully!")
    except Exception as e:
        print("[ERROR] Could not send email:", e)

# === Anomaly Tracking ===
ip_packet_counts = defaultdict(list)

# === Process Packets ===
def process_packet(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = "TCP" if TCP in packet else "UDP" if UDP in packet else str(packet[IP].proto)
        sport = packet[TCP].sport if TCP in packet else packet[UDP].sport if UDP in packet else 0
        dport = packet[TCP].dport if TCP in packet else packet[UDP].dport if UDP in packet else 0
        flags = str(packet[TCP].flags) if TCP in packet else ''
        timestamp = datetime.now()

        # Log packet to DB
        c.execute('''INSERT INTO traffic_logs (src_ip, dst_ip, src_port, dst_port, protocol, flags, timestamp)
                     VALUES (?, ?, ?, ?, ?, ?, ?)''',
                  (ip_src, ip_dst, sport, dport, proto, flags, timestamp))
        conn.commit()

        print(f"{timestamp} | {ip_src}:{sport} -> {ip_dst}:{dport} [{proto}] {flags}")

        # Track packet count
        ip_packet_counts[ip_src].append(timestamp)
        ip_packet_counts[ip_src] = [t for t in ip_packet_counts[ip_src] if t > timestamp - TIME_WINDOW]

        # === Detection Logic ===
        # DoS detection
        if len(ip_packet_counts[ip_src]) > DOS_PACKET_THRESHOLD:
            send_email_alert(
                "[DoS Alert] High Packet Rate Detected",
                f"Source IP: {ip_src}\nPackets in last 10 seconds: {len(ip_packet_counts[ip_src])}"
            )
            ip_packet_counts[ip_src].clear()

        # Port scan detection
        c.execute("SELECT DISTINCT dst_port FROM traffic_logs WHERE src_ip=? AND timestamp > ?",
                  (ip_src, timestamp - TIME_WINDOW))
        unique_ports = [row[0] for row in c.fetchall()]
        if len(unique_ports) > PORT_SCAN_THRESHOLD:
            send_email_alert(
                "[Port Scan Alert] Multiple Ports Accessed",
                f"Source IP: {ip_src}\nUnique Ports in 10s: {unique_ports}"
            )

# === Start Sniffing ===
print("[INFO] Starting packet capture...")
sniff(prn=process_packet, store=False)

