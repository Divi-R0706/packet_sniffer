import sqlite3
from collections import Counter
import matplotlib.pyplot as plt
from datetime import datetime

# Connect to DB
conn = sqlite3.connect('packets.db')
cursor = conn.cursor()

# Fetch timestamps from DB
cursor.execute("SELECT timestamp FROM traffic_logs")
rows = cursor.fetchall()

# Format timestamps to second-level
timestamps = [datetime.strptime(row[0], "%Y-%m-%d %H:%M:%S.%f").strftime("%H:%M:%S") for row in rows]

# Count how many packets per second
packet_counts = Counter(timestamps)

# Sort by time
times = sorted(packet_counts)
counts = [packet_counts[t] for t in times]

# Plot
plt.figure(figsize=(12, 5))
plt.plot(times, counts, marker='o', linestyle='-', color='blue')
plt.xticks(rotation=45)
plt.title("Packets Captured Per Second")
plt.xlabel("Time (HH:MM:SS)")
plt.ylabel("Packet Count")
plt.tight_layout()
plt.grid(True)
plt.show()
