from flask import Flask, render_template, request
import sqlite3

app = Flask(__name__)
DB_PATH = "../packets.db"

@app.route('/')
def index():
    ip_filter = request.args.get("ip")
    query = "SELECT src_ip, dst_ip, src_port, dst_port, protocol, flags, timestamp FROM traffic_logs"
    params = ()

    if ip_filter:
        query += " WHERE src_ip=? OR dst_ip=?"
        params = (ip_filter, ip_filter)

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(query + " ORDER BY timestamp DESC LIMIT 100", params)
    logs = c.fetchall()

    # Count packets per minute for graph
    c.execute("SELECT strftime('%H:%M', timestamp), COUNT(*) FROM traffic_logs GROUP BY 1 ORDER BY 1 DESC LIMIT 10")
    chart_data = c.fetchall()
    times = [row[0] for row in reversed(chart_data)]
    counts = [row[1] for row in reversed(chart_data)]

    # Detect suspicious IPs (DoS or Port Scans)
    suspicious_ips = set()

    c.execute("SELECT src_ip, COUNT(*) FROM traffic_logs WHERE timestamp > datetime('now', '-1 minute') GROUP BY src_ip")
    for ip, count in c.fetchall():
        if count > 50:
            suspicious_ips.add(ip)

    c.execute("SELECT src_ip, COUNT(DISTINCT dst_port) FROM traffic_logs WHERE timestamp > datetime('now', '-1 minute') GROUP BY src_ip")
    for ip, port_count in c.fetchall():
        if port_count > 20:
            suspicious_ips.add(ip)

    conn.close()

    return render_template("index.html", logs=logs, times=times, counts=counts, ip_filter=ip_filter, suspicious_ips=suspicious_ips)

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)



