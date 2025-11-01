from flask import Flask, render_template, jsonify
import sqlite3
from collections import Counter

app = Flask(__name__)

DB_PATH = "vulns.db"

def get_db_rows(limit=1000):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("SELECT id, target, port, service, state, timestamp FROM vulnerabilities ORDER BY timestamp DESC LIMIT ?", (limit,))
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows

@app.route("/api/rows")
def api_rows():
    rows = get_db_rows(1000)
    return jsonify(rows)

@app.route("/api/chart-data")
def api_chart_data():
    rows = get_db_rows(1000)
    # Count by state (open/filtered/closed/etc.)
    states = [r["state"] for r in rows if r["state"]]
    state_counts = Counter(states)
    labels = list(state_counts.keys())
    values = [state_counts[l] for l in labels]

    # Also provide counts by service (top 10)
    services = [r["service"] for r in rows if r["service"]]
    svc_counts = Counter(services).most_common(10)
    svc_labels = [s for s,_ in svc_counts]
    svc_values = [v for _,v in svc_counts]

    return jsonify({
        "state": {"labels": labels, "values": values},
        "service": {"labels": svc_labels, "values": svc_values}
    })

@app.route("/")
def index():
    return render_template("index.html")

if __name__ == "__main__":
    app.run(debug=True)