from flask import Flask, render_template, jsonify
import sqlite3
from collections import Counter
import os

app = Flask(__name__)

DB_PATH = "vulns.db"

def get_db_rows(limit=1000):
    """Fetch recent vulnerability scan results."""
    if not os.path.exists(DB_PATH):
        print("[!] Database not found at:", DB_PATH)
        return []

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    # Check if table exists
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='vulnerabilities';")
    if not cur.fetchone():
        print("[!] Table 'vulnerabilities' not found in DB.")
        conn.close()
        return []

    cur.execute("""
        SELECT id, target, port, service, state, timestamp
        FROM vulnerabilities
        ORDER BY timestamp DESC
        LIMIT ?
    """, (limit,))
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


@app.route("/api/rows")
def api_rows():
    """Return raw scan result rows."""
    rows = get_db_rows(1000)
    return jsonify(rows)


@app.route("/api/chart-data")
def api_chart_data():
    """Return data for charts: port states & top services."""
    rows = get_db_rows(1000)

    if not rows:
        return jsonify({
            "state": {"labels": [], "values": []},
            "service": {"labels": [], "values": []}
        })

    # Count port states
    states = [r["state"] for r in rows if r.get("state")]
    state_counts = Counter(states)
    labels = list(state_counts.keys())
    values = [state_counts[l] for l in labels]

    # Count top services
    services = [r["service"] for r in rows if r.get("service")]
    svc_counts = Counter(services).most_common(10)
    svc_labels = [s for s, _ in svc_counts]
    svc_values = [v for _, v in svc_counts]

    return jsonify({
        "state": {"labels": labels, "values": values},
        "service": {"labels": svc_labels, "values": svc_values}
    })


@app.route("/api/stats")
def api_stats():
    """Return summary stats for the dashboard."""
    rows = get_db_rows(1000)
    if not rows:
        return jsonify({
            "total_hosts": 0,
            "open_ports": 0,
            "filtered_ports": 0,
            "last_scan": "-"
        })

    total_hosts = len(set([r["target"] for r in rows if r.get("target")]))
    open_ports = sum(1 for r in rows if r.get("state") == "open")
    filtered_ports = sum(1 for r in rows if r.get("state") == "filtered")
    last_scan = rows[0].get("timestamp", "-") if rows else "-"

    return jsonify({
        "total_hosts": total_hosts,
        "open_ports": open_ports,
        "filtered_ports": filtered_ports,
        "last_scan": last_scan
    })


@app.route("/")
def index():
    """Render main dashboard page."""
    return render_template("index.html")


if __name__ == "__main__":
    app.run(debug=True, port=5000)
