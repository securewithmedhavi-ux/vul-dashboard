from flask import Flask, render_template, jsonify
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func
from collections import Counter
from datetime import datetime
import config

# --- Flask App Initialization ---
app = Flask(__name__)
app.config.from_object(config)

db = SQLAlchemy(app)

# --- Database Model ---
class Vulnerability(db.Model):
    __tablename__ = "vulnerabilities"
    id = db.Column(db.Integer, primary_key=True)
    target = db.Column(db.String(255))
    port = db.Column(db.Integer)
    service = db.Column(db.String(255))
    state = db.Column(db.String(50))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    def as_dict(self):
        return {
            "id": self.id,
            "target": self.target,
            "port": self.port,
            "service": self.service,
            "state": self.state,
            "timestamp": self.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
        }

# --- Utility Function ---
def get_db_rows(limit=1000):
    """Fetch recent vulnerability scan results."""
    try:
        rows = (
            db.session.query(Vulnerability)
            .order_by(Vulnerability.timestamp.desc())
            .limit(limit)
            .all()
        )
        return [r.as_dict() for r in rows]
    except Exception as e:
        print(f"[!] Database error: {e}")
        return []

# --- API Endpoints ---
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
    state_labels = list(state_counts.keys())
    state_values = [state_counts[s] for s in state_labels]

    # Count top services
    services = [r["service"] for r in rows if r.get("service")]
    svc_counts = Counter(services).most_common(10)
    svc_labels = [s for s, _ in svc_counts]
    svc_values = [v for _, v in svc_counts]

    return jsonify({
        "state": {"labels": state_labels, "values": state_values},
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

    total_hosts = len(set(r["target"] for r in rows if r.get("target")))
    open_ports = sum(1 for r in rows if r.get("state") == "open")
    filtered_ports = sum(1 for r in rows if r.get("state") == "filtered")
    last_scan = rows[0].get("timestamp", "-") if rows else "-"

    return jsonify({
        "total_hosts": total_hosts,
        "open_ports": open_ports,
        "filtered_ports": filtered_ports,
        "last_scan": last_scan
    })

# --- Main Page ---
@app.route("/")
def index():
    """Render main dashboard page."""
    return render_template("index.html")

# --- Entry Point ---
if __name__ == "__main__":
    with app.app_context():
        db.create_all()  # Create tables if not exist
    print("✅ Connected to:", app.config["SQLALCHEMY_DATABASE_URI"])
    app.run(debug=True, host="0.0.0.0", port=5000)