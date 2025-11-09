from flask import Flask, render_template, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from sqlalchemy import func
from collections import Counter
from datetime import datetime
from celery.result import AsyncResult
import os
import subprocess
import xml.etree.ElementTree as ET

# Import Celery instance
from celery_app import celery

# Import database and model
from models import db, Vulnerability

# --- Flask App Initialization ---
app = Flask(__name__)

# Database Configuration
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv(
    "DATABASE_URL", "postgresql://postgres:postgres@db:5432/vulndb"
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Initialize DB and Migrations
db.init_app(app)
migrate = Migrate(app, db)

# --- Helper Function for Nmap Scan ---
def run_nmap_scan(target):
    """Run Nmap scan and parse XML output."""
    print(f"🔍 Running Nmap scan on target: {target}")
    result = subprocess.run(["nmap", "-oX", "-", target], capture_output=True, text=True)

    if result.returncode != 0:
        raise Exception(result.stderr or "Nmap scan failed")

    root = ET.fromstring(result.stdout)
    findings = []

    for host in root.findall("host"):
        addr_el = host.find("address")
        address = addr_el.get("addr") if addr_el is not None else target
        ports = host.find("ports")

        if ports is not None:
            for port in ports.findall("port"):
                port_id = port.get("portid")
                state_el = port.find("state")
                state = state_el.get("state") if state_el is not None else "unknown"
                service_el = port.find("service")
                service = service_el.get("name") if service_el is not None else "unknown"
                findings.append((address, port_id, service, state))

    return findings

# --- Celery Task ---
@celery.task(bind=True, name="vulndashboard.run_scan_task")
def run_scan_task(self, target):
    """Run Nmap in background and save results to DB."""
    try:
        findings = run_nmap_scan(target)
        with app.app_context():
            for f in findings:
                vuln = Vulnerability(
                    target=f[0],
                    port=int(f[1]) if f[1].isdigit() else None,
                    service=f[2],
                    state=f[3],
                    timestamp=datetime.utcnow(),
                )
                db.session.add(vuln)
            db.session.commit()
        return {"status": "success", "count": len(findings)}

    except Exception as e:
        with app.app_context():
            db.session.rollback()
        return {"status": "failed", "error": str(e)}

# --- Utility Function ---
def get_db_rows(limit=1000):
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

# --- Flask API Routes ---
@app.route("/api/rows")
def api_rows():
    rows = get_db_rows(1000)
    return jsonify(rows)

@app.route("/api/chart-data")
def api_chart_data():
    rows = get_db_rows(1000)
    if not rows:
        return jsonify({
            "state": {"labels": [], "values": []},
            "service": {"labels": [], "values": []},
        })

    states = [r["state"] for r in rows if r.get("state")]
    services = [r["service"] for r in rows if r.get("service")]

    state_counts = Counter(states)
    svc_counts = Counter(services).most_common(10)

    return jsonify({
        "state": {"labels": list(state_counts.keys()), "values": list(state_counts.values())},
        "service": {"labels": [s for s, _ in svc_counts], "values": [v for _, v in svc_counts]},
    })

@app.route("/api/stats")
def api_stats():
    rows = get_db_rows(1000)
    if not rows:
        return jsonify({
            "total_hosts": 0,
            "open_ports": 0,
            "filtered_ports": 0,
            "last_scan": "-",
        })

    total_hosts = len(set(r["target"] for r in rows))
    open_ports = sum(1 for r in rows if r["state"] == "open")
    filtered_ports = sum(1 for r in rows if r["state"] == "filtered")
    last_scan = rows[0]["timestamp"]

    return jsonify({
        "total_hosts": total_hosts,
        "open_ports": open_ports,
        "filtered_ports": filtered_ports,
        "last_scan": last_scan,
    })

@app.route("/api/scan", methods=["POST"])
def api_trigger_scan():
    """Trigger async Nmap scan using Celery."""
    data = request.get_json() or {}
    target = data.get("target")

    if not target:
        return jsonify({"error": "Target is required"}), 400

    task = celery.send_task("vulndashboard.run_scan_task", args=[target])
    return jsonify({"task_id": task.id}), 202

@app.route("/api/task/<task_id>")
def api_task_status(task_id):
    """Check Celery task status."""
    res = AsyncResult(task_id, app=celery)
    info = {
        "id": task_id,
        "state": res.state,
        "result": res.result if res.ready() else None,
    }
    return jsonify(info)

@app.route("/")
def index():
    """Render dashboard and clear all previous results."""
    with app.app_context():
        db.session.query(Vulnerability).delete()
        db.session.commit()
        print("🧹 Cleared old vulnerabilities on page refresh")
    return render_template("index.html")

# --- Entry Point ---
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    print("✅ Connected to:", app.config["SQLALCHEMY_DATABASE_URI"])
    app.run(host="0.0.0.0", port=5000)
