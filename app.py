from flask import Flask, render_template, jsonify, request
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from celery.result import AsyncResult
from celery_app import make_celery
from models import db, Vulnerability, CVE  # include CVE
from datetime import datetime
import os

app = Flask(__name__)

# -------------------------
# Configuration
# -------------------------
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv(
    "DATABASE_URL", "postgresql://postgres:postgres@db:5432/vulndb"
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["CELERY_BROKER_URL"] = os.getenv("CELERY_BROKER_URL", "redis://redis:6379/0")
app.config["CELERY_RESULT_BACKEND"] = os.getenv("CELERY_RESULT_BACKEND", "redis://redis:6379/0")

db.init_app(app)
migrate = Migrate(app, db)
celery = make_celery(app)


# -------------------------
# Celery Scan Task
# -------------------------
@celery.task(name="vulndashboard.run_scan_task")
def run_scan_task(target):
    import nmap
    import requests

    scanner = nmap.PortScanner()
    results = []

    try:
        scanner.scan(target, arguments="-sS -T4")

        for host in scanner.all_hosts():
            for proto in scanner[host].all_protocols():
                for port, details in scanner[host][proto].items():
                    state = details["state"]
                    service = details["name"]

                    vuln = Vulnerability(
                        target=host,
                        port=port,
                        service=service,
                        state=state,
                        timestamp=datetime.utcnow(),
                    )
                    db.session.add(vuln)
                    results.append(vuln.as_dict())

                    # --- CVE Fetch ---
                    try:
                        r = requests.get(f"https://vulners.com/api/v3/search/lucene/?query={service}")
                        if r.status_code == 200:
                            data = r.json()
                            if data.get("data", {}).get("search"):
                                for item in data["data"]["search"]:
                                    cve = CVE(
                                        service_name=service,
                                        cve_id=item["id"],
                                        description=item.get("description", ""),
                                        severity=item.get("cvss", 0.0),
                                        published_date=item.get("published", ""),
                                    )
                                    db.session.add(cve)
                    except Exception as api_error:
                        print("Vulners API error:", api_error)

        db.session.commit()

    except Exception as e:
        print("Error during scan:", e)
        db.session.rollback()
        return {"status": "error", "message": str(e)}

    return {"status": "success", "count": len(results)}


# -------------------------
# Routes
# -------------------------
@app.route("/")
def index():

    # -------------------------
    # AUTO-CLEAR DB ON PAGE LOAD
    # -------------------------
    db.session.query(Vulnerability).delete()
    db.session.query(CVE).delete()
    db.session.commit()
    print("✔ Auto-cleared all vulnerabilities & CVEs on page refresh")

    return render_template("index.html")


@app.route("/start_scan", methods=["POST"])
@app.route("/api/scan", methods=["POST"])
def start_scan():
    target = request.json.get("target")
    if not target:
        return jsonify({"error": "Target IP is required"}), 400

    task = run_scan_task.delay(target)
    return jsonify({"task_id": task.id})


@app.route("/api/task/<task_id>")
@app.route("/scan_status/<task_id>")
def scan_status(task_id):
    result = AsyncResult(task_id, app=celery)
    response = {"state": result.state, "info": result.info if result.info else None}
    return jsonify(response)


@app.route("/api/rows")
@app.route("/results")
def results():
    vulnerabilities = Vulnerability.query.order_by(Vulnerability.timestamp.desc()).all()
    return jsonify([v.as_dict() for v in vulnerabilities])


@app.route("/clear_results", methods=["POST"])
def clear_results():
    try:
        db.session.query(Vulnerability).delete()
        db.session.query(CVE).delete()
        db.session.commit()
        return jsonify({"status": "success"})
    except Exception as e:
        db.session.rollback()
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/cves")
def get_cves():
    cves = CVE.query.order_by(CVE.published_date.desc()).all()
    return jsonify([cve.as_dict() for cve in cves])


# -------------------------
# Initialization
# -------------------------
def initialize_database():
    with app.app_context():
        db.create_all()


# -------------------------
# Main Entry
# -------------------------
if __name__ == "__main__":
    initialize_database()
    app.run(host="0.0.0.0", port=5000, debug=True)
