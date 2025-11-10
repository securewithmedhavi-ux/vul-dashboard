# app.py
from flask import Flask, render_template, jsonify, request
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from celery.result import AsyncResult
from celery_app import make_celery
from models import db, Vulnerability
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
# Celery Task
# -------------------------
@celery.task(name="vulndashboard.run_scan_task")
def run_scan_task(target):
    import nmap

    scanner = nmap.PortScanner()
    results = []

    try:
        scanner.scan(target, arguments="-sS -T4")

        for host in scanner.all_hosts():
            for proto in scanner[host].all_protocols():
                ports = scanner[host][proto].keys()
                for port in ports:
                    state = scanner[host][proto][port]["state"]
                    service = scanner[host][proto][port]["name"]

                    vuln = Vulnerability(
                        target=host,
                        port=port,
                        service=service,
                        state=state,
                        timestamp=datetime.utcnow(),
                    )
                    db.session.add(vuln)
                    results.append(vuln.as_dict())

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
    # ✅ Clear all previous results whenever the page loads
    try:
        db.session.query(Vulnerability).delete()
        db.session.commit()
        print("✅ Database cleared on refresh")
    except Exception as e:
        db.session.rollback()
        print("⚠️ Error clearing database:", e)

    return render_template("index.html")


# Both endpoints for compatibility
@app.route("/start_scan", methods=["POST"])
@app.route("/api/scan", methods=["POST"])
def start_scan():
    target = request.json.get("target")
    if not target:
        return jsonify({"error": "Target IP is required"}), 400

    task = run_scan_task.delay(target)
    return jsonify({"task_id": task.id})


# ✅ Route to get Celery task status
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
        num_deleted = db.session.query(Vulnerability).delete()
        db.session.commit()
        return jsonify({"status": "success", "deleted": num_deleted})
    except Exception as e:
        db.session.rollback()
        return jsonify({"status": "error", "message": str(e)}), 500


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
