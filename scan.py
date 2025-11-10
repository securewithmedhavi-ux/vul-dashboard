# scan.py
from celery_app import make_celery
from models import db, Vulnerability
from datetime import datetime
import subprocess
import json
import re
import os

from flask import Flask

# Create minimal Flask context for Celery
app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL", "postgresql://postgres:postgres@db:5432/vulndb")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db.init_app(app)

celery = make_celery(app)


@celery.task(name="vulndashboard.run_scan_task")
def run_scan_task(target):
    """
    Example network scan task — uses nmap to detect open ports
    and saves results in the database.
    """
    try:
        # Simple nmap command
        command = ["nmap", "-sS", "-T4", "-Pn", target]
        result = subprocess.run(command, capture_output=True, text=True)
        output = result.stdout

        # Basic parsing of open ports
        matches = re.findall(r"(\d+)/tcp\s+open\s+(\S+)", output)

        vulnerabilities = []
        with app.app_context():
            for port, service in matches:
                vuln = Vulnerability(
                    target=target,
                    port=int(port),
                    service=service,
                    state="open",
                    timestamp=datetime.utcnow(),
                )
                db.session.add(vuln)
                vulnerabilities.append(vuln.as_dict())

            db.session.commit()

        return {"target": target, "count": len(vulnerabilities), "results": vulnerabilities}

    except Exception as e:
        return {"error": str(e)}
