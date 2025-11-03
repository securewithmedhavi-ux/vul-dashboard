# tasks.py
from celery_app import celery
from datetime import datetime
import subprocess
import xml.etree.ElementTree as ET

# Import Flask context and DB
from app import app, db, Vulnerability


def run_nmap_scan_parse(target: str):
    """Run an Nmap scan and return parsed results as (address, port, service, state)."""
    result = subprocess.run(
        ["nmap", "-oX", "-", target],
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        raise RuntimeError(result.stderr or "Nmap execution failed")

    root = ET.fromstring(result.stdout)
    findings = []

    for host in root.findall("host"):
        addr_el = host.find("address")
        address = addr_el.get("addr") if addr_el is not None else target
        ports_el = host.find("ports")
        if ports_el is not None:
            for port in ports_el.findall("port"):
                port_id = port.get("portid")
                state_el = port.find("state")
                state = state_el.get("state") if state_el is not None else "unknown"
                service_el = port.find("service")
                service = service_el.get("name") if service_el is not None else "unknown"
                findings.append((address, port_id, service, state))
    return findings


@celery.task(bind=True, name="vulndashboard.run_scan_task")
def run_scan_task(self, target: str):
    """Celery task to run Nmap scan and persist results."""
    try:
        findings = run_nmap_scan_parse(target)
    except Exception as e:
        return {"status": "failed", "error": str(e)}

    with app.app_context():
        try:
            for addr, port_str, service, state in findings:
                port = int(port_str) if port_str and port_str.isdigit() else None
                vuln = Vulnerability(
                    target=addr,
                    port=port,
                    service=service,
                    state=state,
                    timestamp=datetime.utcnow()
                )
                db.session.add(vuln)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            return {"status": "failed", "error": f"DB error: {e}"}

    return {"status": "success", "count": len(findings)}