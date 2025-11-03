# nmap_scan.py
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime
from app import app, db, Vulnerability  # ✅ import app as well

def run_nmap_scan(target):
    """Runs an Nmap scan and returns the parsed results."""
    print(f"🔍 Scanning target: {target} ...")

    result = subprocess.run(['nmap', '-oX', '-', target], capture_output=True, text=True)

    if result.returncode != 0:
        print("❗ Nmap returned an error:")
        print(result.stderr)
        return []

    root = ET.fromstring(result.stdout)
    findings = []

    for host in root.findall('host'):
        addr_el = host.find('address')
        address = addr_el.get('addr') if addr_el is not None else target
        ports = host.find('ports')

        if ports is not None:
            for port in ports.findall('port'):
                port_id = port.get('portid')
                state_el = port.find('state')
                state = state_el.get('state') if state_el is not None else 'unknown'
                service_el = port.find('service')
                service = service_el.get('name') if service_el is not None else 'unknown'
                findings.append((address, port_id, service, state))

    return findings


def save_to_postgres(findings):
    """Save scan results to PostgreSQL using SQLAlchemy."""
    if not findings:
        print("ℹ️  No findings to save.")
        return

    # ✅ Use Flask application context here
    with app.app_context():
        for f in findings:
            vuln = Vulnerability(
                target=f[0],
                port=int(f[1]) if f[1].isdigit() else None,
                service=f[2],
                state=f[3],
                timestamp=datetime.now(),
            )
            db.session.add(vuln)

        db.session.commit()
        print("💾 Results saved to PostgreSQL.")


if __name__ == "__main__":
    target = input("Enter target to scan (e.g., 127.0.0.1 or scanme.nmap.org): ").strip()
    if not target:
        print("No target provided. Exiting.")
    else:
        findings = run_nmap_scan(target)
        save_to_postgres(findings)
        print("✅ Scan complete.")