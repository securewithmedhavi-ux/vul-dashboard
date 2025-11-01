import subprocess
import xml.etree.ElementTree as ET
import sqlite3
from datetime import datetime

def run_nmap_scan(target):
    """Runs an Nmap scan and returns the parsed results."""
    print(f"🔍 Scanning target: {target} ...")

    # Run Nmap with XML output
    result = subprocess.run(['nmap', '-oX', '-', target], capture_output=True, text=True)

    if result.returncode != 0:
        print("❗ Nmap returned an error or was not found. Output:")
        print(result.stderr)
        return []

    # Parse XML output
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


def save_to_db(findings):
    """Save scan results to SQLite database."""
    if not findings:
        print("ℹ️  No findings to save.")
        return

    conn = sqlite3.connect('vulns.db')
    cursor = conn.cursor()

    for f in findings:
        cursor.execute('''
            INSERT INTO vulnerabilities (target, port, service, state, timestamp)
            VALUES (?, ?, ?, ?, ?)
        ''', (f[0], int(f[1]) if f[1] and f[1].isdigit() else None, f[2], f[3], datetime.now()))

    conn.commit()
    conn.close()
    print("💾 Results saved to database.")


if __name__ == "__main__":
    target = input("Enter target to scan (e.g., 127.0.0.1 or scanme.nmap.org): ").strip()
    if not target:
        print("No target provided. Exiting.")
    else:
        findings = run_nmap_scan(target)
        save_to_db(findings)
        print("✅ Scan complete.")