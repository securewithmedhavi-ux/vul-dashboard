# models.py
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class Vulnerability(db.Model):
    __tablename__ = "vulnerabilities"

    id = db.Column(db.Integer, primary_key=True)
    target = db.Column(db.String(255))
    port = db.Column(db.Integer)
    service = db.Column(db.String(255))
    state = db.Column(db.String(50))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    cve_id = db.Column(db.String(50))
    cvss_score = db.Column(db.Float)
    cve_description = db.Column(db.Text)

    def as_dict(self):
        return {
            "id": self.id,
            "target": self.target,
            "port": self.port,
            "service": self.service,
            "state": self.state,
            "timestamp": self.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "cve_id": self.cve_id,
            "cvss_score": self.cvss_score,
            "cve_description": self.cve_description,
        }


class CVE(db.Model):
    __tablename__ = "cves"

    id = db.Column(db.Integer, primary_key=True)
    cve_id = db.Column(db.String(50), unique=True, nullable=False)
    description = db.Column(db.Text)
    published_date = db.Column(db.DateTime)
    severity = db.Column(db.String(20))
    cvss_score = db.Column(db.Float)
    source = db.Column(db.String(100))
    last_modified = db.Column(db.DateTime, default=datetime.utcnow)

    def as_dict(self):
        return {
            "id": self.id,
            "cve_id": self.cve_id,
            "description": self.description,
            "published_date": self.published_date.strftime("%Y-%m-%d %H:%M:%S") if self.published_date else None,
            "severity": self.severity,
            "cvss_score": self.cvss_score,
            "source": self.source,
            "last_modified": self.last_modified.strftime("%Y-%m-%d %H:%M:%S") if self.last_modified else None,
        }
