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

    def as_dict(self):
        return {
            "id": self.id,
            "target": self.target,
            "port": self.port,
            "service": self.service,
            "state": self.state,
            "timestamp": self.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
        }
