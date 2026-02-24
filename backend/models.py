from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    websites = db.relationship('WebsiteEntry', backref='owner', lazy=True)
    monitored_emails = db.relationship('MonitoredEmail', backref='owner', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class IPBlacklist(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45), unique=True, nullable=False)
    reason = db.Column(db.String(255))
    added_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<IPBlacklist {self.ip_address}>'

class WebsiteEntry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(255), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    health_score = db.Column(db.Integer, default=100)
    last_scan = db.Column(db.DateTime)
    status = db.Column(db.String(50), default='Optimal')
    malware_detected = db.Column(db.Boolean, default=False)
    breach_count = db.Column(db.Integer, default=0)

class MonitoredEmail(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    breach_count = db.Column(db.Integer, default=0)
    last_check = db.Column(db.DateTime, default=datetime.utcnow)

class BreachLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    target = db.Column(db.String(255), nullable=False) # Email or Website
    attack_type = db.Column(db.String(100))
    severity = db.Column(db.String(20))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    description = db.Column(db.Text)
    is_real_time = db.Column(db.Boolean, default=True)
