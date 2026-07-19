from app import db
from flask_login import UserMixin
from datetime import datetime

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    failed_attempts = db.Column(db.Integer, default=0)
    is_locked = db.Column(db.Boolean, default=False)
    locked_at = db.Column(db.DateTime, nullable=True)
    totp_secret = db.Column(db.String(32), nullable=True)
    is_totp_enabled = db.Column(db.Boolean, default=False)

    def __repr__(self):
        return f'<User {self.username}>'


class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    username = db.Column(db.String(50), nullable=True)
    event_type = db.Column(db.String(50), nullable=False)
    ip_address = db.Column(db.String(45), nullable=False)
    user_agent = db.Column(db.String(256), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', backref=db.backref('audit_logs', order_by='AuditLog.timestamp.desc()', lazy=True))

    def __repr__(self):
        return f'<AuditLog {self.event_type} - {self.username or "Anonymous"}>'