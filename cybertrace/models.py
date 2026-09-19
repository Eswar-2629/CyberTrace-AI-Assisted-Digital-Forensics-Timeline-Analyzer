from datetime import datetime, timezone
from .extensions import db

def utc_now():
    return datetime.now(timezone.utc)

class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.BigInteger, primary_key=True)
    username = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(30), nullable=False)
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utc_now)

class Case(db.Model):
    __tablename__ = "cases"

    id = db.Column(db.BigInteger, primary_key=True)
    case_number = db.Column(db.String(100), unique=True, nullable=False)
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    status = db.Column(db.String(30), nullable=False, default="OPEN")
    created_by = db.Column(db.BigInteger, db.ForeignKey("users.id"), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utc_now)
    updated_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=utc_now,
        onupdate=utc_now
    )

class EvidenceFile(db.Model):
    __tablename__ = "evidence_files"

    id = db.Column(db.BigInteger, primary_key=True)
    case_id = db.Column(
        db.BigInteger,
        db.ForeignKey("cases.id", ondelete="CASCADE"),
        nullable=False
    )
    original_name = db.Column(db.String(255), nullable=False)
    evidence_type = db.Column(db.String(50), nullable=False)
    sha256 = db.Column(db.String(64), nullable=False)
    size_bytes = db.Column(db.BigInteger, nullable=False)
    encrypted_payload = db.Column(db.LargeBinary, nullable=False)
    uploaded_by = db.Column(db.BigInteger, db.ForeignKey("users.id"), nullable=False)
    uploaded_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utc_now)

class Event(db.Model):
    __tablename__ = "events"

    id = db.Column(db.BigInteger, primary_key=True)
    case_id = db.Column(
        db.BigInteger,
        db.ForeignKey("cases.id", ondelete="CASCADE"),
        nullable=False
    )
    evidence_file_id = db.Column(
        db.BigInteger,
        db.ForeignKey("evidence_files.id", ondelete="SET NULL")
    )
    event_time = db.Column(db.DateTime(timezone=True), nullable=False)
    event_type = db.Column(db.String(100), nullable=False)
    source = db.Column(db.String(100))
    host = db.Column(db.String(255))
    username = db.Column(db.String(255))
    source_ip = db.Column(db.String(45))
    destination_ip = db.Column(db.String(45))
    file_path = db.Column(db.Text)
    registry_path = db.Column(db.Text)
    message = db.Column(db.Text, nullable=False)
    normalized_text = db.Column(db.Text)
    metadata = db.Column(db.JSON, nullable=False, default=dict)
    classification = db.Column(db.String(100))
    anomaly_score = db.Column(db.Float)
    is_anomaly = db.Column(db.Boolean, nullable=False, default=False)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utc_now)

class TimelineRelationship(db.Model):
    __tablename__ = "timeline_relationships"

    id = db.Column(db.BigInteger, primary_key=True)
    case_id = db.Column(db.BigInteger, nullable=False)
    from_event_id = db.Column(db.BigInteger, nullable=False)
    to_event_id = db.Column(db.BigInteger, nullable=False)
    relationship_type = db.Column(db.String(100), nullable=False)
    confidence = db.Column(db.Float, nullable=False, default=0.5)

class AuditLog(db.Model):
    __tablename__ = "audit_logs"

    id = db.Column(db.BigInteger, primary_key=True)
    user_id = db.Column(db.BigInteger)
    action = db.Column(db.String(100), nullable=False)
    resource_type = db.Column(db.String(100))
    resource_id = db.Column(db.String(100))
    ip_address = db.Column(db.String(45))
    details = db.Column(db.JSON, nullable=False, default=dict)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utc_now)