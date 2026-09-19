from flask import Blueprint, jsonify, request
from flask_jwt_extended import get_jwt_identity
from sqlalchemy import select

from .analyzer import analyze_case
from .audit import audit
from .crypto import encrypt_bytes, sha256_hex
from .extensions import db
from .ingestion import parse_evidence
from .models import Case, EvidenceFile, Event, TimelineRelationship
from .security import roles_required

events_bp = Blueprint("events", __name__)

@events_bp.post("/cases/<int:case_id>/upload")
@roles_required("ADMIN", "ANALYST")
def upload_evidence(case_id):
    case = db.session.get(Case, case_id)

    if case is None:
        return jsonify({"error": "case not found"}), 404

    uploaded = request.files.get("file")

    if uploaded is None or not uploaded.filename:
        return jsonify({"error": "file is required"}), 400

    content = uploaded.read()

    if not content:
        return jsonify({"error": "file is empty"}), 400

    evidence_type = request.form.get("evidence_type", "UNKNOWN")[:50]

    evidence = EvidenceFile(
        case_id=case_id,
        original_name=uploaded.filename[:255],
        evidence_type=evidence_type,
        sha256=sha256_hex(content),
        size_bytes=len(content),
        encrypted_payload=encrypt_bytes(content),
        uploaded_by=int(get_jwt_identity())
    )

    db.session.add(evidence)
    db.session.commit()

    analysis = parse_evidence(
        content,
        uploaded.filename,
        case_id,
        evidence.id
    )

    audit("UPLOAD_EVIDENCE", "EVIDENCE_FILE", evidence.id, {
        "filename": evidence.original_name,
        "sha256": evidence.sha256,
        "analysis": analysis
    })

    return jsonify({
        "evidence_id": evidence.id,
        "sha256": evidence.sha256,
        "analysis": analysis
    }), 201

@events_bp.get("/cases/<int:case_id>/timeline")
@roles_required("ADMIN", "ANALYST", "VIEWER")
def timeline(case_id):
    case = db.session.get(Case, case_id)

    if case is None:
        return jsonify({"error": "case not found"}), 404

    query = select(Event).where(Event.case_id == case_id)

    event_type = request.args.get("event_type")
    classification = request.args.get("classification")
    anomalies_only = request.args.get("anomalies_only", "false").lower() == "true"

    if event_type:
        query = query.where(Event.event_type == event_type)

    if classification:
        query = query.where(Event.classification == classification)

    if anomalies_only:
        query = query.where(Event.is_anomaly.is_(True))

    query = query.order_by(Event.event_time.asc(), Event.id.asc())

    events = db.session.scalars(query).all()

    return jsonify({
        "case": {
            "id": case.id,
            "case_number": case.case_number,
            "title": case.title
        },
        "events": [
            {
                "id": event.id,
                "start": event.event_time.isoformat(),
                "content": f"{event.classification or event.event_type}: "
                           f"{event.message[:160]}",
                "event_type": event.event_type,
                "classification": event.classification,
                "host": event.host,
                "username": event.username,
                "source_ip": event.source_ip,
                "destination_ip": event.destination_ip,
                "message": event.message,
                "metadata": event.metadata,
                "is_anomaly": event.is_anomaly,
                "anomaly_score": event.anomaly_score
            }
            for event in events
        ]
    })

@events_bp.post("/cases/<int:case_id>/reanalyze")
@roles_required("ADMIN", "ANALYST")
def reanalyze(case_id):
    if db.session.get(Case, case_id) is None:
        return jsonify({"error": "case not found"}), 404

    result = analyze_case(case_id)
    audit("REANALYZE_CASE", "CASE", case_id, result)

    return jsonify(result)

@events_bp.get("/cases/<int:case_id>/relationships")
@roles_required("ADMIN", "ANALYST", "VIEWER")
def relationships(case_id):
    items = db.session.scalars(
        select(TimelineRelationship)
        .where(TimelineRelationship.case_id == case_id)
        .order_by(TimelineRelationship.id.asc())
    ).all()

    return jsonify([
        {
            "id": item.id,
            "from": item.from_event_id,
            "to": item.to_event_id,
            "type": item.relationship_type,
            "confidence": item.confidence
        }
        for item in items
    ])