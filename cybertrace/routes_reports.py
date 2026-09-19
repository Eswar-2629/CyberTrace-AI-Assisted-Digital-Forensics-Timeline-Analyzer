import csv
import io
import json
from flask import Blueprint, Response, jsonify, request
from sqlalchemy import select

from .audit import audit
from .extensions import db
from .models import Case, Event
from .security import roles_required

reports_bp = Blueprint("reports", __name__)

@reports_bp.get("/cases/<int:case_id>")
@roles_required("ADMIN", "ANALYST", "VIEWER")
def export_report(case_id):
    case = db.session.get(Case, case_id)

    if case is None:
        return jsonify({"error": "case not found"}), 404

    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow([
        "event_id",
        "event_time",
        "event_type",
        "classification",
        "host",
        "username",
        "source_ip",
        "destination_ip",
        "is_anomaly",
        "anomaly_score",
        "message"
    ])

    events = db.session.scalars(
        select(Event)
        .where(Event.case_id == case_id)
        .order_by(Event.event_time.asc(), Event.id.asc())
    ).all()

    for event in events:
        writer.writerow([
            event.id,
            event.event_time.isoformat(),
            event.event_type,
            event.classification,
            event.host,
            event.username,
            event.source_ip,
            event.destination_ip,
            event.is_anomaly,
            event.anomaly_score,
            event.message
        ])

    audit("EXPORT_REPORT", "CASE", case_id, {
        "format": "csv",
        "event_count": len(events)
    })

    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={
            "Content-Disposition":
                f"attachment; filename=cybertrace-case-{case_id}.csv"
        }
    )