import csv
import io
import json
from datetime import datetime, timezone

import dateparser

from .extensions import db
from .models import Event
from .analyzer import analyze_case

def parse_timestamp(value):
    if not value:
        return datetime.now(timezone.utc)

    parsed = dateparser.parse(str(value))

    if parsed is None:
        return datetime.now(timezone.utc)

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)

    return parsed.astimezone(timezone.utc)

def clean(value):
    return None if value in ("", None) else str(value)

def make_event(case_id, evidence_id, row):
    message = str(
        row.get("message")
        or row.get("description")
        or json.dumps(row, sort_keys=True)
    )

    known = {
        "timestamp", "event_time", "event_type", "type", "source",
        "host", "username", "source_ip", "destination_ip",
        "file_path", "registry_path", "message", "description"
    }

    metadata = {
        key: value
        for key, value in row.items()
        if key not in known
    }

    return Event(
        case_id=case_id,
        evidence_file_id=evidence_id,
        event_time=parse_timestamp(row.get("timestamp") or row.get("event_time")),
        event_type=str(row.get("event_type") or row.get("type") or "UNKNOWN"),
        source=clean(row.get("source")),
        host=clean(row.get("host")),
        username=clean(row.get("username")),
        source_ip=clean(row.get("source_ip")),
        destination_ip=clean(row.get("destination_ip")),
        file_path=clean(row.get("file_path")),
        registry_path=clean(row.get("registry_path")),
        message=message[:100000],
        metadata=metadata
    )

def parse_evidence(content, filename, case_id, evidence_id):
    name = filename.lower()
    events = []

    if name.endswith(".jsonl"):
        for line in content.decode("utf-8-sig").splitlines():
            if line.strip():
                events.append(make_event(
                    case_id,
                    evidence_id,
                    json.loads(line)
                ))

    elif name.endswith(".json"):
        payload = json.loads(content.decode("utf-8-sig"))
        rows = payload if isinstance(payload, list) else payload.get("events", [])
        events = [
            make_event(case_id, evidence_id, row)
            for row in rows
        ]

    elif name.endswith(".csv"):
        text = content.decode("utf-8-sig")
        reader = csv.DictReader(io.StringIO(text))
        events = [
            make_event(case_id, evidence_id, row)
            for row in reader
        ]

    else:
        for line in content.decode("utf-8", errors="replace").splitlines():
            if line.strip():
                events.append(make_event(
                    case_id,
                    evidence_id,
                    {
                        "timestamp": None,
                        "event_type": "TEXT_LOG",
                        "message": line
                    }
                ))

    db.session.add_all(events)
    db.session.commit()

    return analyze_case(case_id)