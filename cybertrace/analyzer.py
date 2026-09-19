import re
from datetime import timedelta

import numpy as np
from sklearn.ensemble import IsolationForest
from sqlalchemy import select

from .extensions import db
from .models import Event, TimelineRelationship

CLASS_RULES = {
    "AUTHENTICATION": [
        "login", "logon", "authentication", "password", "4624", "4625"
    ],
    "NETWORK": [
        "tcp", "udp", "connection", "firewall", "dns", "http", "ssh"
    ],
    "FILE_ACTIVITY": [
        "created", "deleted", "modified", "renamed", "file", "sha256"
    ],
    "REGISTRY_ACTIVITY": [
        "registry", "regedit", "hkey_local_machine", "hkey_current_user"
    ],
    "PERSISTENCE": [
        "scheduled task", "service", "startup", "autorun", "run key"
    ],
    "MALWARE_INDICATOR": [
        "malware", "ransomware", "trojan", "suspicious", "encoded", "powershell"
    ],
}

def normalize_text(text):
    return re.sub(r"\s+", " ", text.lower()).strip()

def classify_event(event_type, message):
    text = normalize_text(f"{event_type} {message}")

    for category, terms in CLASS_RULES.items():
        if any(term in text for term in terms):
            return category

    return "OTHER"

def event_features(event):
    metadata = event.metadata or {}
    return [
        event.event_time.hour,
        event.event_time.weekday(),
        len(event.message or ""),
        int(bool(event.source_ip)),
        int(bool(event.destination_ip)),
        float(metadata.get("bytes", 0) or 0),
        float(metadata.get("risk_hint", 0) or 0),
    ]

def analyze_case(case_id):
    events = db.session.scalars(
        select(Event)
        .where(Event.case_id == case_id)
        .order_by(Event.event_time.asc(), Event.id.asc())
    ).all()

    if not events:
        return {"events": 0, "relationships": 0}

    for event in events:
        event.normalized_text = normalize_text(event.message)
        event.classification = classify_event(
            event.event_type,
            event.message
        )

    matrix = np.array([event_features(event) for event in events], dtype=float)

    if len(events) >= 8:
        model = IsolationForest(
            n_estimators=150,
            contamination="auto",
            random_state=42
        )
        labels = model.fit_predict(matrix)
        scores = model.score_samples(matrix)

        for event, label, score in zip(events, labels, scores):
            event.is_anomaly = bool(label == -1)
            event.anomaly_score = float(score)
    else:
        for event in events:
            event.is_anomaly = False
            event.anomaly_score = None

    existing = db.session.scalars(
        select(TimelineRelationship).where(
            TimelineRelationship.case_id == case_id
        )
    ).all()

    existing_keys = {
        (item.from_event_id, item.to_event_id, item.relationship_type)
        for item in existing
    }

    relationship_count = 0

    for previous, current in zip(events, events[1:]):
        delta = current.event_time - previous.event_time

        if delta < timedelta(hours=24):
            if previous.host and current.host and previous.host == current.host:
                relationship_type = "SAME_HOST"
                confidence = 0.85
            elif previous.username and current.username and previous.username == current.username:
                relationship_type = "SAME_USER"
                confidence = 0.80
            elif previous.source_ip and current.source_ip and previous.source_ip == current.source_ip:
                relationship_type = "SAME_SOURCE_IP"
                confidence = 0.90
            else:
                relationship_type = "TEMPORAL_PROXIMITY"
                confidence = 0.55

            key = (previous.id, current.id, relationship_type)

            if key not in existing_keys:
                db.session.add(TimelineRelationship(
                    case_id=case_id,
                    from_event_id=previous.id,
                    to_event_id=current.id,
                    relationship_type=relationship_type,
                    confidence=confidence
                ))
                relationship_count += 1

    db.session.commit()

    return {
        "events": len(events),
        "relationships": relationship_count,
        "anomalies": sum(1 for item in events if item.is_anomaly),
    }