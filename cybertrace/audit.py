from flask import request
from flask_jwt_extended import get_jwt_identity
from .extensions import db
from .models import AuditLog

def audit(action, resource_type=None, resource_id=None, details=None):
    identity = get_jwt_identity()

    item = AuditLog(
        user_id=int(identity) if identity else None,
        action=action,
        resource_type=resource_type,
        resource_id=str(resource_id) if resource_id is not None else None,
        ip_address=request.remote_addr,
        details=details or {}
    )

    db.session.add(item)
    db.session.commit()