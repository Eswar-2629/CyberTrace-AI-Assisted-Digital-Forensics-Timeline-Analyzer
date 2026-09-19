from flask import Blueprint, jsonify, request
from flask_jwt_extended import get_jwt_identity
from sqlalchemy import select

from .audit import audit
from .extensions import db
from .models import Case
from .security import roles_required

cases_bp = Blueprint("cases", __name__)

@cases_bp.post("")
@roles_required("ADMIN", "ANALYST")
def create_case():
    data = request.get_json(silent=True) or {}

    case_number = str(data.get("case_number", "")).strip()
    title = str(data.get("title", "")).strip()

    if not case_number or not title:
        return jsonify({"error": "case_number and title are required"}), 400

    if db.session.scalar(
        select(Case).where(Case.case_number == case_number)
    ):
        return jsonify({"error": "case number already exists"}), 409

    case = Case(
        case_number=case_number,
        title=title,
        description=data.get("description"),
        created_by=int(get_jwt_identity())
    )

    db.session.add(case)
    db.session.commit()

    audit("CREATE_CASE", "CASE", case.id, {
        "case_number": case.case_number
    })

    return jsonify({
        "id": case.id,
        "case_number": case.case_number,
        "title": case.title,
        "status": case.status
    }), 201

@cases_bp.get("")
@roles_required("ADMIN", "ANALYST", "VIEWER")
def list_cases():
    cases = db.session.scalars(
        select(Case).order_by(Case.created_at.desc())
    ).all()

    return jsonify([
        {
            "id": item.id,
            "case_number": item.case_number,
            "title": item.title,
            "description": item.description,
            "status": item.status,
            "created_at": item.created_at.isoformat()
        }
        for item in cases
    ])

@cases_bp.get("/<int:case_id>")
@roles_required("ADMIN", "ANALYST", "VIEWER")
def get_case(case_id):
    case = db.session.get(Case, case_id)

    if case is None:
        return jsonify({"error": "case not found"}), 404

    return jsonify({
        "id": case.id,
        "case_number": case.case_number,
        "title": case.title,
        "description": case.description,
        "status": case.status,
        "created_at": case.created_at.isoformat()
    })