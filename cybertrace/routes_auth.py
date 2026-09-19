from argon2 import PasswordHasher
from flask import Blueprint, jsonify, request
from flask_jwt_extended import create_access_token

from .audit import audit
from .extensions import db
from .models import User

auth_bp = Blueprint("auth", __name__)
password_hasher = PasswordHasher()

@auth_bp.post("/register")
def register():
    data = request.get_json(silent=True) or {}

    username = str(data.get("username", "")).strip()
    password = str(data.get("password", ""))

    if len(username) < 3 or len(password) < 12:
        return jsonify({
            "error": "username must have 3+ characters and password 12+ characters"
        }), 400

    if User.query.filter_by(username=username).first():
        return jsonify({"error": "username already exists"}), 409

    user = User(
        username=username,
        password_hash=password_hasher.hash(password),
        role="VIEWER"
    )

    db.session.add(user)
    db.session.commit()

    return jsonify({"id": user.id, "username": user.username}), 201

@auth_bp.post("/login")
def login():
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", ""))

    user = User.query.filter_by(username=username, is_active=True).first()

    if user is None:
        return jsonify({"error": "invalid credentials"}), 401

    try:
        password_hasher.verify(user.password_hash, password)
    except Exception:
        return jsonify({"error": "invalid credentials"}), 401

    token = create_access_token(
        identity=str(user.id),
        additional_claims={
            "username": user.username,
            "role": user.role
        }
    )

    audit("LOGIN", "USER", user.id, {"username": user.username})

    return jsonify({
        "access_token": token,
        "user": {
            "id": user.id,
            "username": user.username,
            "role": user.role
        }
    })