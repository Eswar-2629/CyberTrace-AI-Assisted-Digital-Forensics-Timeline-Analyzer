from flask import Flask, jsonify, render_template
from flask_cors import CORS
from werkzeug.exceptions import RequestEntityTooLarge

from .config import Config
from .extensions import db, migrate, jwt
from .routes_auth import auth_bp
from .routes_cases import cases_bp
from .routes_events import events_bp
from .routes_reports import reports_bp

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    db.init_app(app)
    migrate.init_app(app, db)
    jwt.init_app(app)

    CORS(
        app,
        resources={r"/api/*": {
            "origins": app.config["CORS_ORIGINS"].split(",")
        }}
    )

    app.register_blueprint(auth_bp, url_prefix="/api/auth")
    app.register_blueprint(cases_bp, url_prefix="/api/cases")
    app.register_blueprint(events_bp, url_prefix="/api/events")
    app.register_blueprint(reports_bp, url_prefix="/api/reports")

    @app.get("/")
    def home():
        return render_template("login.html")

    @app.get("/dashboard")
    def dashboard():
        return render_template("dashboard.html")

    @app.errorhandler(RequestEntityTooLarge)
    def too_large(_error):
        return jsonify({"error": "uploaded evidence exceeds size limit"}), 413

    @app.errorhandler(404)
    def not_found(_error):
        return jsonify({"error": "resource not found"}), 404

    @app.errorhandler(500)
    def server_error(_error):
        db.session.rollback()
        return jsonify({"error": "internal server error"}), 500

    return app