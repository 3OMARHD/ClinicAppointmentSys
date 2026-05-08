"""
Logging/Audit Service — Main Application
Centralized audit logging and monitoring dashboard API.
"""

import os
import logging
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, g
from flask_cors import CORS
from sqlalchemy import func
from models import get_db_session, AuditLog

app = Flask(__name__)
CORS(app)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

JWT_SECRET = os.environ.get("JWT_SECRET_KEY", "default-secret-key")
INTERNAL_API_KEY = os.environ.get("INTERNAL_API_KEY", "default-internal-key")


# ---- Middleware ----
import jwt
from functools import wraps


def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return jsonify({"error": "Authentication required"}), 401
        token = auth_header.split(" ", 1)[1]
        try:
            payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
            g.current_user = payload
        except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
            return jsonify({"error": "Invalid or expired token"}), 401
        return f(*args, **kwargs)
    return decorated


def require_admin(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not hasattr(g, "current_user") or g.current_user.get("role") != "admin":
            return jsonify({"error": "Admin access required"}), 403
        return f(*args, **kwargs)
    return decorated


def require_internal_key(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        api_key = request.headers.get("X-Internal-Key", "")
        if not api_key or api_key != INTERNAL_API_KEY:
            return jsonify({"error": "Forbidden"}), 403
        return f(*args, **kwargs)
    return decorated


# ---- Endpoints ----

@app.route("/api/logs/health", methods=["GET"])
def health():
    return jsonify({"status": "healthy", "service": "logging-service"}), 200


@app.route("/api/logs/", methods=["POST"])
@require_internal_key
def create_log():
    """Internal: Create an audit log entry."""
    data = request.get_json()
    if not data or not data.get("action"):
        return jsonify({"error": "action is required"}), 400

    db = get_db_session()
    try:
        log = AuditLog(
            user_id=data.get("user_id"),
            action=data["action"],
            resource=data.get("resource", ""),
            ip_address=data.get("ip_address", ""),
            status=data.get("status", "success"),
            details=data.get("details", "")
        )
        db.add(log)
        db.commit()
        return jsonify({"message": "Log created"}), 201
    except Exception as e:
        db.rollback()
        logger.error(f"Create log error: {e}")
        return jsonify({"error": "Internal server error"}), 500
    finally:
        db.close()


@app.route("/api/logs/", methods=["GET"])
@require_auth
@require_admin
def list_logs():
    """Admin: Query audit logs with filters."""
    db = get_db_session()
    try:
        query = db.query(AuditLog)

        # Filters
        action = request.args.get("action")
        user_id = request.args.get("user_id")
        status = request.args.get("status")
        resource = request.args.get("resource")
        limit = min(int(request.args.get("limit", 50)), 200)
        offset = int(request.args.get("offset", 0))

        if action:
            query = query.filter(AuditLog.action.ilike(f"%{action}%"))
        if user_id:
            query = query.filter(AuditLog.user_id == int(user_id))
        if status:
            query = query.filter(AuditLog.status == status)
        if resource:
            query = query.filter(AuditLog.resource == resource)

        total = query.count()
        logs = query.order_by(AuditLog.timestamp.desc()).offset(offset).limit(limit).all()

        return jsonify({
            "logs": [l.to_dict() for l in logs],
            "total": total, "limit": limit, "offset": offset
        }), 200
    finally:
        db.close()


@app.route("/api/logs/dashboard", methods=["GET"])
@require_auth
@require_admin
def dashboard():
    """Admin: Monitoring dashboard data."""
    db = get_db_session()
    try:
        now = datetime.utcnow()
        last_24h = now - timedelta(hours=24)
        last_7d = now - timedelta(days=7)

        # Total counts
        total_logs = db.query(func.count(AuditLog.id)).scalar()

        # Last 24 hours
        logs_24h = db.query(func.count(AuditLog.id)).filter(
            AuditLog.timestamp >= last_24h).scalar()

        # Login stats
        successful_logins = db.query(func.count(AuditLog.id)).filter(
            AuditLog.action == "user.login", AuditLog.status == "success").scalar()
        failed_logins = db.query(func.count(AuditLog.id)).filter(
            AuditLog.action == "user.login_failed").scalar()

        # Registrations
        registrations = db.query(func.count(AuditLog.id)).filter(
            AuditLog.action == "user.registered").scalar()

        # File operations
        file_uploads = db.query(func.count(AuditLog.id)).filter(
            AuditLog.action == "file.uploaded").scalar()
        file_downloads = db.query(func.count(AuditLog.id)).filter(
            AuditLog.action == "file.downloaded").scalar()

        # Unauthorized attempts
        unauthorized = db.query(func.count(AuditLog.id)).filter(
            AuditLog.status == "failure").scalar()

        # Appointments
        appt_created = db.query(func.count(AuditLog.id)).filter(
            AuditLog.action == "appointment.created").scalar()
        appt_cancelled = db.query(func.count(AuditLog.id)).filter(
            AuditLog.action == "appointment.cancelled").scalar()

        # Recent activity (last 10)
        recent = db.query(AuditLog).order_by(
            AuditLog.timestamp.desc()).limit(10).all()

        # Actions breakdown
        actions_breakdown = db.query(
            AuditLog.action, func.count(AuditLog.id)
        ).group_by(AuditLog.action).order_by(func.count(AuditLog.id).desc()).limit(15).all()

        return jsonify({
            "summary": {
                "total_events": total_logs,
                "events_last_24h": logs_24h,
                "successful_logins": successful_logins,
                "failed_logins": failed_logins,
                "registrations": registrations,
                "file_uploads": file_uploads,
                "file_downloads": file_downloads,
                "unauthorized_attempts": unauthorized,
                "appointments_created": appt_created,
                "appointments_cancelled": appt_cancelled
            },
            "actions_breakdown": {a: c for a, c in actions_breakdown},
            "recent_activity": [l.to_dict() for l in recent]
        }), 200
    finally:
        db.close()


@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Not found"}), 404

@app.errorhandler(500)
def internal_error(e):
    return jsonify({"error": "Internal server error"}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5003, debug=False)
