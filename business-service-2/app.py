"""
Notification Service (business-service-2) — Main Application
Handles user notifications for appointments and system events.
"""

import os
import logging
from datetime import datetime
from flask import Flask, request, jsonify, g
from flask_cors import CORS
from models import get_db_session, Notification
from middleware import require_auth, require_role, require_internal_key

app = Flask(__name__)
CORS(app)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


@app.route("/api/notifications/health", methods=["GET"])
def health():
    return jsonify({"status": "healthy", "service": "notification-service"}), 200


@app.route("/api/notifications/", methods=["POST"])
@require_internal_key
def create_notification():
    """Internal: Create a notification (called by worker service)."""
    data = request.get_json()
    if not data:
        return jsonify({"error": "Request body must be JSON"}), 400

    required = ["user_id", "type", "title", "message"]
    for field in required:
        if not data.get(field):
            return jsonify({"error": f"{field} is required"}), 400

    db = get_db_session()
    try:
        notif = Notification(
            user_id=data["user_id"], type=data["type"],
            title=data["title"], message=data["message"]
        )
        db.add(notif)
        db.commit()
        db.refresh(notif)

        logger.info(f"Notification created for user {data['user_id']}: {data['type']}")
        return jsonify({"message": "Notification created", "notification": notif.to_dict()}), 201
    except Exception as e:
        db.rollback()
        logger.error(f"Create notification error: {e}")
        return jsonify({"error": "Internal server error"}), 500
    finally:
        db.close()


@app.route("/api/notifications/", methods=["GET"])
@require_auth
def list_notifications():
    """Get current user's notifications."""
    db = get_db_session()
    try:
        uid = g.current_user["user_id"]
        role = g.current_user["role"]

        if role == "admin":
            notifs = db.query(Notification).order_by(Notification.created_at.desc()).limit(100).all()
        else:
            notifs = db.query(Notification).filter(
                Notification.user_id == uid
            ).order_by(Notification.created_at.desc()).all()

        unread = sum(1 for n in notifs if not n.is_read)
        return jsonify({
            "notifications": [n.to_dict() for n in notifs],
            "total": len(notifs), "unread": unread
        }), 200
    finally:
        db.close()


@app.route("/api/notifications/<int:notif_id>/read", methods=["PUT"])
@require_auth
def mark_as_read(notif_id):
    """Mark a notification as read."""
    db = get_db_session()
    try:
        notif = db.query(Notification).filter(Notification.id == notif_id).first()
        if not notif:
            return jsonify({"error": "Notification not found"}), 404

        if g.current_user["role"] != "admin" and notif.user_id != g.current_user["user_id"]:
            return jsonify({"error": "Access denied"}), 403

        notif.is_read = True
        notif.read_at = datetime.utcnow()
        db.commit()
        return jsonify({"message": "Marked as read", "notification": notif.to_dict()}), 200
    except Exception as e:
        db.rollback()
        logger.error(f"Mark read error: {e}")
        return jsonify({"error": "Internal server error"}), 500
    finally:
        db.close()


@app.route("/api/notifications/stats", methods=["GET"])
@require_auth
@require_role("admin")
def notification_stats():
    """Admin: Get notification statistics."""
    db = get_db_session()
    try:
        from sqlalchemy import func
        total = db.query(func.count(Notification.id)).scalar()
        unread = db.query(func.count(Notification.id)).filter(Notification.is_read == False).scalar()
        by_type = db.query(
            Notification.type, func.count(Notification.id)
        ).group_by(Notification.type).all()

        return jsonify({
            "total_notifications": total,
            "unread_notifications": unread,
            "by_type": {t: c for t, c in by_type}
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
    app.run(host="0.0.0.0", port=5002, debug=False)
