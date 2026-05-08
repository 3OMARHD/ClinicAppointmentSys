"""
Auth Service — Middleware
JWT verification, RBAC decorators, and internal API key validation.
"""

import jwt
import os
from functools import wraps
from flask import request, jsonify, g
from models import get_db_session, User

JWT_SECRET = os.environ.get("JWT_SECRET_KEY", "default-secret-key")
INTERNAL_API_KEY = os.environ.get("INTERNAL_API_KEY", "default-internal-key")


def decode_token(token):
    """Decode and validate a JWT token."""
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


def require_auth(f):
    """Decorator to require valid JWT authentication."""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        # Extract token from Authorization header
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header.split(" ", 1)[1]

        if not token:
            return jsonify({"error": "Authentication required", "message": "Missing authorization token"}), 401

        payload = decode_token(token)
        if not payload:
            return jsonify({"error": "Authentication failed", "message": "Invalid or expired token"}), 401

        # Load user from database
        db = get_db_session()
        try:
            user = db.query(User).filter(User.id == payload.get("user_id")).first()
            if not user:
                return jsonify({"error": "Authentication failed", "message": "User not found"}), 401
            if not user.is_active:
                return jsonify({"error": "Account disabled", "message": "Your account has been deactivated"}), 403

            g.current_user = user
            g.db = db
        except Exception:
            db.close()
            return jsonify({"error": "Internal server error"}), 500

        result = f(*args, **kwargs)
        db.close()
        return result

    return decorated


def require_role(*roles):
    """Decorator to require specific roles (must be used after @require_auth)."""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if not hasattr(g, "current_user"):
                return jsonify({"error": "Authentication required"}), 401

            if g.current_user.role not in roles:
                return jsonify({
                    "error": "Access denied",
                    "message": f"This endpoint requires one of the following roles: {', '.join(roles)}"
                }), 403

            return f(*args, **kwargs)
        return decorated
    return decorator


def require_internal_key(f):
    """Decorator to require internal API key for service-to-service calls."""
    @wraps(f)
    def decorated(*args, **kwargs):
        api_key = request.headers.get("X-Internal-Key", "")

        if not api_key or api_key != INTERNAL_API_KEY:
            return jsonify({"error": "Forbidden", "message": "Invalid internal API key"}), 403

        return f(*args, **kwargs)
    return decorated


def get_client_ip():
    """Get the real client IP, considering proxy headers."""
    if request.headers.get("X-Forwarded-For"):
        return request.headers.get("X-Forwarded-For").split(",")[0].strip()
    if request.headers.get("X-Real-IP"):
        return request.headers.get("X-Real-IP")
    return request.remote_addr
