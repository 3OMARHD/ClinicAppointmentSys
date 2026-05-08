"""
Appointment Service — Middleware
JWT verification and RBAC decorators (shared logic with auth-service).
"""

import jwt
import os
from functools import wraps
from flask import request, jsonify, g

JWT_SECRET = os.environ.get("JWT_SECRET_KEY", "default-secret-key")
INTERNAL_API_KEY = os.environ.get("INTERNAL_API_KEY", "default-internal-key")


def decode_token(token):
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return None


def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return jsonify({"error": "Authentication required", "message": "Missing authorization token"}), 401
        token = auth_header.split(" ", 1)[1]
        payload = decode_token(token)
        if not payload:
            return jsonify({"error": "Authentication failed", "message": "Invalid or expired token"}), 401
        g.current_user = payload
        return f(*args, **kwargs)
    return decorated


def require_role(*roles):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if not hasattr(g, "current_user"):
                return jsonify({"error": "Authentication required"}), 401
            if g.current_user.get("role") not in roles:
                return jsonify({"error": "Access denied", "message": f"Requires role: {', '.join(roles)}"}), 403
            return f(*args, **kwargs)
        return decorated
    return decorator


def require_internal_key(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        api_key = request.headers.get("X-Internal-Key", "")
        if not api_key or api_key != INTERNAL_API_KEY:
            return jsonify({"error": "Forbidden", "message": "Invalid internal API key"}), 403
        return f(*args, **kwargs)
    return decorated


def get_client_ip():
    if request.headers.get("X-Forwarded-For"):
        return request.headers.get("X-Forwarded-For").split(",")[0].strip()
    if request.headers.get("X-Real-IP"):
        return request.headers.get("X-Real-IP")
    return request.remote_addr
