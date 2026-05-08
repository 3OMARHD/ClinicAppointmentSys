"""
Notification Service — Middleware
JWT verification and RBAC decorators.
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
            return jsonify({"error": "Authentication required"}), 401
        token = auth_header.split(" ", 1)[1]
        payload = decode_token(token)
        if not payload:
            return jsonify({"error": "Invalid or expired token"}), 401
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
                return jsonify({"error": "Access denied"}), 403
            return f(*args, **kwargs)
        return decorated
    return decorator


def require_internal_key(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        api_key = request.headers.get("X-Internal-Key", "")
        if not api_key or api_key != INTERNAL_API_KEY:
            return jsonify({"error": "Forbidden"}), 403
        return f(*args, **kwargs)
    return decorated
