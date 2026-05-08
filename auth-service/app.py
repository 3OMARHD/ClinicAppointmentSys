"""
Auth Service — Main Application
Handles user registration, login, JWT authentication, OAuth, and user management.
"""

import os
import jwt
import bcrypt
import pika
import json
import requests
import logging
from datetime import datetime, timedelta, timezone
from flask import Flask, request, jsonify, redirect, g
from flask_cors import CORS
from models import get_db_session, User
from middleware import require_auth, require_role, require_internal_key, get_client_ip
from validators import validate_registration, validate_login

# ---- Configuration ----
app = Flask(__name__)
CORS(app)

# Configure logging — never log passwords
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

JWT_SECRET = os.environ.get("JWT_SECRET_KEY", "default-secret-key")
JWT_EXPIRY_HOURS = int(os.environ.get("JWT_EXPIRY_HOURS", "1"))
RABBITMQ_URL = os.environ.get("RABBITMQ_URL", "amqp://guest:guest@rabbitmq:5672/")
INTERNAL_API_KEY = os.environ.get("INTERNAL_API_KEY", "default-internal-key")
LOGGING_SERVICE_URL = os.environ.get("LOGGING_SERVICE_URL", "http://logging-service:5003")

# GitHub OAuth
GITHUB_CLIENT_ID = os.environ.get("GITHUB_CLIENT_ID", "")
GITHUB_CLIENT_SECRET = os.environ.get("GITHUB_CLIENT_SECRET", "")


# ---- Helper Functions ----

def generate_token(user):
    """Generate a JWT token for a user."""
    payload = {
        "user_id": user.id,
        "email": user.email,
        "username": user.username,
        "role": user.role,
        "iat": datetime.now(timezone.utc),
        "exp": datetime.now(timezone.utc) + timedelta(hours=JWT_EXPIRY_HOURS)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")


def hash_password(password):
    """Hash a password using bcrypt."""
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def check_password(password, password_hash):
    """Verify a password against its hash."""
    return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))


def publish_event(event_type, data):
    """Publish an event to RabbitMQ."""
    try:
        connection = pika.BlockingConnection(pika.URLParameters(RABBITMQ_URL))
        channel = connection.channel()
        channel.queue_declare(queue="audit_queue", durable=True)
        message = json.dumps({"event": event_type, "data": data, "timestamp": datetime.utcnow().isoformat()})
        channel.basic_publish(
            exchange="",
            routing_key="audit_queue",
            body=message,
            properties=pika.BasicProperties(delivery_mode=2)  # Persistent
        )
        connection.close()
    except Exception as e:
        logger.error(f"Failed to publish event to RabbitMQ: {str(e)}")


def send_audit_log(user_id, action, resource, ip_address, status, details=""):
    """Send audit log to the logging service."""
    try:
        requests.post(
            f"{LOGGING_SERVICE_URL}/api/logs/",
            json={
                "user_id": user_id,
                "action": action,
                "resource": resource,
                "ip_address": ip_address,
                "status": status,
                "details": details
            },
            headers={"X-Internal-Key": INTERNAL_API_KEY},
            timeout=5
        )
    except Exception as e:
        logger.error(f"Failed to send audit log: {str(e)}")


# ---- Health Check ----

@app.route("/api/auth/health", methods=["GET"])
def health():
    """Health check endpoint."""
    return jsonify({"status": "healthy", "service": "auth-service"}), 200


# ---- Registration ----

@app.route("/api/auth/register", methods=["POST"])
def register():
    """Register a new user."""
    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid request", "message": "Request body must be JSON"}), 400

    # Validate input
    valid, errors = validate_registration(data)
    if not valid:
        return jsonify({"error": "Validation failed", "messages": errors}), 400

    db = get_db_session()
    try:
        # Check if email already exists
        existing = db.query(User).filter(
            (User.email == data["email"]) | (User.username == data["username"])
        ).first()
        if existing:
            if existing.email == data["email"]:
                return jsonify({"error": "Conflict", "message": "Email already registered"}), 409
            return jsonify({"error": "Conflict", "message": "Username already taken"}), 409

        # Create user with hashed password
        user = User(
            email=data["email"],
            username=data["username"],
            password_hash=hash_password(data["password"]),
            role=data.get("role", "patient")
        )
        db.add(user)
        db.commit()
        db.refresh(user)

        # Generate token
        token = generate_token(user)

        # Log the event
        client_ip = get_client_ip()
        send_audit_log(user.id, "user.registered", "auth", client_ip, "success",
                       f"New user registered: {user.username} ({user.role})")
        publish_event("user.registered", {"user_id": user.id, "username": user.username, "role": user.role})

        logger.info(f"User registered: {user.username} (role: {user.role})")

        return jsonify({
            "message": "Registration successful",
            "user": user.to_dict(),
            "token": token
        }), 201

    except Exception as e:
        db.rollback()
        logger.error(f"Registration error: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500
    finally:
        db.close()


# ---- Login ----

@app.route("/api/auth/login", methods=["POST"])
def login():
    """Login with email and password."""
    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid request", "message": "Request body must be JSON"}), 400

    # Validate input
    valid, errors = validate_login(data)
    if not valid:
        return jsonify({"error": "Validation failed", "messages": errors}), 400

    client_ip = get_client_ip()
    db = get_db_session()
    try:
        user = db.query(User).filter(User.email == data["email"]).first()

        if not user or not user.password_hash:
            send_audit_log(None, "user.login_failed", "auth", client_ip, "failure",
                           f"Login attempt with unknown email: {data['email']}")
            return jsonify({"error": "Authentication failed", "message": "Invalid email or password"}), 401

        if not check_password(data["password"], user.password_hash):
            send_audit_log(user.id, "user.login_failed", "auth", client_ip, "failure",
                           f"Invalid password for user: {user.username}")
            return jsonify({"error": "Authentication failed", "message": "Invalid email or password"}), 401

        if not user.is_active:
            return jsonify({"error": "Account disabled", "message": "Your account has been deactivated"}), 403

        # Generate token
        token = generate_token(user)

        # Log successful login
        send_audit_log(user.id, "user.login", "auth", client_ip, "success",
                       f"User logged in: {user.username}")
        publish_event("user.login", {"user_id": user.id, "username": user.username})

        logger.info(f"User logged in: {user.username}")

        return jsonify({
            "message": "Login successful",
            "user": user.to_dict(),
            "token": token
        }), 200

    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500
    finally:
        db.close()


# ---- OAuth (GitHub) ----

@app.route("/api/auth/oauth/github", methods=["GET"])
def github_oauth_redirect():
    """Redirect user to GitHub for OAuth login."""
    if not GITHUB_CLIENT_ID or GITHUB_CLIENT_ID.startswith("your_"):
        return jsonify({
            "error": "OAuth not configured",
            "message": "GitHub OAuth client ID is not set. See .env file for setup instructions.",
            "setup_steps": [
                "1. Go to https://github.com/settings/developers",
                "2. Click 'New OAuth App'",
                "3. Set Homepage URL to https://localhost",
                "4. Set Callback URL to https://localhost/api/auth/oauth/github/callback",
                "5. Copy Client ID and Secret to .env file",
                "6. Restart the auth-service container"
            ]
        }), 501

    github_auth_url = (
        f"https://github.com/login/oauth/authorize"
        f"?client_id={GITHUB_CLIENT_ID}"
        f"&scope=user:email"
        f"&redirect_uri=https://localhost/api/auth/oauth/github/callback"
    )
    return jsonify({"redirect_url": github_auth_url}), 200


@app.route("/api/auth/oauth/github/callback", methods=["GET", "POST"])
def github_oauth_callback():
    """Handle GitHub OAuth callback."""
    code = request.args.get("code") or (request.get_json() or {}).get("code")
    if not code:
        return jsonify({"error": "Missing authorization code"}), 400

    if not GITHUB_CLIENT_ID or not GITHUB_CLIENT_SECRET:
        return jsonify({"error": "OAuth not configured"}), 501

    try:
        # Exchange code for access token
        token_response = requests.post(
            "https://github.com/login/oauth/access_token",
            json={
                "client_id": GITHUB_CLIENT_ID,
                "client_secret": GITHUB_CLIENT_SECRET,
                "code": code
            },
            headers={"Accept": "application/json"},
            timeout=10
        )
        token_data = token_response.json()
        access_token = token_data.get("access_token")

        if not access_token:
            return jsonify({"error": "Failed to get access token from GitHub"}), 400

        # Get user info from GitHub
        user_response = requests.get(
            "https://api.github.com/user",
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=10
        )
        github_user = user_response.json()

        # Get email
        email_response = requests.get(
            "https://api.github.com/user/emails",
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=10
        )
        emails = email_response.json()
        primary_email = next((e["email"] for e in emails if e.get("primary")), None)

        if not primary_email:
            return jsonify({"error": "Could not retrieve email from GitHub"}), 400

        github_id = str(github_user.get("id"))
        username = github_user.get("login", f"github_{github_id}")

        db = get_db_session()
        try:
            # Check if user exists with this OAuth ID
            user = db.query(User).filter(
                User.oauth_provider == "github",
                User.oauth_id == github_id
            ).first()

            if not user:
                # Check if email already exists
                user = db.query(User).filter(User.email == primary_email).first()
                if user:
                    # Link existing account
                    user.oauth_provider = "github"
                    user.oauth_id = github_id
                else:
                    # Create new user
                    user = User(
                        email=primary_email,
                        username=username,
                        role="patient",
                        oauth_provider="github",
                        oauth_id=github_id
                    )
                    db.add(user)

                db.commit()
                db.refresh(user)

            # Generate JWT
            token = generate_token(user)

            client_ip = get_client_ip()
            send_audit_log(user.id, "user.oauth_login", "auth", client_ip, "success",
                           f"OAuth login via GitHub: {user.username}")

            return jsonify({
                "message": "OAuth login successful",
                "user": user.to_dict(),
                "token": token
            }), 200

        finally:
            db.close()

    except requests.RequestException as e:
        logger.error(f"GitHub OAuth error: {str(e)}")
        return jsonify({"error": "Failed to communicate with GitHub"}), 502
    except Exception as e:
        logger.error(f"OAuth error: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500


# ---- Protected Endpoints ----

@app.route("/api/auth/me", methods=["GET"])
@require_auth
def get_me():
    """Get current user profile."""
    return jsonify({"user": g.current_user.to_dict()}), 200


@app.route("/api/auth/users", methods=["GET"])
@require_auth
@require_role("admin")
def list_users():
    """Admin only: List all users."""
    db = get_db_session()
    try:
        users = db.query(User).all()
        return jsonify({
            "users": [u.to_dict() for u in users],
            "total": len(users)
        }), 200
    finally:
        db.close()


@app.route("/api/auth/users/<int:user_id>", methods=["GET"])
@require_auth
def get_user(user_id):
    """Get user by ID. Admin can view any user, users can only view themselves."""
    if g.current_user.role != "admin" and g.current_user.id != user_id:
        send_audit_log(g.current_user.id, "unauthorized_access", "auth", get_client_ip(), "failure",
                       f"User {g.current_user.id} tried to access user {user_id}")
        return jsonify({"error": "Access denied", "message": "You can only view your own profile"}), 403

    db = get_db_session()
    try:
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            return jsonify({"error": "Not found", "message": "User not found"}), 404
        return jsonify({"user": user.to_dict()}), 200
    finally:
        db.close()


@app.route("/api/auth/users/<int:user_id>/deactivate", methods=["PUT"])
@require_auth
@require_role("admin")
def deactivate_user(user_id):
    """Admin only: Deactivate a user."""
    db = get_db_session()
    try:
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            return jsonify({"error": "Not found", "message": "User not found"}), 404

        user.is_active = False
        db.commit()

        send_audit_log(g.current_user.id, "user.deactivated", "auth", get_client_ip(), "success",
                       f"Admin deactivated user: {user.username}")

        return jsonify({"message": f"User {user.username} deactivated"}), 200
    finally:
        db.close()


# ---- Internal Endpoints (Service-to-Service) ----

@app.route("/api/auth/internal/verify", methods=["POST"])
@require_internal_key
def internal_verify_token():
    """Internal: Verify a JWT token and return user info."""
    data = request.get_json()
    token = data.get("token", "") if data else ""

    if not token:
        return jsonify({"error": "Token required"}), 400

    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        return jsonify({"valid": True, "payload": payload}), 200
    except jwt.ExpiredSignatureError:
        return jsonify({"valid": False, "error": "Token expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"valid": False, "error": "Invalid token"}), 401


# ---- Error Handlers ----

@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Not found", "message": "The requested resource was not found"}), 404


@app.errorhandler(405)
def method_not_allowed(e):
    return jsonify({"error": "Method not allowed"}), 405


@app.errorhandler(500)
def internal_error(e):
    logger.error(f"Internal server error: {str(e)}")
    return jsonify({"error": "Internal server error"}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
