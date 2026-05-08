"""
Auth Service — Input Validators
Validates user input for registration and login.
"""

import re


def validate_email(email):
    """Validate email format."""
    if not email or not isinstance(email, str):
        return False, "Email is required"
    email = email.strip()
    if len(email) > 255:
        return False, "Email must be less than 255 characters"
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(pattern, email):
        return False, "Invalid email format"
    return True, email


def validate_password(password):
    """Validate password strength."""
    if not password or not isinstance(password, str):
        return False, "Password is required"
    if len(password) < 8:
        return False, "Password must be at least 8 characters"
    if len(password) > 128:
        return False, "Password must be less than 128 characters"
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    if not re.search(r'[0-9]', password):
        return False, "Password must contain at least one digit"
    return True, password


def validate_username(username):
    """Validate username."""
    if not username or not isinstance(username, str):
        return False, "Username is required"
    username = username.strip()
    if len(username) < 3:
        return False, "Username must be at least 3 characters"
    if len(username) > 100:
        return False, "Username must be less than 100 characters"
    if not re.match(r'^[a-zA-Z0-9_.-]+$', username):
        return False, "Username can only contain letters, numbers, underscores, dots, and hyphens"
    return True, username


def validate_role(role):
    """Validate role."""
    valid_roles = ["admin", "doctor", "patient"]
    if not role or not isinstance(role, str):
        return False, "Role is required"
    role = role.strip().lower()
    if role not in valid_roles:
        return False, f"Role must be one of: {', '.join(valid_roles)}"
    return True, role


def validate_registration(data):
    """Validate complete registration data."""
    errors = []

    valid, result = validate_email(data.get("email", ""))
    if not valid:
        errors.append(result)
    else:
        data["email"] = result

    valid, result = validate_username(data.get("username", ""))
    if not valid:
        errors.append(result)
    else:
        data["username"] = result

    valid, result = validate_password(data.get("password", ""))
    if not valid:
        errors.append(result)

    # Role is optional, defaults to 'patient'
    role = data.get("role", "patient")
    valid, result = validate_role(role)
    if not valid:
        errors.append(result)
    else:
        data["role"] = result

    return len(errors) == 0, errors


def validate_login(data):
    """Validate login data."""
    errors = []

    if not data.get("email"):
        errors.append("Email is required")

    if not data.get("password"):
        errors.append("Password is required")

    return len(errors) == 0, errors
