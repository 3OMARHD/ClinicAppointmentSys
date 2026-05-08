"""
Appointment Service — File Handler
Handles secure file upload, encryption, and integrity verification.
"""

import os
import uuid
import hashlib
from cryptography.fernet import Fernet

UPLOAD_DIR = os.environ.get("UPLOAD_DIR", "/app/uploads")
ENCRYPTION_KEY = os.environ.get("ENCRYPTION_KEY", "")
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB

ALLOWED_EXTENSIONS = {".pdf", ".jpg", ".jpeg", ".png", ".doc", ".docx"}
BLOCKED_EXTENSIONS = {".exe", ".php", ".js", ".bat", ".sh", ".cmd", ".vbs", ".msi"}
ALLOWED_MIME_TYPES = {
    "application/pdf", "image/jpeg", "image/png",
    "application/msword",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
}


def get_fernet():
    """Get Fernet cipher for encryption/decryption."""
    key = ENCRYPTION_KEY
    if not key:
        key = Fernet.generate_key().decode()
    # Ensure key is proper Fernet format
    try:
        return Fernet(key.encode() if isinstance(key, str) else key)
    except Exception:
        # Generate a valid key if the provided one is invalid
        return Fernet(Fernet.generate_key())


def validate_file(file):
    """Validate uploaded file for security."""
    errors = []

    if not file or not file.filename:
        return False, ["No file provided"]

    filename = file.filename.lower()
    ext = os.path.splitext(filename)[1]

    # Check blocked extensions
    if ext in BLOCKED_EXTENSIONS:
        errors.append(f"File extension '{ext}' is not allowed (blocked for security)")
        return False, errors

    # Check allowed extensions
    if ext not in ALLOWED_EXTENSIONS:
        errors.append(f"File extension '{ext}' is not allowed. Allowed: {', '.join(ALLOWED_EXTENSIONS)}")

    # Check MIME type
    if file.content_type and file.content_type not in ALLOWED_MIME_TYPES:
        errors.append(f"MIME type '{file.content_type}' is not allowed")

    # Check file size (read content to check)
    file.seek(0, 2)  # Seek to end
    size = file.tell()
    file.seek(0)  # Reset

    if size > MAX_FILE_SIZE:
        errors.append(f"File size ({size} bytes) exceeds maximum ({MAX_FILE_SIZE} bytes / 5MB)")

    if size == 0:
        errors.append("File is empty")

    if errors:
        return False, errors

    return True, {"size": size, "ext": ext, "mime_type": file.content_type}


def compute_hash(data):
    """Compute SHA-256 hash of file data."""
    return hashlib.sha256(data).hexdigest()


def encrypt_file(data):
    """Encrypt file data using Fernet (AES)."""
    f = get_fernet()
    return f.encrypt(data)


def decrypt_file(encrypted_data):
    """Decrypt file data using Fernet (AES)."""
    f = get_fernet()
    return f.decrypt(encrypted_data)


def save_file(file, file_info):
    """Save and encrypt an uploaded file. Returns stored filename and hash."""
    os.makedirs(UPLOAD_DIR, exist_ok=True)

    # Generate safe filename
    safe_name = f"{uuid.uuid4().hex}{file_info['ext']}.enc"
    file_path = os.path.join(UPLOAD_DIR, safe_name)

    # Read file data
    file_data = file.read()

    # Compute hash of original file
    file_hash = compute_hash(file_data)

    # Encrypt and save
    encrypted_data = encrypt_file(file_data)
    with open(file_path, "wb") as f:
        f.write(encrypted_data)

    return safe_name, file_hash, file_info["size"]


def load_file(stored_filename):
    """Load and decrypt a stored file."""
    file_path = os.path.join(UPLOAD_DIR, stored_filename)
    if not os.path.exists(file_path):
        return None

    with open(file_path, "rb") as f:
        encrypted_data = f.read()

    return decrypt_file(encrypted_data)


def verify_file_integrity(stored_filename, original_hash):
    """Verify file integrity by comparing hashes."""
    decrypted_data = load_file(stored_filename)
    if decrypted_data is None:
        return False, "File not found"

    current_hash = compute_hash(decrypted_data)
    if current_hash == original_hash:
        return True, "File integrity verified — hash matches"
    else:
        return False, "File integrity FAILED — hash mismatch (file may have been tampered)"
