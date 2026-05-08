"""
Appointment Service (business-service-1) — Main Application
Handles doctors, appointments, and medical file uploads.
"""

import os
import json
import pika
import logging
import requests
from datetime import datetime, timezone
from flask import Flask, request, jsonify, g, send_file
from flask_cors import CORS
from io import BytesIO
from models import get_db_session, Doctor, Appointment, MedicalFile
from middleware import require_auth, require_role, require_internal_key, get_client_ip
from file_handler import validate_file, save_file, load_file, verify_file_integrity

app = Flask(__name__)
CORS(app)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

RABBITMQ_URL = os.environ.get("RABBITMQ_URL", "amqp://guest:guest@rabbitmq:5672/")
INTERNAL_API_KEY = os.environ.get("INTERNAL_API_KEY", "default-internal-key")
LOGGING_SERVICE_URL = os.environ.get("LOGGING_SERVICE_URL", "http://logging-service:5003")


def publish_message(queue, data):
    """Publish message to RabbitMQ."""
    try:
        conn = pika.BlockingConnection(pika.URLParameters(RABBITMQ_URL))
        ch = conn.channel()
        ch.queue_declare(queue=queue, durable=True)
        ch.basic_publish(exchange="", routing_key=queue, body=json.dumps(data),
                         properties=pika.BasicProperties(delivery_mode=2))
        conn.close()
    except Exception as e:
        logger.error(f"RabbitMQ publish error: {e}")


def send_audit_log(user_id, action, resource, ip, status, details=""):
    try:
        requests.post(f"{LOGGING_SERVICE_URL}/api/logs/", json={
            "user_id": user_id, "action": action, "resource": resource,
            "ip_address": ip, "status": status, "details": details
        }, headers={"X-Internal-Key": INTERNAL_API_KEY}, timeout=5)
    except Exception as e:
        logger.error(f"Audit log error: {e}")


# ---- Health ----
@app.route("/api/appointments/health", methods=["GET"])
def health():
    return jsonify({"status": "healthy", "service": "appointment-service"}), 200


# ===== DOCTORS =====

@app.route("/api/appointments/doctors", methods=["POST"])
@require_auth
@require_role("admin")
def create_doctor():
    """Admin: Create a doctor profile."""
    data = request.get_json()
    if not data:
        return jsonify({"error": "Request body must be JSON"}), 400

    user_id = data.get("user_id")
    specialization = data.get("specialization", "").strip()
    if not user_id or not specialization:
        return jsonify({"error": "user_id and specialization are required"}), 400

    db = get_db_session()
    try:
        existing = db.query(Doctor).filter(Doctor.user_id == user_id).first()
        if existing:
            return jsonify({"error": "Doctor profile already exists for this user"}), 409

        doctor = Doctor(
            user_id=user_id, specialization=specialization,
            phone=data.get("phone", ""),
        )
        db.add(doctor)
        db.commit()
        db.refresh(doctor)

        send_audit_log(g.current_user["user_id"], "doctor.created", "appointments",
                       get_client_ip(), "success", f"Doctor created: user_id={user_id}")
        return jsonify({"message": "Doctor created", "doctor": doctor.to_dict()}), 201
    except Exception as e:
        db.rollback()
        logger.error(f"Create doctor error: {e}")
        return jsonify({"error": "Internal server error"}), 500
    finally:
        db.close()


@app.route("/api/appointments/doctors", methods=["GET"])
@require_auth
def list_doctors():
    """List all doctors."""
    db = get_db_session()
    try:
        doctors = db.query(Doctor).all()
        return jsonify({"doctors": [d.to_dict() for d in doctors]}), 200
    finally:
        db.close()


@app.route("/api/appointments/doctors/<int:doctor_id>", methods=["GET"])
@require_auth
def get_doctor(doctor_id):
    db = get_db_session()
    try:
        doctor = db.query(Doctor).filter(Doctor.id == doctor_id).first()
        if not doctor:
            return jsonify({"error": "Doctor not found"}), 404
        return jsonify({"doctor": doctor.to_dict()}), 200
    finally:
        db.close()


@app.route("/api/appointments/doctors/<int:doctor_id>", methods=["PUT"])
@require_auth
@require_role("admin")
def update_doctor(doctor_id):
    data = request.get_json()
    db = get_db_session()
    try:
        doctor = db.query(Doctor).filter(Doctor.id == doctor_id).first()
        if not doctor:
            return jsonify({"error": "Doctor not found"}), 404
        if data.get("specialization"):
            doctor.specialization = data["specialization"]
        if data.get("phone"):
            doctor.phone = data["phone"]
        db.commit()
        return jsonify({"message": "Doctor updated", "doctor": doctor.to_dict()}), 200
    except Exception as e:
        db.rollback()
        logger.error(f"Update doctor error: {e}")
        return jsonify({"error": "Internal server error"}), 500
    finally:
        db.close()


@app.route("/api/appointments/doctors/<int:doctor_id>", methods=["DELETE"])
@require_auth
@require_role("admin")
def delete_doctor(doctor_id):
    db = get_db_session()
    try:
        doctor = db.query(Doctor).filter(Doctor.id == doctor_id).first()
        if not doctor:
            return jsonify({"error": "Doctor not found"}), 404
        db.delete(doctor)
        db.commit()
        send_audit_log(g.current_user["user_id"], "doctor.deleted", "appointments",
                       get_client_ip(), "success", f"Doctor {doctor_id} deleted")
        return jsonify({"message": "Doctor deleted"}), 200
    finally:
        db.close()


# ===== APPOINTMENTS =====

@app.route("/api/appointments/", methods=["POST"])
@require_auth
@require_role("patient")
def create_appointment():
    """Patient: Book an appointment."""
    data = request.get_json()
    if not data:
        return jsonify({"error": "Request body must be JSON"}), 400

    doctor_id = data.get("doctor_id")
    date_str = data.get("appointment_date")
    notes = data.get("notes", "")

    if not doctor_id or not date_str:
        return jsonify({"error": "doctor_id and appointment_date are required"}), 400

    # Validate date
    try:
        appt_date = datetime.fromisoformat(date_str)
    except ValueError:
        return jsonify({"error": "Invalid date format. Use ISO format: YYYY-MM-DDTHH:MM:SS"}), 400

    if appt_date < datetime.now():
        return jsonify({"error": "Appointment date cannot be in the past"}), 400

    db = get_db_session()
    try:
        doctor = db.query(Doctor).filter(Doctor.id == doctor_id).first()
        if not doctor:
            return jsonify({"error": "Doctor not found"}), 404

        appt = Appointment(
            patient_id=g.current_user["user_id"], doctor_id=doctor_id,
            appointment_date=appt_date, notes=notes, status="pending"
        )
        db.add(appt)
        db.commit()
        db.refresh(appt)

        # Publish to RabbitMQ for worker processing
        publish_message("appointment_queue", {
            "event": "appointment.created",
            "appointment_id": appt.id,
            "patient_id": g.current_user["user_id"],
            "doctor_id": doctor_id,
            "doctor_user_id": doctor.user_id,
            "appointment_date": appt_date.isoformat(),
            "timestamp": datetime.utcnow().isoformat()
        })

        send_audit_log(g.current_user["user_id"], "appointment.created", "appointments",
                       get_client_ip(), "success", f"Appointment {appt.id} created")

        return jsonify({"message": "Appointment booked", "appointment": appt.to_dict()}), 201
    except Exception as e:
        db.rollback()
        logger.error(f"Create appointment error: {e}")
        return jsonify({"error": "Internal server error"}), 500
    finally:
        db.close()


@app.route("/api/appointments/", methods=["GET"])
@require_auth
def list_appointments():
    """List appointments — filtered by role."""
    db = get_db_session()
    try:
        role = g.current_user["role"]
        uid = g.current_user["user_id"]

        if role == "admin":
            appts = db.query(Appointment).all()
        elif role == "doctor":
            doctor = db.query(Doctor).filter(Doctor.user_id == uid).first()
            if not doctor:
                return jsonify({"appointments": []}), 200
            appts = db.query(Appointment).filter(Appointment.doctor_id == doctor.id).all()
        else:  # patient
            appts = db.query(Appointment).filter(Appointment.patient_id == uid).all()

        return jsonify({"appointments": [a.to_dict() for a in appts]}), 200
    finally:
        db.close()


@app.route("/api/appointments/<int:appt_id>", methods=["GET"])
@require_auth
def get_appointment(appt_id):
    db = get_db_session()
    try:
        appt = db.query(Appointment).filter(Appointment.id == appt_id).first()
        if not appt:
            return jsonify({"error": "Appointment not found"}), 404

        role = g.current_user["role"]
        uid = g.current_user["user_id"]
        if role == "patient" and appt.patient_id != uid:
            return jsonify({"error": "Access denied"}), 403
        if role == "doctor":
            doctor = db.query(Doctor).filter(Doctor.user_id == uid).first()
            if not doctor or appt.doctor_id != doctor.id:
                return jsonify({"error": "Access denied"}), 403

        return jsonify({"appointment": appt.to_dict()}), 200
    finally:
        db.close()


@app.route("/api/appointments/<int:appt_id>", methods=["PUT"])
@require_auth
@require_role("doctor", "admin")
def update_appointment(appt_id):
    """Doctor/Admin: Update appointment status."""
    data = request.get_json()
    db = get_db_session()
    try:
        appt = db.query(Appointment).filter(Appointment.id == appt_id).first()
        if not appt:
            return jsonify({"error": "Appointment not found"}), 404

        # Doctor can only update their own appointments
        if g.current_user["role"] == "doctor":
            doctor = db.query(Doctor).filter(Doctor.user_id == g.current_user["user_id"]).first()
            if not doctor or appt.doctor_id != doctor.id:
                return jsonify({"error": "Access denied"}), 403

        new_status = data.get("status", "").strip().lower()
        valid_statuses = ["pending", "confirmed", "cancelled", "completed"]
        if new_status and new_status in valid_statuses:
            appt.status = new_status
        if data.get("notes"):
            appt.notes = data["notes"]

        appt.updated_at = datetime.utcnow()
        db.commit()

        send_audit_log(g.current_user["user_id"], f"appointment.{new_status}", "appointments",
                       get_client_ip(), "success", f"Appointment {appt_id} updated to {new_status}")

        return jsonify({"message": "Appointment updated", "appointment": appt.to_dict()}), 200
    except Exception as e:
        db.rollback()
        logger.error(f"Update error: {e}")
        return jsonify({"error": "Internal server error"}), 500
    finally:
        db.close()


@app.route("/api/appointments/<int:appt_id>", methods=["DELETE"])
@require_auth
def cancel_appointment(appt_id):
    """Patient/Admin: Cancel appointment."""
    db = get_db_session()
    try:
        appt = db.query(Appointment).filter(Appointment.id == appt_id).first()
        if not appt:
            return jsonify({"error": "Appointment not found"}), 404

        if g.current_user["role"] == "patient" and appt.patient_id != g.current_user["user_id"]:
            return jsonify({"error": "Access denied"}), 403

        appt.status = "cancelled"
        appt.updated_at = datetime.utcnow()
        db.commit()

        publish_message("cancellation_queue", {
            "event": "appointment.cancelled",
            "appointment_id": appt.id,
            "patient_id": appt.patient_id,
            "doctor_id": appt.doctor_id,
            "timestamp": datetime.utcnow().isoformat()
        })

        send_audit_log(g.current_user["user_id"], "appointment.cancelled", "appointments",
                       get_client_ip(), "success", f"Appointment {appt_id} cancelled")

        return jsonify({"message": "Appointment cancelled"}), 200
    finally:
        db.close()


# ===== MEDICAL FILES =====

@app.route("/api/appointments/<int:appt_id>/files", methods=["POST"])
@require_auth
def upload_file(appt_id):
    """Upload medical file for an appointment."""
    db = get_db_session()
    try:
        appt = db.query(Appointment).filter(Appointment.id == appt_id).first()
        if not appt:
            return jsonify({"error": "Appointment not found"}), 404

        uid = g.current_user["user_id"]
        role = g.current_user["role"]
        if role == "patient" and appt.patient_id != uid:
            return jsonify({"error": "Access denied"}), 403

        if "file" not in request.files:
            return jsonify({"error": "No file provided"}), 400

        file = request.files["file"]
        valid, result = validate_file(file)
        if not valid:
            send_audit_log(uid, "file.upload_rejected", "appointments",
                           get_client_ip(), "failure", f"File rejected: {result}")
            return jsonify({"error": "File validation failed", "messages": result}), 400

        stored_name, file_hash, file_size = save_file(file, result)

        med_file = MedicalFile(
            appointment_id=appt_id, patient_id=appt.patient_id,
            original_filename=file.filename, stored_filename=stored_name,
            file_hash=file_hash, encrypted=True,
            mime_type=result["mime_type"], file_size=file_size
        )
        db.add(med_file)
        db.commit()
        db.refresh(med_file)

        send_audit_log(uid, "file.uploaded", "appointments", get_client_ip(), "success",
                       f"File uploaded: {file.filename} for appointment {appt_id}")

        return jsonify({"message": "File uploaded and encrypted", "file": med_file.to_dict()}), 201
    except Exception as e:
        db.rollback()
        logger.error(f"Upload error: {e}")
        return jsonify({"error": "Internal server error"}), 500
    finally:
        db.close()


@app.route("/api/appointments/<int:appt_id>/files", methods=["GET"])
@require_auth
def list_files(appt_id):
    """List files for an appointment."""
    db = get_db_session()
    try:
        appt = db.query(Appointment).filter(Appointment.id == appt_id).first()
        if not appt:
            return jsonify({"error": "Appointment not found"}), 404

        uid = g.current_user["user_id"]
        role = g.current_user["role"]
        if role == "patient" and appt.patient_id != uid:
            return jsonify({"error": "Access denied"}), 403

        files = db.query(MedicalFile).filter(MedicalFile.appointment_id == appt_id).all()
        return jsonify({"files": [f.to_dict() for f in files]}), 200
    finally:
        db.close()


@app.route("/api/appointments/<int:appt_id>/files/<int:file_id>", methods=["GET"])
@require_auth
def download_file(appt_id, file_id):
    """Download (decrypt) a medical file."""
    db = get_db_session()
    try:
        med_file = db.query(MedicalFile).filter(
            MedicalFile.id == file_id, MedicalFile.appointment_id == appt_id
        ).first()
        if not med_file:
            return jsonify({"error": "File not found"}), 404

        uid = g.current_user["user_id"]
        role = g.current_user["role"]
        if role == "patient" and med_file.patient_id != uid:
            send_audit_log(uid, "file.download_denied", "appointments",
                           get_client_ip(), "failure", f"Unauthorized download attempt: file {file_id}")
            return jsonify({"error": "Access denied"}), 403

        decrypted = load_file(med_file.stored_filename)
        if decrypted is None:
            return jsonify({"error": "File not found on disk"}), 404

        send_audit_log(uid, "file.downloaded", "appointments", get_client_ip(), "success",
                       f"File downloaded: {med_file.original_filename}")

        return send_file(BytesIO(decrypted), download_name=med_file.original_filename,
                         mimetype=med_file.mime_type, as_attachment=True)
    finally:
        db.close()


@app.route("/api/appointments/<int:appt_id>/files/<int:file_id>/verify", methods=["GET"])
@require_auth
def verify_integrity(appt_id, file_id):
    """Verify file integrity using SHA-256 hash."""
    db = get_db_session()
    try:
        med_file = db.query(MedicalFile).filter(
            MedicalFile.id == file_id, MedicalFile.appointment_id == appt_id
        ).first()
        if not med_file:
            return jsonify({"error": "File not found"}), 404

        valid, message = verify_file_integrity(med_file.stored_filename, med_file.file_hash)
        return jsonify({
            "file_id": file_id, "original_filename": med_file.original_filename,
            "integrity_valid": valid, "message": message,
            "stored_hash": med_file.file_hash
        }), 200
    finally:
        db.close()


# ---- Error Handlers ----
@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Not found"}), 404

@app.errorhandler(413)
def too_large(e):
    return jsonify({"error": "File too large", "message": "Maximum file size is 5MB"}), 413

@app.errorhandler(500)
def internal_error(e):
    return jsonify({"error": "Internal server error"}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=False)
