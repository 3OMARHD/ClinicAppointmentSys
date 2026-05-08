"""
Worker Service — Background Job Consumer
Consumes messages from RabbitMQ and triggers notifications and audit logs.
Queues:
  - appointment_queue: new appointment → notify doctor & patient
  - cancellation_queue: cancelled appointment → notify doctor & patient
  - audit_queue: audit events → forward to logging service
"""

import os
import json
import time
import logging
import requests
import pika

logging.basicConfig(level=logging.INFO, format="%(asctime)s [WORKER] %(message)s")
logger = logging.getLogger(__name__)

RABBITMQ_URL = os.environ.get("RABBITMQ_URL", "amqp://guest:guest@rabbitmq:5672/")
INTERNAL_API_KEY = os.environ.get("INTERNAL_API_KEY", "default-internal-key")
NOTIFICATION_SERVICE_URL = os.environ.get("NOTIFICATION_SERVICE_URL", "http://business-service-2:5002")
LOGGING_SERVICE_URL = os.environ.get("LOGGING_SERVICE_URL", "http://logging-service:5003")

INTERNAL_HEADERS = {"X-Internal-Key": INTERNAL_API_KEY, "Content-Type": "application/json"}


def create_notification(user_id, notif_type, title, message):
    """Send notification via the notification service."""
    try:
        resp = requests.post(
            f"{NOTIFICATION_SERVICE_URL}/api/notifications/",
            json={"user_id": user_id, "type": notif_type, "title": title, "message": message},
            headers=INTERNAL_HEADERS, timeout=10
        )
        if resp.status_code == 201:
            logger.info(f"Notification sent to user {user_id}: {title}")
        else:
            logger.error(f"Notification failed ({resp.status_code}): {resp.text}")
    except Exception as e:
        logger.error(f"Notification service error: {e}")


def send_audit_log(user_id, action, resource, status, details=""):
    """Forward audit log to logging service."""
    try:
        requests.post(
            f"{LOGGING_SERVICE_URL}/api/logs/",
            json={
                "user_id": user_id, "action": action, "resource": resource,
                "ip_address": "worker-service", "status": status, "details": details
            },
            headers=INTERNAL_HEADERS, timeout=10
        )
    except Exception as e:
        logger.error(f"Logging service error: {e}")


def handle_appointment_created(data):
    """Handle new appointment event."""
    logger.info(f"Processing appointment.created: {data}")

    patient_id = data.get("patient_id")
    doctor_user_id = data.get("doctor_user_id")
    appt_id = data.get("appointment_id")
    appt_date = data.get("appointment_date", "")

    # Notify patient
    create_notification(
        patient_id, "appointment_confirmation",
        "Appointment Booked",
        f"Your appointment #{appt_id} has been booked for {appt_date}. "
        f"Please wait for doctor confirmation."
    )

    # Notify doctor
    if doctor_user_id:
        create_notification(
            doctor_user_id, "new_appointment",
            "New Appointment Request",
            f"You have a new appointment request #{appt_id} scheduled for {appt_date}. "
            f"Please confirm or reschedule."
        )

    send_audit_log(patient_id, "worker.appointment_processed", "worker", "success",
                   f"Appointment {appt_id} notifications sent")


def handle_appointment_cancelled(data):
    """Handle appointment cancellation event."""
    logger.info(f"Processing appointment.cancelled: {data}")

    patient_id = data.get("patient_id")
    doctor_id = data.get("doctor_id")
    appt_id = data.get("appointment_id")

    # Notify patient
    create_notification(
        patient_id, "appointment_cancelled",
        "Appointment Cancelled",
        f"Your appointment #{appt_id} has been cancelled."
    )

    send_audit_log(patient_id, "worker.cancellation_processed", "worker", "success",
                   f"Cancellation notifications sent for appointment {appt_id}")


def handle_audit_event(data):
    """Forward audit event to logging service."""
    event_data = data.get("data", {})
    send_audit_log(
        event_data.get("user_id"), data.get("event", "unknown"),
        "audit", "success", json.dumps(event_data)
    )


def callback_appointment(ch, method, properties, body):
    """RabbitMQ callback for appointment queue."""
    try:
        data = json.loads(body)
        event = data.get("event", "")
        if event == "appointment.created":
            handle_appointment_created(data)
        else:
            logger.info(f"Unknown appointment event: {event}")
        ch.basic_ack(delivery_tag=method.delivery_tag)
    except Exception as e:
        logger.error(f"Error processing appointment message: {e}")
        ch.basic_nack(delivery_tag=method.delivery_tag, requeue=True)


def callback_cancellation(ch, method, properties, body):
    """RabbitMQ callback for cancellation queue."""
    try:
        data = json.loads(body)
        handle_appointment_cancelled(data)
        ch.basic_ack(delivery_tag=method.delivery_tag)
    except Exception as e:
        logger.error(f"Error processing cancellation message: {e}")
        ch.basic_nack(delivery_tag=method.delivery_tag, requeue=True)


def callback_audit(ch, method, properties, body):
    """RabbitMQ callback for audit queue."""
    try:
        data = json.loads(body)
        handle_audit_event(data)
        ch.basic_ack(delivery_tag=method.delivery_tag)
    except Exception as e:
        logger.error(f"Error processing audit message: {e}")
        ch.basic_nack(delivery_tag=method.delivery_tag, requeue=True)


def connect_with_retry(max_retries=30, delay=5):
    """Connect to RabbitMQ with retry logic."""
    for attempt in range(1, max_retries + 1):
        try:
            logger.info(f"Connecting to RabbitMQ (attempt {attempt}/{max_retries})...")
            connection = pika.BlockingConnection(pika.URLParameters(RABBITMQ_URL))
            logger.info("Connected to RabbitMQ successfully!")
            return connection
        except pika.exceptions.AMQPConnectionError:
            if attempt < max_retries:
                logger.warning(f"RabbitMQ not ready, retrying in {delay}s...")
                time.sleep(delay)
            else:
                logger.error("Could not connect to RabbitMQ after max retries")
                raise


def main():
    """Main worker loop."""
    logger.info("Worker service starting...")

    connection = connect_with_retry()
    channel = connection.channel()

    # Declare queues
    channel.queue_declare(queue="appointment_queue", durable=True)
    channel.queue_declare(queue="cancellation_queue", durable=True)
    channel.queue_declare(queue="audit_queue", durable=True)

    # Fair dispatch — one message at a time per worker
    channel.basic_qos(prefetch_count=1)

    # Set up consumers
    channel.basic_consume(queue="appointment_queue", on_message_callback=callback_appointment)
    channel.basic_consume(queue="cancellation_queue", on_message_callback=callback_cancellation)
    channel.basic_consume(queue="audit_queue", on_message_callback=callback_audit)

    logger.info("Worker ready — waiting for messages on: appointment_queue, cancellation_queue, audit_queue")

    try:
        channel.start_consuming()
    except KeyboardInterrupt:
        logger.info("Worker shutting down...")
        channel.stop_consuming()
    finally:
        connection.close()


if __name__ == "__main__":
    main()
