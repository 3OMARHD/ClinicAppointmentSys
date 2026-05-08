"""
Appointment Service — Database Models
Defines Doctor, Appointment, and MedicalFile models.
"""

from sqlalchemy import create_engine, Column, Integer, String, Boolean, DateTime, Text, Time, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from datetime import datetime
import os

DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql://clinic_admin:password@localhost:5432/clinic_db")

engine = create_engine(DATABASE_URL, pool_pre_ping=True, pool_size=5, max_overflow=10)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class Doctor(Base):
    __tablename__ = "doctors"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, unique=True, nullable=False)
    specialization = Column(String(100), nullable=False)
    phone = Column(String(20), nullable=True)
    available_from = Column(Time, default="09:00")
    available_to = Column(Time, default="17:00")
    created_at = Column(DateTime, default=datetime.utcnow)
    appointments = relationship("Appointment", back_populates="doctor")

    def to_dict(self):
        return {
            "id": self.id, "user_id": self.user_id,
            "specialization": self.specialization, "phone": self.phone,
            "available_from": str(self.available_from) if self.available_from else None,
            "available_to": str(self.available_to) if self.available_to else None,
            "created_at": self.created_at.isoformat() if self.created_at else None
        }


class Appointment(Base):
    __tablename__ = "appointments"
    id = Column(Integer, primary_key=True, index=True)
    patient_id = Column(Integer, nullable=False)
    doctor_id = Column(Integer, ForeignKey("doctors.id"), nullable=False)
    appointment_date = Column(DateTime, nullable=False)
    status = Column(String(20), nullable=False, default="pending")
    notes = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    doctor = relationship("Doctor", back_populates="appointments")
    files = relationship("MedicalFile", back_populates="appointment")

    def to_dict(self):
        return {
            "id": self.id, "patient_id": self.patient_id, "doctor_id": self.doctor_id,
            "appointment_date": self.appointment_date.isoformat() if self.appointment_date else None,
            "status": self.status, "notes": self.notes,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None
        }


class MedicalFile(Base):
    __tablename__ = "medical_files"
    id = Column(Integer, primary_key=True, index=True)
    appointment_id = Column(Integer, ForeignKey("appointments.id"), nullable=False)
    patient_id = Column(Integer, nullable=False)
    original_filename = Column(String(255), nullable=False)
    stored_filename = Column(String(255), nullable=False)
    file_hash = Column(String(64), nullable=False)
    encrypted = Column(Boolean, default=True)
    mime_type = Column(String(100), nullable=False)
    file_size = Column(Integer, nullable=False)
    uploaded_at = Column(DateTime, default=datetime.utcnow)
    appointment = relationship("Appointment", back_populates="files")

    def to_dict(self):
        return {
            "id": self.id, "appointment_id": self.appointment_id,
            "patient_id": self.patient_id, "original_filename": self.original_filename,
            "file_hash": self.file_hash, "encrypted": self.encrypted,
            "mime_type": self.mime_type, "file_size": self.file_size,
            "uploaded_at": self.uploaded_at.isoformat() if self.uploaded_at else None
        }


def get_db_session():
    return SessionLocal()
