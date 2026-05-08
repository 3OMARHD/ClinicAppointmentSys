"""
Logging Service — Database Models
"""

from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime
import os

DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql://clinic_admin:password@localhost:5432/clinic_db")

engine = create_engine(DATABASE_URL, pool_pre_ping=True, pool_size=5, max_overflow=10)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class AuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, nullable=True, index=True)
    action = Column(String(100), nullable=False, index=True)
    resource = Column(String(100), nullable=True)
    ip_address = Column(String(45), nullable=True)
    status = Column(String(20), nullable=False, default="success")
    details = Column(Text, nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)

    def to_dict(self):
        return {
            "id": self.id, "user_id": self.user_id,
            "action": self.action, "resource": self.resource,
            "ip_address": self.ip_address, "status": self.status,
            "details": self.details,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None
        }


def get_db_session():
    return SessionLocal()
