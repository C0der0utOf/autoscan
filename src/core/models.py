"""Database models for the security automation platform."""

from datetime import datetime
from enum import Enum
from typing import Optional

from sqlalchemy import Column, DateTime, Enum as SQLEnum, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship

from src.core.database import Base


class ScanStatus(str, Enum):
    """Scan status enumeration."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class Severity(str, Enum):
    """Vulnerability severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Scan(Base):
    """Scan execution record."""

    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    target = Column(String, nullable=False, index=True)
    scan_type = Column(String, nullable=False)  # compliance, vulnerability, config, full
    status = Column(SQLEnum(ScanStatus), default=ScanStatus.PENDING, index=True)
    started_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)
    error_message = Column(Text, nullable=True)

    # Relationships
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")
    compliance_results = relationship("ComplianceResult", back_populates="scan", cascade="all, delete-orphan")


class Finding(Base):
    """Security finding from a scan."""

    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False, index=True)
    title = Column(String, nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(SQLEnum(Severity), nullable=False, index=True)
    category = Column(String, nullable=False)  # vulnerability, compliance, config
    cve_id = Column(String, nullable=True, index=True)
    cvss_score = Column(Float, nullable=True)
    recommendation = Column(Text, nullable=True)
    detected_at = Column(DateTime, default=datetime.utcnow)

    # Relationship
    scan = relationship("Scan", back_populates="findings")


class ComplianceResult(Base):
    """Compliance check result."""

    __tablename__ = "compliance_results"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False, index=True)
    framework = Column(String, nullable=False)  # cis, nist, custom
    rule_id = Column(String, nullable=False)
    rule_name = Column(String, nullable=False)
    passed = Column(Integer, default=0)  # 0 = failed, 1 = passed
    description = Column(Text, nullable=True)
    remediation = Column(Text, nullable=True)
    checked_at = Column(DateTime, default=datetime.utcnow)

    # Relationship
    scan = relationship("Scan", back_populates="compliance_results")

