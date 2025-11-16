"""Tests for the security scanner."""

import pytest
from sqlalchemy.orm import Session

from src.core.database import SessionLocal, init_db
from src.core.models import Scan, ScanStatus
from src.core.scanner import SecurityScanner


@pytest.fixture
def db_session():
    """Create a test database session."""
    init_db()
    db = SessionLocal()
    yield db
    db.close()


def test_scanner_initialization(db_session: Session):
    """Test scanner initialization."""
    scanner = SecurityScanner(db_session=db_session)
    assert scanner.db_session is not None
    assert scanner.logger is not None


def test_scan_creation(db_session: Session):
    """Test scan creation."""
    scanner = SecurityScanner(db_session=db_session)
    scan = scanner.scan(target="test-host", scan_type="compliance")

    assert scan is not None
    assert scan.target == "test-host"
    assert scan.scan_type == "compliance"
    assert scan.status in [ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.RUNNING]


def test_get_scan_results(db_session: Session):
    """Test retrieving scan results."""
    scanner = SecurityScanner(db_session=db_session)
    scan = scanner.scan(target="test-host", scan_type="config")

    results = scanner.get_scan_results(scan.id)
    assert results is not None
    assert results["id"] == scan.id
    assert results["target"] == "test-host"

