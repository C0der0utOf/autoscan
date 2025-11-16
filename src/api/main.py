"""FastAPI application for the security automation platform."""

from contextlib import asynccontextmanager
from typing import List

from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy.orm import Session

from src.core.database import SessionLocal, init_db
from src.core.logger import configure_logging
from src.core.models import Scan, ScanStatus
from src.core.scanner import SecurityScanner

# Configure logging
configure_logging()

# Initialize database on startup
init_db()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan events."""
    # Startup
    init_db()
    yield
    # Shutdown
    pass


app = FastAPI(
    title="Security Automation Platform API",
    description="REST API for security scanning and compliance checking",
    version="0.1.0",
    lifespan=lifespan,
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify actual origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Dependency to get DB session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# Pydantic models for API
class ScanRequest(BaseModel):
    target: str
    scan_type: str = "full"
    compliance_frameworks: List[str] = []


class ScanResponse(BaseModel):
    id: int
    target: str
    scan_type: str
    status: str
    started_at: str
    completed_at: str | None

    class Config:
        from_attributes = True


class FindingResponse(BaseModel):
    id: int
    title: str
    description: str
    severity: str
    category: str
    cve_id: str | None
    cvss_score: float | None
    recommendation: str | None

    class Config:
        from_attributes = True


@app.get("/")
async def root():
    """Root endpoint."""
    return {"message": "Security Automation Platform API", "version": "0.1.0"}


@app.get("/health")
async def health():
    """Health check endpoint."""
    return {"status": "healthy"}


@app.post("/scans", response_model=ScanResponse)
async def create_scan(scan_request: ScanRequest, db: Session = Depends(get_db)):
    """Create and start a new security scan."""
    scanner = SecurityScanner(db_session=db)
    scan = scanner.scan(
        target=scan_request.target,
        scan_type=scan_request.scan_type,
        compliance_frameworks=scan_request.compliance_frameworks or None,
    )

    return ScanResponse(
        id=scan.id,
        target=scan.target,
        scan_type=scan.scan_type,
        status=scan.status.value,
        started_at=scan.started_at.isoformat() if scan.started_at else "",
        completed_at=scan.completed_at.isoformat() if scan.completed_at else None,
    )


@app.get("/scans/{scan_id}", response_model=ScanResponse)
async def get_scan(scan_id: int, db: Session = Depends(get_db)):
    """Get scan details by ID."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    return ScanResponse(
        id=scan.id,
        target=scan.target,
        scan_type=scan.scan_type,
        status=scan.status.value,
        started_at=scan.started_at.isoformat() if scan.started_at else "",
        completed_at=scan.completed_at.isoformat() if scan.completed_at else None,
    )


@app.get("/scans/{scan_id}/findings", response_model=List[FindingResponse])
async def get_scan_findings(scan_id: int, db: Session = Depends(get_db)):
    """Get findings for a specific scan."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    return [
        FindingResponse(
            id=f.id,
            title=f.title,
            description=f.description,
            severity=f.severity.value,
            category=f.category,
            cve_id=f.cve_id,
            cvss_score=f.cvss_score,
            recommendation=f.recommendation,
        )
        for f in scan.findings
    ]


@app.get("/scans", response_model=List[ScanResponse])
async def list_scans(limit: int = 10, db: Session = Depends(get_db)):
    """List recent scans."""
    scans = db.query(Scan).order_by(Scan.started_at.desc()).limit(limit).all()
    return [
        ScanResponse(
            id=s.id,
            target=s.target,
            scan_type=s.scan_type,
            status=s.status.value,
            started_at=s.started_at.isoformat() if s.started_at else "",
            completed_at=s.completed_at.isoformat() if s.completed_at else None,
        )
        for s in scans
    ]


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)

