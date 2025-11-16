"""Main scanning orchestration engine."""

from datetime import datetime
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session

from src.compliance.cis_benchmarks import CISBenchmarkChecker
from src.config_analyzer.system_hardening import SystemHardeningAnalyzer
from src.core.database import get_db, init_db
from src.core.logger import get_logger
from src.core.models import Finding, Scan, ScanStatus, Severity
from src.vulnerability.cve_scanner import CVEScanner

logger = get_logger(__name__)


class SecurityScanner:
    """Main security scanner orchestrator."""

    def __init__(self, db_session: Optional[Session] = None):
        """Initialize the scanner."""
        self.db_session = db_session
        self.logger = get_logger(self.__class__.__name__)

    def scan(
        self,
        target: str,
        scan_type: str = "full",
        compliance_frameworks: Optional[List[str]] = None,
        vulnerability_scan: bool = True,
        config_analysis: bool = True,
    ) -> Scan:
        """
        Execute a security scan.

        Args:
            target: Target system to scan
            scan_type: Type of scan (compliance, vulnerability, config, full)
            compliance_frameworks: List of compliance frameworks to check
            vulnerability_scan: Whether to perform vulnerability scanning
            config_analysis: Whether to perform configuration analysis

        Returns:
            Scan object with results
        """
        self.logger.info(
            "Starting security scan",
            target=target,
            scan_type=scan_type,
            compliance_frameworks=compliance_frameworks,
        )

        # Create scan record
        scan = Scan(
            target=target,
            scan_type=scan_type,
            status=ScanStatus.RUNNING,
            started_at=datetime.utcnow(),
        )

        if self.db_session:
            self.db_session.add(scan)
            self.db_session.commit()
            self.db_session.refresh(scan)

        try:
            # Initialize database if needed
            if not self.db_session:
                init_db()

            # Execute scan based on type
            if scan_type == "full" or scan_type == "compliance":
                self._run_compliance_checks(scan, compliance_frameworks or ["cis"])

            if scan_type == "full" or scan_type == "vulnerability":
                if vulnerability_scan:
                    self._run_vulnerability_scan(scan)

            if scan_type == "full" or scan_type == "config":
                if config_analysis:
                    self._run_config_analysis(scan)

            # Mark scan as completed
            scan.status = ScanStatus.COMPLETED
            scan.completed_at = datetime.utcnow()

            if self.db_session:
                self.db_session.commit()

            self.logger.info("Scan completed successfully", scan_id=scan.id, target=target)

        except Exception as e:
            self.logger.error("Scan failed", error=str(e), scan_id=scan.id if scan.id else None)
            scan.status = ScanStatus.FAILED
            scan.error_message = str(e)
            scan.completed_at = datetime.utcnow()

            if self.db_session:
                self.db_session.commit()

        return scan

    def _run_compliance_checks(self, scan: Scan, frameworks: List[str]) -> None:
        """Run compliance checks against specified frameworks."""
        self.logger.info("Running compliance checks", frameworks=frameworks)

        for framework in frameworks:
            if framework.lower() == "cis":
                checker = CISBenchmarkChecker(target=scan.target)
                results = checker.check_compliance()
                for result in results:
                    result.scan_id = scan.id
                    if self.db_session:
                        self.db_session.add(result)
                    else:
                        scan.compliance_results.append(result)

                # Also create findings for failed compliance checks
                for result in results:
                    if not result.passed:
                        finding = Finding(
                            scan_id=scan.id,
                            title=f"Compliance Failure: {result.rule_id}",
                            description=f"{result.rule_name}: {result.description}",
                            severity=self._map_compliance_to_severity(result),
                            category="compliance",
                            recommendation=result.remediation,
                        )
                        if self.db_session:
                            self.db_session.add(finding)
                        else:
                            scan.findings.append(finding)

        if self.db_session:
            self.db_session.commit()

    def _run_vulnerability_scan(self, scan: Scan) -> None:
        """Run vulnerability scanning."""
        self.logger.info("Running vulnerability scan")

        scanner = CVEScanner(target=scan.target)
        findings = scanner.scan_system_packages()

        for finding in findings:
            finding.scan_id = scan.id
            if self.db_session:
                self.db_session.add(finding)
            else:
                scan.findings.append(finding)

        if self.db_session:
            self.db_session.commit()

    def _run_config_analysis(self, scan: Scan) -> None:
        """Run configuration analysis."""
        self.logger.info("Running configuration analysis")

        analyzer = SystemHardeningAnalyzer(target=scan.target)
        findings = analyzer.analyze()

        for finding in findings:
            finding.scan_id = scan.id
            if self.db_session:
                self.db_session.add(finding)
            else:
                scan.findings.append(finding)

        if self.db_session:
            self.db_session.commit()

    def get_scan_results(self, scan_id: int) -> Optional[Dict[str, Any]]:
        """
        Retrieve scan results.

        Args:
            scan_id: ID of the scan to retrieve

        Returns:
            Dictionary containing scan results
        """
        if not self.db_session:
            return None

        scan = self.db_session.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            return None

        return {
            "id": scan.id,
            "target": scan.target,
            "scan_type": scan.scan_type,
            "status": scan.status.value,
            "started_at": scan.started_at.isoformat() if scan.started_at else None,
            "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
            "findings_count": len(scan.findings),
            "compliance_results_count": len(scan.compliance_results),
        }

    def _map_compliance_to_severity(self, compliance_result) -> Severity:
        """Map compliance result to finding severity."""
        # This is a simple mapping - could be enhanced based on rule severity
        if "critical" in compliance_result.remediation.lower() or "high" in compliance_result.remediation.lower():
            return Severity.HIGH
        elif "medium" in compliance_result.remediation.lower():
            return Severity.MEDIUM
        else:
            return Severity.LOW

