"""System hardening configuration analyzer."""

import platform
from typing import List

from src.core.logger import get_logger
from src.core.models import Finding, Severity
from src.core.remote_executor import RemoteExecutor

logger = get_logger(__name__)


class SystemHardeningAnalyzer:
    """Analyze system hardening configurations."""

    def __init__(self, target: str = "localhost"):
        """Initialize the system hardening analyzer."""
        self.logger = get_logger(self.__class__.__name__)
        self.target = target
        self.executor = RemoteExecutor(target=target)

    def analyze(self) -> List[Finding]:
        """
        Analyze system hardening configurations.

        Returns:
            List of security findings
        """
        self.logger.info("Starting system hardening analysis")
        findings = []

        if platform.system() != "Linux":
            self.logger.warning("System hardening checks are primarily for Linux", system=platform.system())
            return findings

        # Check various hardening configurations
        findings.extend(self._check_ssh_config())
        findings.extend(self._check_firewall())
        findings.extend(self._check_password_policy())
        findings.extend(self._check_file_permissions())
        findings.extend(self._check_network_security())

        self.logger.info("System hardening analysis completed", findings_count=len(findings))
        return findings

    def _check_ssh_config(self) -> List[Finding]:
        """Check SSH configuration security."""
        findings = []
        ssh_config_path = "/etc/ssh/sshd_config"

        if not self.executor.file_exists(ssh_config_path):
            findings.append(
                Finding(
                    title="SSH configuration file not found",
                    description="SSH daemon configuration file is missing",
                    severity=Severity.MEDIUM,
                    category="config",
                    recommendation="Ensure SSH is properly configured",
                )
            )
            return findings

        try:
            content = self.executor.read_file(ssh_config_path)
            if not content:
                return findings
            checks = {
                "PasswordAuthentication": ("no", Severity.HIGH, "Disable password authentication, use keys"),
                "PermitRootLogin": ("no", Severity.HIGH, "Disable root login via SSH"),
                "Protocol": ("2", Severity.CRITICAL, "Use SSH protocol 2 only"),
                "X11Forwarding": ("no", Severity.MEDIUM, "Disable X11 forwarding if not needed"),
            }

            for setting, (expected, severity, recommendation) in checks.items():
                if setting not in content:
                    findings.append(
                        Finding(
                            title=f"SSH {setting} not configured",
                            description=f"SSH setting {setting} is not explicitly set",
                            severity=severity,
                            category="config",
                            recommendation=recommendation,
                        )
                    )
                elif f"{setting} {expected}" not in content and f"{setting}\t{expected}" not in content:
                    # Check if it's set to the wrong value
                    for line in content.split("\n"):
                        if line.strip().startswith(setting):
                            findings.append(
                                Finding(
                                    title=f"SSH {setting} misconfigured",
                                    description=f"SSH setting {setting} should be set to {expected}",
                                    severity=severity,
                                    category="config",
                                    recommendation=recommendation,
                                )
                            )
                            break

        except Exception as e:
            self.logger.error("Error checking SSH config", error=str(e))

        return findings

    def _check_firewall(self) -> List[Finding]:
        """Check firewall configuration."""
        findings = []

        # Check if firewall is active
        firewall_commands = [
            ["systemctl", "is-active", "ufw"],
            ["systemctl", "is-active", "firewalld"],
            ["systemctl", "is-active", "iptables"],
        ]

        firewall_active = False
        for cmd in firewall_commands:
            stdout, stderr, returncode = self.executor.execute_command(cmd, timeout=5)
            if returncode == 0 and stdout.strip() == "active":
                firewall_active = True
                break

        if not firewall_active:
            findings.append(
                Finding(
                    title="Firewall not active",
                    description="No active firewall detected on the system",
                    severity=Severity.HIGH,
                    category="config",
                    recommendation="Enable and configure a firewall (ufw, firewalld, or iptables)",
                )
            )

        return findings

    def _check_password_policy(self) -> List[Finding]:
        """Check password policy configuration."""
        findings = []
        login_defs_path = "/etc/login.defs"
        pam_common_password_path = "/etc/pam.d/common-password"

        if self.executor.file_exists(login_defs_path):
            try:
                content = self.executor.read_file(login_defs_path)
                if not content:
                    return findings
                # Check for minimum password length
                if "PASS_MIN_LEN" not in content:
                    findings.append(
                        Finding(
                            title="Password minimum length not configured",
                            description="PASS_MIN_LEN is not set in /etc/login.defs",
                            severity=Severity.MEDIUM,
                            category="config",
                            recommendation="Set PASS_MIN_LEN to at least 12",
                        )
                    )
            except Exception as e:
                self.logger.error("Error checking password policy", error=str(e))

        if not self.executor.file_exists(pam_common_password_path):
            findings.append(
                Finding(
                    title="PAM password configuration missing",
                    description="PAM common-password configuration not found",
                    severity=Severity.MEDIUM,
                    category="config",
                    recommendation="Configure PAM password policies",
                )
            )

        return findings

    def _check_file_permissions(self) -> List[Finding]:
        """Check critical file permissions."""
        findings = []

        critical_files = [
            ("/etc/passwd", "644"),
            ("/etc/shadow", "640"),
            ("/etc/group", "644"),
            ("/etc/sudoers", "440"),
        ]

        for file_path, expected_perms in critical_files:
            if self.executor.file_exists(file_path):
                try:
                    # Get file permissions via stat command
                    stdout, stderr, returncode = self.executor.execute_command(
                        ["stat", "-c", "%a", file_path],
                        timeout=5
                    )
                    if returncode == 0 and stdout.strip():
                        actual_perms = stdout.strip()
                        if actual_perms != expected_perms:
                            findings.append(
                                Finding(
                                    title=f"Incorrect permissions on {file_path}",
                                    description=f"File {file_path} has permissions {actual_perms}, expected {expected_perms}",
                                    severity=Severity.HIGH,
                                    category="config",
                                    recommendation=f"Set permissions on {file_path} to {expected_perms}",
                                )
                        )
                except Exception as e:
                    self.logger.error("Error checking file permissions", file=file_path, error=str(e))

        return findings

    def _check_network_security(self) -> List[Finding]:
        """Check network security configurations."""
        findings = []

        # Check if IP forwarding is disabled (should be for most servers)
        ip_forward_path = "/proc/sys/net/ipv4/ip_forward"
        if self.executor.file_exists(ip_forward_path):
            content = self.executor.read_file(ip_forward_path)
            if content and content.strip() == "1":
                findings.append(
                    Finding(
                        title="IP forwarding enabled",
                        description="IP forwarding is enabled, which may not be necessary",
                        severity=Severity.MEDIUM,
                        category="config",
                        recommendation="Disable IP forwarding if not required for routing",
                    )
                )

        # Check for ICMP redirects
        icmp_redirects_path = "/proc/sys/net/ipv4/conf/all/accept_redirects"
        if self.executor.file_exists(icmp_redirects_path):
            content = self.executor.read_file(icmp_redirects_path)
            if content and content.strip() == "1":
                findings.append(
                    Finding(
                        title="ICMP redirects accepted",
                        description="System accepts ICMP redirects, which can be a security risk",
                        severity=Severity.MEDIUM,
                        category="config",
                        recommendation="Disable ICMP redirect acceptance",
                    )
                )

        return findings

