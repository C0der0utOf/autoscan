"""CIS Benchmarks compliance checking."""

import platform
from pathlib import Path
from typing import Dict, List, Optional

import yaml

from src.core.logger import get_logger
from src.core.models import ComplianceResult
from src.core.remote_executor import RemoteExecutor

logger = get_logger(__name__)


class CISBenchmarkChecker:
    """CIS Benchmark compliance checker."""

    def __init__(self, target: str = "localhost", rules_file: Optional[Path] = None):
        """Initialize the CIS Benchmark checker."""
        self.logger = get_logger(self.__class__.__name__)
        self.target = target
        self.executor = RemoteExecutor(target=target)
        self.rules_file = rules_file or Path(__file__).parent.parent.parent / "configs" / "cis_linux_rules.yaml"
        self.rules = self._load_rules()

    def _load_rules(self) -> Dict:
        """Load CIS Benchmark rules from YAML file."""
        if not self.rules_file.exists():
            self.logger.warning("CIS rules file not found, using default rules", file=str(self.rules_file))
            return self._get_default_rules()

        try:
            with open(self.rules_file, "r") as f:
                return yaml.safe_load(f) or {}
        except Exception as e:
            self.logger.error("Failed to load CIS rules", error=str(e))
            return self._get_default_rules()

    def _get_default_rules(self) -> Dict:
        """Get default CIS Benchmark rules."""
        return {
            "rules": [
                {
                    "id": "1.1.1.1",
                    "name": "Ensure mounting of cramfs filesystems is disabled",
                    "check": "check_module_disabled",
                    "params": {"module": "cramfs"},
                    "severity": "medium",
                },
                {
                    "id": "1.1.1.2",
                    "name": "Ensure mounting of squashfs filesystems is disabled",
                    "check": "check_module_disabled",
                    "params": {"module": "squashfs"},
                    "severity": "low",
                },
                {
                    "id": "1.1.1.3",
                    "name": "Ensure mounting of udf filesystems is disabled",
                    "check": "check_module_disabled",
                    "params": {"module": "udf"},
                    "severity": "low",
                },
                {
                    "id": "1.1.2",
                    "name": "Ensure /tmp is configured",
                    "check": "check_tmp_mount",
                    "severity": "high",
                },
                {
                    "id": "1.1.3",
                    "name": "Ensure nodev option set on /tmp partition",
                    "check": "check_mount_option",
                    "params": {"mount_point": "/tmp", "option": "nodev"},
                    "severity": "medium",
                },
                {
                    "id": "1.1.4",
                    "name": "Ensure nosuid option set on /tmp partition",
                    "check": "check_mount_option",
                    "params": {"mount_point": "/tmp", "option": "nosuid"},
                    "severity": "medium",
                },
                {
                    "id": "1.1.5",
                    "name": "Ensure noexec option set on /tmp partition",
                    "check": "check_mount_option",
                    "params": {"mount_point": "/tmp", "option": "noexec"},
                    "severity": "medium",
                },
                {
                    "id": "1.2.1",
                    "name": "Ensure package manager repositories are configured",
                    "check": "check_package_repos",
                    "severity": "high",
                },
                {
                    "id": "1.2.2",
                    "name": "Ensure GPG keys are configured",
                    "check": "check_gpg_keys",
                    "severity": "high",
                },
                {
                    "id": "1.3.1",
                    "name": "Ensure AIDE is installed",
                    "check": "check_package_installed",
                    "params": {"package": "aide"},
                    "severity": "medium",
                },
                {
                    "id": "1.3.2",
                    "name": "Ensure filesystem integrity is regularly checked",
                    "check": "check_aide_cron",
                    "severity": "medium",
                },
            ]
        }

    def check_compliance(self) -> List[ComplianceResult]:
        """
        Check system compliance against CIS Benchmarks.

        Returns:
            List of compliance results
        """
        self.logger.info("Starting CIS Benchmark compliance check")
        results = []

        if platform.system() != "Linux":
            self.logger.warning("CIS Benchmarks are primarily for Linux systems", system=platform.system())
            return results

        rules = self.rules.get("rules", [])
        for rule in rules:
            try:
                passed = self._check_rule(rule)
                result = ComplianceResult(
                    framework="cis",
                    rule_id=rule["id"],
                    rule_name=rule["name"],
                    passed=1 if passed else 0,
                    description=rule.get("description", ""),
                    remediation=self._get_remediation(rule),
                )
                results.append(result)
            except Exception as e:
                self.logger.error("Error checking rule", rule_id=rule.get("id"), error=str(e))
                result = ComplianceResult(
                    framework="cis",
                    rule_id=rule.get("id", "unknown"),
                    rule_name=rule.get("name", "Unknown rule"),
                    passed=0,
                    description=f"Error checking rule: {str(e)}",
                )
                results.append(result)

        self.logger.info("CIS Benchmark compliance check completed", results_count=len(results))
        return results

    def _check_rule(self, rule: Dict) -> bool:
        """Check a single CIS rule."""
        check_type = rule.get("check")
        params = rule.get("params", {})

        check_methods = {
            "check_module_disabled": self._check_module_disabled,
            "check_mount_option": self._check_mount_option,
            "check_package_repos": self._check_package_repos,
            "check_gpg_keys": self._check_gpg_keys,
            "check_package_installed": self._check_package_installed,
            "check_aide_cron": self._check_aide_cron,
            "check_tmp_mount": self._check_tmp_mount,
        }

        method = check_methods.get(check_type)
        if not method:
            self.logger.warning("Unknown check type", check_type=check_type)
            return False

        return method(**params)

    def _check_module_disabled(self, module: str) -> bool:
        """Check if a kernel module is disabled."""
        stdout, stderr, returncode = self.executor.execute_command(
            ["modprobe", "-n", "-v", module],
            timeout=5
        )
        # If modprobe returns successfully, the module can be loaded (not disabled)
        return returncode != 0

    def _check_mount_option(self, mount_point: str, option: str) -> bool:
        """Check if a mount option is set."""
        stdout, stderr, returncode = self.executor.execute_command(["mount"], timeout=5)
        if returncode != 0:
            return False
        for line in stdout.split("\n"):
            if mount_point in line and option in line:
                return True
        return False

    def _check_tmp_mount(self) -> bool:
        """Check if /tmp is a separate mount."""
        return self._check_mount_option("/tmp", "/tmp")

    def _check_package_repos(self) -> bool:
        """Check if package repositories are configured."""
        # Check for common package managers
        if (self.executor.file_exists("/etc/apt/sources.list") or 
            self.executor.file_exists("/etc/apt/sources.list.d")):
            return True
        if self.executor.file_exists("/etc/yum.repos.d"):
            return True
        if self.executor.file_exists("/etc/pacman.conf"):
            return True
        return False

    def _check_gpg_keys(self) -> bool:
        """Check if GPG keys are configured."""
        # Check for GPG key directories
        gpg_dirs = [
            "/etc/apt/trusted.gpg.d",
            "/usr/share/keyrings",
            "/etc/pki/rpm-gpg",
        ]
        for gpg_dir in gpg_dirs:
            if self.executor.file_exists(gpg_dir):
                # Check if directory has files
                stdout, _, returncode = self.executor.execute_command(
                    ["test", "-n", "$(ls -A " + gpg_dir + " 2>/dev/null)"],
                    timeout=5
                )
                if returncode == 0:
                    return True
        return False

    def _check_package_installed(self, package: str) -> bool:
        """Check if a package is installed."""
        # Try different package managers
        for cmd in [["dpkg", "-l", package], ["rpm", "-q", package], ["pacman", "-Q", package]]:
            _, _, returncode = self.executor.execute_command(cmd, timeout=5)
            if returncode == 0:
                return True
        return False

    def _check_aide_cron(self) -> bool:
        """Check if AIDE cron job is configured."""
        # Check crontab files
        crontab_files = [
            "/etc/crontab",
            "/etc/cron.daily/aide",
            "/etc/cron.weekly/aide",
        ]
        for crontab_file in crontab_files:
            content = self.executor.read_file(crontab_file)
            if content and "aide" in content.lower():
                return True
        return False

    def _get_remediation(self, rule: Dict) -> str:
        """Get remediation guidance for a rule."""
        rule_id = rule.get("id", "")
        check_type = rule.get("check", "")

        remediation_templates = {
            "check_module_disabled": f"To remediate {rule_id}, add the module to /etc/modprobe.d/blacklist.conf",
            "check_mount_option": f"To remediate {rule_id}, add the option to /etc/fstab",
            "check_package_installed": f"To remediate {rule_id}, install the required package using your package manager",
        }

        return remediation_templates.get(check_type, f"Review CIS Benchmark documentation for {rule_id}")

