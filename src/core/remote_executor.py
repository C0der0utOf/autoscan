"""Remote execution module for SSH-based scanning."""

import subprocess
from pathlib import Path
from typing import Optional

from src.core.logger import get_logger

logger = get_logger(__name__)


class RemoteExecutor:
    """Execute commands and read files on remote systems via SSH."""

    def __init__(self, target: str, user: Optional[str] = None, key_file: Optional[str] = None):
        """
        Initialize remote executor.

        Args:
            target: Target hostname or IP address
            user: SSH username (optional, defaults to current user)
            key_file: Path to SSH private key file (optional)
        """
        self.target = target
        self.user = user
        self.key_file = key_file
        self.logger = get_logger(self.__class__.__name__)
        self._is_local = self._check_if_local()

    def _check_if_local(self) -> bool:
        """Check if target is localhost."""
        local_indicators = ["localhost", "127.0.0.1", "::1", "0.0.0.0"]
        return self.target.lower() in local_indicators

    def is_local(self) -> bool:
        """Check if this is a local execution."""
        return self._is_local

    def execute_command(self, command: list[str], timeout: int = 10) -> tuple[str, str, int]:
        """
        Execute a command on the target system.

        Args:
            command: Command as list of strings
            timeout: Command timeout in seconds

        Returns:
            Tuple of (stdout, stderr, returncode)
        """
        if self._is_local:
            # Execute locally
            try:
                result = subprocess.run(
                    command,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                )
                return result.stdout, result.stderr, result.returncode
            except subprocess.TimeoutExpired:
                return "", "Command timed out", 1
            except Exception as e:
                return "", str(e), 1
        else:
            # Execute via SSH
            ssh_command = self._build_ssh_command(command)
            try:
                result = subprocess.run(
                    ssh_command,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                )
                return result.stdout, result.stderr, result.returncode
            except subprocess.TimeoutExpired:
                return "", "SSH command timed out", 1
            except Exception as e:
                self.logger.error("SSH execution failed", error=str(e), target=self.target)
                return "", f"SSH error: {str(e)}", 1

    def read_file(self, file_path: str) -> Optional[str]:
        """
        Read a file from the target system.

        Args:
            file_path: Path to file on target system

        Returns:
            File contents as string, or None if file doesn't exist or can't be read
        """
        if self._is_local:
            # Read local file
            try:
                path = Path(file_path)
                if path.exists():
                    return path.read_text()
                return None
            except Exception as e:
                self.logger.error("Failed to read local file", file=file_path, error=str(e))
                return None
        else:
            # Read remote file via SSH
            command = ["cat", file_path]
            stdout, stderr, returncode = self.execute_command(command)
            if returncode == 0:
                return stdout
            else:
                self.logger.warning("Failed to read remote file", file=file_path, error=stderr)
                return None

    def file_exists(self, file_path: str) -> bool:
        """
        Check if a file exists on the target system.

        Args:
            file_path: Path to file on target system

        Returns:
            True if file exists, False otherwise
        """
        if self._is_local:
            return Path(file_path).exists()
        else:
            command = ["test", "-f", file_path]
            _, _, returncode = self.execute_command(command)
            return returncode == 0

    def _build_ssh_command(self, command: list[str]) -> list[str]:
        """Build SSH command with optional user and key file."""
        ssh_cmd = ["ssh"]
        
        # Add SSH options for non-interactive mode
        ssh_cmd.extend(["-o", "StrictHostKeyChecking=no"])
        ssh_cmd.extend(["-o", "BatchMode=yes"])
        ssh_cmd.extend(["-o", "ConnectTimeout=5"])
        
        if self.key_file:
            ssh_cmd.extend(["-i", self.key_file])
        
        # Build target string
        if self.user:
            target_str = f"{self.user}@{self.target}"
        else:
            target_str = self.target
        
        ssh_cmd.append(target_str)
        
        # Add the actual command
        ssh_cmd.extend(command)
        
        return ssh_cmd

