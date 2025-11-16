"""Configuration management for the security automation platform."""

import os
from pathlib import Path
from typing import Optional

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    # Application
    app_name: str = "Security Automation Platform"
    app_version: str = "0.1.0"
    debug: bool = False

    # Database
    database_url: str = "sqlite:///./security_platform.db"
    database_echo: bool = False

    # API
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    api_reload: bool = False

    # CVE Database
    nvd_api_key: Optional[str] = None
    cve_cache_dir: Path = Path("./data/cve_cache")
    cve_cache_ttl_hours: int = 24

    # Scanning
    scan_timeout_seconds: int = 300
    max_concurrent_scans: int = 5

    # Reporting
    reports_dir: Path = Path("./reports")
    default_report_format: str = "json"

    # Logging
    log_level: str = "INFO"
    log_format: str = "json"  # json or text

    def __init__(self, **kwargs):
        """Initialize settings and create necessary directories."""
        super().__init__(**kwargs)
        # Create directories if they don't exist
        self.cve_cache_dir.mkdir(parents=True, exist_ok=True)
        self.reports_dir.mkdir(parents=True, exist_ok=True)


# Global settings instance
settings = Settings()

