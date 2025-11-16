"""Tests for configuration analysis."""

import pytest

from src.config_analyzer.system_hardening import SystemHardeningAnalyzer


def test_system_hardening_analyzer_initialization():
    """Test system hardening analyzer initialization."""
    analyzer = SystemHardeningAnalyzer()
    assert analyzer.logger is not None


def test_system_hardening_analysis():
    """Test system hardening analysis."""
    analyzer = SystemHardeningAnalyzer()
    findings = analyzer.analyze()

    # Should return a list of findings
    assert isinstance(findings, list)
    # Each finding should have required fields
    for finding in findings:
        assert hasattr(finding, "title")
        assert hasattr(finding, "description")
        assert hasattr(finding, "severity")
        assert hasattr(finding, "category")

