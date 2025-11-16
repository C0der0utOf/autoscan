"""Tests for compliance checking."""

import pytest

from src.compliance.cis_benchmarks import CISBenchmarkChecker


def test_cis_checker_initialization():
    """Test CIS checker initialization."""
    checker = CISBenchmarkChecker()
    assert checker.rules is not None
    assert isinstance(checker.rules, dict)


def test_cis_compliance_check():
    """Test CIS compliance checking."""
    checker = CISBenchmarkChecker()
    results = checker.check_compliance()

    # Should return a list of compliance results
    assert isinstance(results, list)
    # Each result should have required fields
    for result in results:
        assert hasattr(result, "framework")
        assert hasattr(result, "rule_id")
        assert hasattr(result, "rule_name")
        assert hasattr(result, "passed")

