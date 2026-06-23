import pytest
from datetime import datetime, timezone
from app.models import Alert, AlertType, SeverityLevel, RiskLevel
from app.normalizer import normalize_alert
from app.risk_engine import (
    calculate_risk_score,
    assign_risk_level,
    evaluate_alert,
    is_critical
)


@pytest.fixture
def critical_alert():
    alert = Alert(
        alert_type=AlertType.RANSOMWARE,
        source_ip="185.220.101.45",
        severity=SeverityLevel.CRITICAL,
        timestamp=datetime.now(timezone.utc),
        description="Ransomware encryption activity detected.",
        destination_ip="192.168.1.100",
        port=445
    )
    return normalize_alert(alert)


@pytest.fixture
def low_alert():
    alert = Alert(
        alert_type=AlertType.PHISHING,
        source_ip="198.51.100.42",
        severity=SeverityLevel.LOW,
        timestamp=datetime.now(timezone.utc),
        description="Phishing email detected.",
    )
    return normalize_alert(alert)


def test_calculate_risk_score_returns_float(critical_alert):
    """
    Test risk score is a float.
    """
    score = calculate_risk_score(critical_alert)
    assert isinstance(score, float)


def test_calculate_risk_score_max_100(critical_alert):
    """
    Test risk score never exceeds 100.
    """
    score = calculate_risk_score(critical_alert)
    assert score <= 100.0


def test_calculate_risk_score_min_0(low_alert):
    """
    Test risk score is never negative.
    """
    score = calculate_risk_score(low_alert)
    assert score >= 0.0


def test_ransomware_critical_score(critical_alert):
    """
    Test Ransomware + Critical = max score.
    """
    score = calculate_risk_score(critical_alert)
    assert score == 100.0


def test_assign_risk_level_critical(critical_alert):
    """
    Test high score returns Critical level.
    """
    level = assign_risk_level(95.0)
    assert level == RiskLevel.CRITICAL


def test_assign_risk_level_low(low_alert):
    """
    Test low score returns Low level.
    """
    level = assign_risk_level(10.0)
    assert level == RiskLevel.LOW


def test_evaluate_alert_updates_risk_score(critical_alert):
    """
    Test evaluate_alert sets risk_score on alert.
    """
    result = evaluate_alert(critical_alert)
    assert result.risk_score is not None


def test_evaluate_alert_updates_risk_level(critical_alert):
    """
    Test evaluate_alert sets risk_level on alert.
    """
    result = evaluate_alert(critical_alert)
    assert result.risk_level is not None


def test_is_critical_true(critical_alert):
    """
    Test is_critical returns True for critical alert.
    """
    evaluated = evaluate_alert(critical_alert)
    assert is_critical(evaluated) is True


def test_is_critical_false(low_alert):
    """
    Test is_critical returns False for low alert.
    """
    evaluated = evaluate_alert(low_alert)
    assert is_critical(evaluated) is False