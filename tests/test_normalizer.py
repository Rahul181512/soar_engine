import pytest
from datetime import datetime, timezone
from pydantic import ValidationError

from app.models import Alert, AlertType, SeverityLevel
from app.normalizer import normalize_alert


# Sample valid alert fixture
@pytest.fixture
def sample_alert():
    return Alert(
        alert_type=AlertType.BRUTE_FORCE,
        source_ip="45.67.89.10",
        severity=SeverityLevel.HIGH,
        timestamp=datetime.now(timezone.utc),
        description="Multiple failed SSH login attempts.",
        destination_ip="192.168.1.50",
        port=22
    )


def test_normalize_alert_returns_normalized_alert(sample_alert):
    result = normalize_alert(sample_alert)
    assert result is not None


def test_normalize_alert_id_generated(sample_alert):
    result = normalize_alert(sample_alert)

    assert result.alert_id is not None
    assert len(result.alert_id) > 0


def test_unique_alert_ids(sample_alert):
    result1 = normalize_alert(sample_alert)
    result2 = normalize_alert(sample_alert)

    assert result1.alert_id != result2.alert_id


def test_normalize_alert_type(sample_alert):
    result = normalize_alert(sample_alert)

    assert result.alert_type == "Brute Force"


def test_normalize_severity(sample_alert):
    result = normalize_alert(sample_alert)

    assert result.severity == "high"


def test_normalize_timestamp_utc(sample_alert):
    result = normalize_alert(sample_alert)

    assert "UTC" in result.normalized_timestamp


def test_normalize_source_ip(sample_alert):
    result = normalize_alert(sample_alert)

    assert result.source_ip == "45.67.89.10"


def test_normalize_destination_ip(sample_alert):
    result = normalize_alert(sample_alert)

    assert result.destination_ip == "192.168.1.50"


def test_normalize_port(sample_alert):
    result = normalize_alert(sample_alert)

    assert result.port == 22


def test_normalize_alert_without_optional_fields():
    alert = Alert(
        alert_type=AlertType.PHISHING,
        source_ip="198.51.100.42",
        severity=SeverityLevel.MEDIUM,
        timestamp=datetime.now(timezone.utc),
    )

    result = normalize_alert(alert)

    assert result is not None
    assert result.destination_ip is None
    assert result.port is None


def test_normalize_invalid_ip():
    with pytest.raises(ValidationError):
        Alert(
            alert_type=AlertType.MALWARE,
            source_ip="999.999.999.999",
            severity=SeverityLevel.HIGH,
            timestamp=datetime.now(timezone.utc),
        )