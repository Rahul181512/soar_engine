import pytest
from datetime import datetime, timezone

from app.models import Alert, AlertType, SeverityLevel
from app.normalizer import normalize_alert
from app.enrichment import (
    enrich_alert,
    check_abuseipdb,
    check_virustotal,
)


@pytest.fixture
def normalized_alert():
    alert = Alert(
        alert_type=AlertType.BRUTE_FORCE,
        source_ip="45.67.89.10",
        severity=SeverityLevel.HIGH,
        timestamp=datetime.now(timezone.utc),
        description="Multiple failed SSH login attempts.",
        destination_ip="192.168.1.50",
        port=22,
    )

    return normalize_alert(alert)


def test_check_abuseipdb_returns_dict(normalized_alert):
    result = check_abuseipdb(normalized_alert.source_ip)

    assert isinstance(result, dict)


def test_check_abuseipdb_has_required_keys(normalized_alert):
    result = check_abuseipdb(normalized_alert.source_ip)

    assert "source" in result
    assert "ip" in result
    assert "abuse_score" in result
    assert "is_malicious" in result


def test_check_virustotal_returns_dict(normalized_alert):
    result = check_virustotal(normalized_alert.source_ip)

    assert isinstance(result, dict)


def test_check_virustotal_has_required_keys(normalized_alert):
    result = check_virustotal(normalized_alert.source_ip)

    assert "source" in result
    assert "ip" in result
    assert "malicious_votes" in result
    assert "is_malicious" in result


def test_enrich_alert_returns_alert(normalized_alert):
    result = enrich_alert(normalized_alert)

    assert result is not None
    assert result.alert_id == normalized_alert.alert_id


def test_enrich_alert_has_enrichment_data(normalized_alert):
    result = enrich_alert(normalized_alert)

    assert result.enrichment_data is not None


def test_enrich_alert_has_abuseipdb_data(normalized_alert):
    result = enrich_alert(normalized_alert)

    assert "abuseipdb" in result.enrichment_data


def test_enrich_alert_has_virustotal_data(normalized_alert):
    result = enrich_alert(normalized_alert)

    assert "virustotal" in result.enrichment_data


def test_enrich_alert_malicious_flag(normalized_alert):
    result = enrich_alert(normalized_alert)

    assert "is_malicious" in result.enrichment_data


def test_enrichment_contains_expected_structure(normalized_alert):
    result = enrich_alert(normalized_alert)

    enrichment = result.enrichment_data

    assert isinstance(enrichment, dict)
    assert "abuseipdb" in enrichment
    assert "virustotal" in enrichment
    assert "is_malicious" in enrichment