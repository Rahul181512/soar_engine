from datetime import datetime, timezone
from app.models import Alert, AlertType, SeverityLevel, CaseStatus, NormalizedAlert
from app.normalizer import normalize_alert
from app.enrichment import enrich_alert
from app.risk_engine import evaluate_alert
from app.case_manager import (
    create_case,
    close_case,
    assign_case,
    CASE_STORE,
)
from app.dashboard import (
    get_dashboard_summary,
    get_dashboard_statistics,
    get_case_timeline,
    get_cases_grouped_by_status,
    get_recent_cases,
    get_recent_timeline,
    assigned_cases,
)


# ==========================================================
# Fixtures
# ==========================================================

def make_evaluated_alert(
    ip: str = "185.220.101.45"
) -> NormalizedAlert:
    """
    Helper to create a fully evaluated alert.
    """
    alert = Alert(
        alert_type=AlertType.RANSOMWARE,
        source_ip=ip,
        severity=SeverityLevel.CRITICAL,
        timestamp=datetime.now(timezone.utc),
        description="Ransomware detected.",
        destination_ip="192.168.1.100",
        port=445,
    )
    normalized = normalize_alert(alert)
    enriched = enrich_alert(normalized)
    evaluated = evaluate_alert(enriched)
    return evaluated


def setup_function():
    """
    Clear CASE_STORE before each test.
    """
    CASE_STORE.clear()


# ==========================================================
# get_dashboard_summary tests
# ==========================================================

def test_dashboard_summary_returns_dict():
    result = get_dashboard_summary()
    assert isinstance(result, dict)


def test_dashboard_summary_has_required_keys():
    result = get_dashboard_summary()
    assert "generated_at" in result
    assert "total_cases" in result
    assert "open_cases" in result
    assert "closed_cases" in result
    assert "critical_cases" in result
    assert "assigned_cases" in result
    assert "recent_cases" in result
    assert "recent_timeline" in result


def test_dashboard_summary_generated_at_is_string():
    result = get_dashboard_summary()
    assert isinstance(result["generated_at"], str)


def test_dashboard_summary_counts_are_integers():
    result = get_dashboard_summary()
    assert isinstance(result["total_cases"], int)
    assert isinstance(result["open_cases"], int)
    assert isinstance(result["closed_cases"], int)
    assert isinstance(result["critical_cases"], int)
    assert isinstance(result["assigned_cases"], int)


# ==========================================================
# get_dashboard_statistics tests
# ==========================================================

def test_dashboard_statistics_returns_dict():
    result = get_dashboard_statistics()
    assert isinstance(result, dict)


def test_dashboard_statistics_has_required_keys():
    result = get_dashboard_statistics()
    assert "total_cases" in result
    assert "open_cases" in result
    assert "closed_cases" in result
    assert "critical_cases" in result
    assert "assigned_cases" in result


def test_dashboard_statistics_correct_count():
    alert = make_evaluated_alert()
    create_case(alert)
    result = get_dashboard_statistics()
    assert result["total_cases"] == 1
    assert result["open_cases"] == 1
    assert result["closed_cases"] == 0


def test_dashboard_empty():
    """
    Empty dashboard should return all zeros.
    """
    result = get_dashboard_statistics()
    assert result["total_cases"] == 0
    assert result["open_cases"] == 0
    assert result["closed_cases"] == 0
    assert result["critical_cases"] == 0


# ==========================================================
# get_case_timeline tests
# ==========================================================

def test_case_timeline_returns_list():
    alert = make_evaluated_alert()
    case = create_case(alert)
    timeline = get_case_timeline(case.case_id)
    assert isinstance(timeline, list)


def test_case_timeline_has_events():
    alert = make_evaluated_alert()
    case = create_case(alert)
    timeline = get_case_timeline(case.case_id)
    assert len(timeline) > 0


def test_case_timeline_event_has_required_keys():
    alert = make_evaluated_alert()
    case = create_case(alert)
    timeline = get_case_timeline(case.case_id)
    for event in timeline:
        assert "timestamp" in event
        assert "event" in event
        assert "detail" in event


def test_case_timeline_invalid_case_returns_empty():
    timeline = get_case_timeline("invalid-case-id")
    assert timeline == []


# ==========================================================
# get_cases_grouped_by_status tests
# ==========================================================

def test_cases_grouped_by_status_returns_dict():
    result = get_cases_grouped_by_status()
    assert isinstance(result, dict)


def test_cases_grouped_by_status_has_all_statuses():
    result = get_cases_grouped_by_status()
    assert CaseStatus.OPEN.value in result
    assert CaseStatus.IN_PROGRESS.value in result
    assert CaseStatus.RESOLVED.value in result
    assert CaseStatus.CLOSED.value in result


def test_cases_grouped_open_case():
    alert = make_evaluated_alert()
    create_case(alert)
    result = get_cases_grouped_by_status()
    assert len(result[CaseStatus.OPEN.value]) == 1


def test_cases_grouped_closed_case():
    alert = make_evaluated_alert()
    case = create_case(alert)
    close_case(case.case_id)
    result = get_cases_grouped_by_status()
    assert len(result[CaseStatus.CLOSED.value]) == 1


# ==========================================================
# get_recent_cases tests
# ==========================================================

def test_get_recent_cases_returns_list():
    result = get_recent_cases()
    assert isinstance(result, list)


def test_get_recent_cases_limit():
    for i in range(1, 4):
        alert = make_evaluated_alert(ip=f"10.0.0.{i}")
        create_case(alert)

    result = get_recent_cases(limit=2)
    assert len(result) == 2


def test_get_recent_cases_returns_dicts():
    alert = make_evaluated_alert()
    create_case(alert)
    result = get_recent_cases()
    for case in result:
        assert isinstance(case, dict)


# ==========================================================
# get_recent_timeline tests
# ==========================================================

def test_get_recent_timeline_returns_list():
    result = get_recent_timeline()
    assert isinstance(result, list)


def test_get_recent_timeline_has_events():
    alert = make_evaluated_alert()
    create_case(alert)
    result = get_recent_timeline()
    assert len(result) > 0


def test_get_recent_timeline_event_has_required_keys():
    alert = make_evaluated_alert()
    create_case(alert)
    result = get_recent_timeline()
    for event in result:
        assert "case_id" in event
        assert "timestamp" in event
        assert "event" in event
        assert "detail" in event


def test_get_recent_timeline_limit():
    alert = make_evaluated_alert()
    create_case(alert)
    result = get_recent_timeline(limit=1)
    assert len(result) == 1


# ==========================================================
# assigned_cases tests
# ==========================================================

def test_assigned_cases_initially_zero():
    alert = make_evaluated_alert()
    create_case(alert)
    assert assigned_cases() == 0


def test_assigned_cases_after_assignment():
    alert = make_evaluated_alert()
    case = create_case(alert)
    case = assign_case(case.case_id, "analyst_user")
    assert assigned_cases() == 1
    assert case.assigned_to == "analyst_user"  # ✅ Added