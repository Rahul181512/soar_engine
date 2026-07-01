import pytest
from datetime import datetime, timezone
from app.models import Alert, AlertType, SeverityLevel, CaseStatus
from app.normalizer import normalize_alert
from app.enrichment import enrich_alert
from app.risk_engine import evaluate_alert
from app.case_manager import (
    create_case,
    get_case,
    get_all_cases,
    assign_case,
    update_case_status,
    close_case,
    delete_case,
    total_cases,
    open_cases,
    closed_cases,
    critical_cases,
    CASE_STORE,
)


# ==========================================================
# Fixtures
# ==========================================================

def make_evaluated_alert():
    """
    Helper to create a fully evaluated alert.
    """
    alert = Alert(
        alert_type=AlertType.RANSOMWARE,
        source_ip="185.220.101.45",
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
# create_case tests
# ==========================================================

def test_create_case_returns_case():
    alert = make_evaluated_alert()
    case = create_case(alert)
    assert case is not None


def test_create_case_has_case_id():
    alert = make_evaluated_alert()
    case = create_case(alert)
    assert case.case_id is not None
    assert len(case.case_id) > 0


def test_create_case_has_correct_alert_id():
    alert = make_evaluated_alert()
    case = create_case(alert)
    assert case.alert_id == alert.alert_id


def test_create_case_has_correct_source_ip():
    alert = make_evaluated_alert()
    case = create_case(alert)
    assert case.source_ip == alert.source_ip


def test_create_case_default_status_is_open():
    alert = make_evaluated_alert()
    case = create_case(alert)
    assert case.status == CaseStatus.OPEN


def test_create_case_has_timeline():
    alert = make_evaluated_alert()
    case = create_case(alert)
    assert len(case.timeline) > 0


def test_create_case_prevents_duplicates():
    """
    Same alert should not create two cases.
    """
    alert = make_evaluated_alert()
    case1 = create_case(alert)
    case2 = create_case(alert)
    assert case1.case_id == case2.case_id


# ==========================================================
# get_case tests
# ==========================================================

def test_get_case_returns_correct_case():
    alert = make_evaluated_alert()
    case = create_case(alert)
    fetched = get_case(case.case_id)
    assert fetched is not None
    assert fetched.case_id == case.case_id


def test_get_case_invalid_id_returns_none():
    result = get_case("invalid-case-id")
    assert result is None


# ==========================================================
# get_all_cases tests
# ==========================================================

def test_get_all_cases_returns_list():
    cases = get_all_cases()
    assert isinstance(cases, list)


def test_get_all_cases_count():
    alert = make_evaluated_alert()
    create_case(alert)
    cases = get_all_cases()
    assert len(cases) == 1


# ==========================================================
# assign_case tests
# ==========================================================

def test_assign_case_success():
    alert = make_evaluated_alert()
    case = create_case(alert)
    updated = assign_case(case.case_id, "analyst_user")
    assert updated.assigned_to == "analyst_user"


def test_assign_case_adds_timeline_event():
    alert = make_evaluated_alert()
    case = create_case(alert)
    updated = assign_case(case.case_id, "analyst_user")
    assert updated.timeline[-1].event == "Case Assigned"


def test_assign_case_invalid_case_raises_error():
    with pytest.raises(ValueError, match="Case not found"):
        assign_case("invalid-id", "analyst_user")


def test_assign_case_invalid_analyst_raises_error():
    alert = make_evaluated_alert()
    case = create_case(alert)
    with pytest.raises(ValueError, match="Analyst does not exist"):
        assign_case(case.case_id, "unknown_analyst")


# ==========================================================
# update_case_status tests
# ==========================================================

def test_update_case_status_success():
    alert = make_evaluated_alert()
    case = create_case(alert)
    updated = update_case_status(case.case_id, CaseStatus.IN_PROGRESS)
    assert updated.status == CaseStatus.IN_PROGRESS


def test_update_case_status_adds_timeline():
    alert = make_evaluated_alert()
    case = create_case(alert)
    updated = update_case_status(case.case_id, CaseStatus.RESOLVED)
    assert updated.timeline[-1].event == "Status Updated"


def test_update_case_status_invalid_case():
    with pytest.raises(ValueError, match="Case not found"):
        update_case_status("invalid-id", CaseStatus.RESOLVED)


# ==========================================================
# close_case tests
# ==========================================================

def test_close_case_success():
    alert = make_evaluated_alert()
    case = create_case(alert)
    closed = close_case(case.case_id)
    assert closed.status == CaseStatus.CLOSED


def test_close_case_adds_timeline():
    alert = make_evaluated_alert()
    case = create_case(alert)
    closed = close_case(case.case_id)
    assert closed.timeline[-1].event == "Case Closed"


def test_close_case_invalid_id():
    with pytest.raises(ValueError, match="Case not found"):
        close_case("invalid-id")


# ==========================================================
# delete_case tests
# ==========================================================

def test_delete_case_success():
    alert = make_evaluated_alert()
    case = create_case(alert)
    result = delete_case(case.case_id)
    assert result is True


def test_delete_case_removes_from_store():
    alert = make_evaluated_alert()
    case = create_case(alert)
    delete_case(case.case_id)
    assert get_case(case.case_id) is None


def test_delete_case_invalid_id():
    result = delete_case("invalid-id")
    assert result is False


# ==========================================================
# Stats tests
# ==========================================================

def test_total_cases():
    alert = make_evaluated_alert()
    create_case(alert)
    assert total_cases() == 1


def test_open_cases():
    alert = make_evaluated_alert()
    create_case(alert)
    assert open_cases() == 1


def test_closed_cases():
    alert = make_evaluated_alert()
    case = create_case(alert)
    close_case(case.case_id)
    assert closed_cases() == 1


def test_critical_cases():
    alert = make_evaluated_alert()
    create_case(alert)
    assert critical_cases() == 1