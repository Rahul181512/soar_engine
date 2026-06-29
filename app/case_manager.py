from datetime import datetime, timezone

from app.logger import soar_logger
from app.models import Case, CaseStatus, TimelineEvent, NormalizedAlert
from app.rbac import get_user

CASE_STORE: dict[str, Case] = {}

def add_timeline_event(case: Case, event: str, detail: str) -> None:
    timeline = TimelineEvent(
        timestamp=datetime.now(timezone.utc).isoformat(),
        event=event,
        detail=detail,
    )
    case.timeline.append(timeline)
    case.updated_at = datetime.now(timezone.utc).isoformat()
    soar_logger.info(f"Timeline Updated | Case={case.case_id} | Event={event}")

def create_case(alert: NormalizedAlert) -> Case:
    for existing in CASE_STORE.values():
        if existing.alert_id == alert.alert_id:
            soar_logger.warning(
                f"Duplicate case prevented | Alert={alert.alert_id}"
            )
            return existing

    case = Case(
        alert_id=alert.alert_id,
        alert_type=alert.alert_type,
        source_ip=alert.source_ip,
        severity=alert.severity,
        risk_score=alert.risk_score,
        risk_level=alert.risk_level.value if alert.risk_level else None,
        action_taken=alert.action_taken,
    )

    add_timeline_event(case, "Case Created", "Incident case created automatically.")
    CASE_STORE[case.case_id] = case
    soar_logger.info(f"Case Created | Case={case.case_id}")
    return case

def get_case(case_id: str) -> Case | None:
    return CASE_STORE.get(case_id)

def get_all_cases() -> list[Case]:
    return list(CASE_STORE.values())

def assign_case(case_id: str, analyst: str) -> Case:
    case = get_case(case_id)
    if not case:
        raise ValueError("Case not found")

    if get_user(analyst) is None:
        raise ValueError("Analyst does not exist")

    case.assigned_to = analyst
    add_timeline_event(case, "Case Assigned", f"Assigned to {analyst}")
    soar_logger.info(f"Case Assigned | Case={case_id} | Analyst={analyst}")
    return case

def update_case_status(case_id: str, status: CaseStatus) -> Case:
    case = get_case(case_id)
    if not case:
        raise ValueError("Case not found")

    case.status = status
    add_timeline_event(case, "Status Updated", f"Status changed to {status.value}")
    soar_logger.info(f"Case Updated | Case={case_id} | Status={status.value}")
    return case

def close_case(case_id: str) -> Case:
    case = update_case_status(case_id, CaseStatus.CLOSED)
    add_timeline_event(case, "Case Closed", "Incident resolved successfully.")
    soar_logger.info(f"Case Closed | Case={case_id}")
    return case

def delete_case(case_id: str) -> bool:
    case = get_case(case_id)
    if not case:
        return False

    add_timeline_event(case, "Case Deleted", "Case removed from memory.")
    del CASE_STORE[case_id]
    soar_logger.info(f"Case Deleted | Case={case_id}")
    return True

def total_cases() -> int:
    return len(CASE_STORE)

def open_cases() -> int:
    return sum(1 for c in CASE_STORE.values() if c.status == CaseStatus.OPEN)

def closed_cases() -> int:
    return sum(1 for c in CASE_STORE.values() if c.status == CaseStatus.CLOSED)

def critical_cases() -> int:
    return sum(1 for c in CASE_STORE.values() if c.risk_level == "Critical")