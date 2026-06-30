from datetime import datetime, timezone

from app.case_manager import (
    get_all_cases,
    get_case,
    total_cases,
    open_cases,
    closed_cases,
    critical_cases,
)
from app.models import CaseStatus
from app.logger import soar_logger


def assigned_cases() -> int:
    """
    Return number of assigned cases.
    """
    return sum(
        1
        for case in get_all_cases()
        if case.assigned_to is not None
    )


def get_recent_cases(limit: int = 5) -> list:
    """
    Return most recently created cases.
    """
    all_cases = get_all_cases()

    sorted_cases = sorted(
        all_cases,
        key=lambda c: c.created_at,
        reverse=True,
    )

    return [
        case.model_dump()
        for case in sorted_cases[:limit]
    ]


def get_recent_timeline(limit: int = 10) -> list:
    """
    Return latest timeline events from all cases.
    """
    timeline = []

    for case in get_all_cases():
        for event in case.timeline:
            timeline.append(
                {
                    "case_id": case.case_id,
                    "timestamp": event.timestamp,
                    "event": event.event,
                    "detail": event.detail,
                }
            )

    timeline.sort(
        key=lambda e: e["timestamp"],
        reverse=True,
    )

    return timeline[:limit]


def get_dashboard_summary() -> dict:
    """
    Return dashboard summary.
    """
    try:
        summary = {
            "generated_at": datetime.now(
                timezone.utc
            ).isoformat(),
            "total_cases": total_cases(),
            "open_cases": open_cases(),
            "closed_cases": closed_cases(),
            "critical_cases": critical_cases(),
            "assigned_cases": assigned_cases(),
            "recent_cases": get_recent_cases(),
            "recent_timeline": get_recent_timeline(),
        }

        soar_logger.info(
            "Dashboard summary generated successfully."
        )

        return summary

    except Exception:
        soar_logger.exception(
            "Dashboard summary generation failed."
        )
        raise ValueError(
            "Dashboard summary generation failed."
        )


def get_case_timeline(case_id: str) -> list:
    """
    Return timeline of a specific case.
    """
    case = get_case(case_id)

    if not case:
        soar_logger.warning(
            f"Case not found | ID={case_id}"
        )
        return []

    return [
        event.model_dump()
        for event in case.timeline
    ]


def get_cases_grouped_by_status() -> dict:
    """
    Group cases by status.
    """
    grouped = {
        CaseStatus.OPEN.value: [],
        CaseStatus.IN_PROGRESS.value: [],
        CaseStatus.RESOLVED.value: [],
        CaseStatus.CLOSED.value: [],
    }

    for case in get_all_cases():
        grouped[
            case.status.value
        ].append(
            case.model_dump()
        )

    soar_logger.info(
        "Cases grouped by status."
    )

    return grouped


def get_dashboard_statistics() -> dict:
    """
    Return statistics only.
    """
    return {
        "total_cases": total_cases(),
        "open_cases": open_cases(),
        "closed_cases": closed_cases(),
        "critical_cases": critical_cases(),
        "assigned_cases": assigned_cases(),
    }