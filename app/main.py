from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware

from app.models import Alert, NormalizedAlert, RiskLevel, CaseStatus
from app.normalizer import normalize_alert
from app.enrichment import enrich_alert
from app.risk_engine import evaluate_alert
from app.playbooks import (
    execute_playbook,
    get_blocked_ips,
    get_isolated_hosts,
)
from app.case_manager import (
    create_case,
    get_case,
    get_all_cases,
    assign_case,
    update_case_status,
    close_case,
    delete_case,
)
from app.dashboard import (
    get_dashboard_summary,
    get_dashboard_statistics,
    get_case_timeline,
    get_cases_grouped_by_status,
)
from app.rbac import (
    has_permission,
    can_approve_high_impact,
    get_all_users,
    get_available_roles,
)
from app.logger import soar_logger
from app.config import settings


# In-memory alert store
alert_store: list[NormalizedAlert] = []


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description=(
        "Automated SOAR Incident Containment Engine "
        "for Enterprise Security Operations."
    ),
)


# -----------------------------
# CORS
# -----------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# -----------------------------
# Startup Event
# -----------------------------
@app.on_event("startup")
async def startup_event():
    soar_logger.info(
        f"{settings.APP_NAME} v{settings.APP_VERSION} started successfully"
    )


# -----------------------------
# Home
# -----------------------------
@app.get("/", tags=["Home"], summary="SOAR Engine Home")
def home() -> dict:
    return {
        "message": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "docs": "/docs",
        "health": "/health",
    }


# -----------------------------
# Health Check
# -----------------------------
@app.get("/health", tags=["Health"], summary="Health check endpoint")
def health_check() -> dict:
    return {
        "status": "healthy",
        "app": settings.APP_NAME,
        "version": settings.APP_VERSION,
    }


# -----------------------------
# Main Alert Endpoint
# -----------------------------
@app.post(
    "/alerts",
    tags=["Alerts"],
    summary="Process SIEM alert",
    status_code=status.HTTP_201_CREATED,
)
def ingest_alert(alert: Alert) -> dict:
    try:
        soar_logger.info(
            f"Alert received | Type: {alert.alert_type} | IP: {alert.source_ip}"
        )

        # Step 1: Normalize
        normalized = normalize_alert(alert)
        soar_logger.info(f"Step 1 Complete | ID: {normalized.alert_id}")

        # Step 2: Enrich
        enriched = enrich_alert(normalized)
        soar_logger.info(f"Step 2 Complete | ID: {enriched.alert_id}")

        # Step 3: Risk Evaluation
        evaluated = evaluate_alert(enriched)
        soar_logger.info(
            f"Step 3 Complete | ID: {evaluated.alert_id} | "
            f"Score: {evaluated.risk_score} | Level: {evaluated.risk_level}"
        )

        # Step 4: Playbook Execution
        playbook_result = execute_playbook(evaluated)
        soar_logger.info(
            f"Step 4 Complete | ID: {evaluated.alert_id} | "
            f"Action: {playbook_result['action']}"
        )

        # Save Alert
        alert_store.append(evaluated)

        # Step 5: Create Case
        case = create_case(evaluated)
        soar_logger.info(f"Step 5 Complete | Case: {case.case_id}")

        return {
            "message": "Alert processed successfully",
            "alert_id": evaluated.alert_id,
            "case_id": case.case_id,
            "risk_score": evaluated.risk_score,
            "risk_level": (
                evaluated.risk_level.value if evaluated.risk_level else None
            ),
            "action_taken": playbook_result["action"],
            "playbook_message": playbook_result["message"],
        }

    except Exception:
        soar_logger.exception("Alert processing failed")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Alert processing failed",
        )


# -----------------------------
# Get All Alerts
# -----------------------------
@app.get("/alerts", tags=["Alerts"], summary="Get all processed alerts")
def get_all_alerts() -> dict:
    return {"total": len(alert_store), "alerts": alert_store}


# -----------------------------
# Get Alert By ID
# -----------------------------
@app.get("/alerts/{alert_id}", tags=["Alerts"], summary="Get alert by ID")
def get_alert(alert_id: str):
    for alert in alert_store:
        if alert.alert_id == alert_id:
            return alert

    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"Alert {alert_id} not found",
    )


# -----------------------------
# Blocked IPs
# -----------------------------
@app.get("/blocked-ips", tags=["Containment"], summary="Get blocked IPs")
def blocked_ips() -> dict:
    ips = get_blocked_ips()
    return {"total_blocked": len(ips), "blocked_ips": ips}


# -----------------------------
# Isolated Hosts
# -----------------------------
@app.get("/isolated-hosts", tags=["Containment"], summary="Get isolated hosts")
def isolated_hosts() -> dict:
    hosts = get_isolated_hosts()
    return {"total_isolated": len(hosts), "isolated_hosts": hosts}


# -----------------------------
# Alert Stats
# -----------------------------
@app.get("/stats", tags=["Dashboard"], summary="Get SOAR statistics")
def get_stats() -> dict:
    critical = sum(1 for a in alert_store if a.risk_level == RiskLevel.CRITICAL)
    high = sum(1 for a in alert_store if a.risk_level == RiskLevel.HIGH)
    medium = sum(1 for a in alert_store if a.risk_level == RiskLevel.MEDIUM)
    low = sum(1 for a in alert_store if a.risk_level == RiskLevel.LOW)

    return {
        "total_alerts": len(alert_store),
        "by_risk_level": {
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
        },
        "total_blocked_ips": len(get_blocked_ips()),
        "total_isolated_hosts": len(get_isolated_hosts()),
    }


# ==========================================================
# CASE MANAGEMENT ENDPOINTS
# ==========================================================

@app.get("/cases", tags=["Cases"], summary="Get all cases")
def list_cases() -> dict:
    cases = get_all_cases()
    return {"total": len(cases), "cases": cases}


@app.get("/cases/{case_id}", tags=["Cases"], summary="Get case by ID")
def get_single_case(case_id: str):
    case = get_case(case_id)

    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case {case_id} not found",
        )

    return case


@app.get(
    "/cases/{case_id}/timeline",
    tags=["Cases"],
    summary="Get case timeline",
)
def case_timeline(case_id: str) -> dict:
    case = get_case(case_id)

    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case {case_id} not found",
        )

    return {
        "case_id": case_id,
        "timeline": get_case_timeline(case_id),
    }


@app.post(
    "/cases/{case_id}/assign",
    tags=["Cases"],
    summary="Assign case to an analyst",
)
def assign_case_to_analyst(
    case_id: str,
    analyst_username: str,
    requested_by: str,
) -> dict:
    try:
        if not has_permission(requested_by, "execute_playbook"):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You do not have permission to assign cases",
            )

        case = assign_case(case_id, analyst_username)

        return {
            "message": "Case assigned successfully",
            "case_id": case.case_id,
            "assigned_to": case.assigned_to,
        }

    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )


@app.put(
    "/cases/{case_id}/status",
    tags=["Cases"],
    summary="Update case status",
)
def update_status(
    case_id: str,
    new_status: CaseStatus,
    requested_by: str,
) -> dict:
    try:
        if new_status == CaseStatus.CLOSED:
            if not can_approve_high_impact(requested_by):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Only Admin or Senior Analyst can close cases",
                )

        case = update_case_status(case_id, new_status)

        return {
            "message": "Case status updated",
            "case_id": case.case_id,
            "status": case.status.value,
        }

    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )


@app.post(
    "/cases/{case_id}/close",
    tags=["Cases"],
    summary="Close a case (requires approval)",
)
def close_case_endpoint(case_id: str, requested_by: str) -> dict:
    try:
        if not can_approve_high_impact(requested_by):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Only Admin or Senior Analyst can close cases",
            )

        case = close_case(case_id)

        return {
            "message": "Case closed successfully",
            "case_id": case.case_id,
            "status": case.status.value,
        }

    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )


@app.delete(
    "/cases/{case_id}",
    tags=["Cases"],
    summary="Delete a case (admin only)",
)
def delete_case_endpoint(case_id: str, requested_by: str) -> dict:
    if not can_approve_high_impact(requested_by):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only Admin or Senior Analyst can delete cases",
        )

    deleted = delete_case(case_id)

    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case {case_id} not found",
        )

    return {"message": "Case deleted successfully", "case_id": case_id}


# ==========================================================
# DASHBOARD ENDPOINTS
# ==========================================================

@app.get("/dashboard", tags=["Dashboard"], summary="Get dashboard summary")
def dashboard_summary() -> dict:
    return get_dashboard_summary()


@app.get(
    "/dashboard/statistics",
    tags=["Dashboard"],
    summary="Dashboard statistics",
)
def dashboard_statistics() -> dict:
    return get_dashboard_statistics()


@app.get(
    "/dashboard/cases-by-status",
    tags=["Dashboard"],
    summary="Get cases grouped by status",
)
def dashboard_cases_by_status() -> dict:
    return get_cases_grouped_by_status()


# ==========================================================
# RBAC ENDPOINTS
# ==========================================================

@app.get("/users", tags=["RBAC"], summary="Get all users")
def list_users() -> dict:
    return {"users": get_all_users()}


@app.get("/roles", tags=["RBAC"], summary="Get all available roles")
def list_roles() -> dict:
    return {"roles": get_available_roles()}