from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware

from app.models import Alert, NormalizedAlert, RiskLevel
from app.normalizer import normalize_alert
from app.enrichment import enrich_alert
from app.risk_engine import evaluate_alert
from app.playbooks import (
    execute_playbook,
    get_blocked_ips,
    get_isolated_hosts,
)
from app.logger import soar_logger
from app.config import settings


# In-memory alert store
# Future: Replace with database
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
# Health Check
# -----------------------------
@app.get(
    "/health",
    tags=["Health"],
    summary="Health check endpoint"
)
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
            f"Alert received | "
            f"Type: {alert.alert_type} | "
            f"IP: {alert.source_ip}"
        )

        # Step 1: Normalize
        normalized = normalize_alert(alert)

        soar_logger.info(
            f"Step 1 Complete | "
            f"ID: {normalized.alert_id}"
        )

        # Step 2: Enrich
        enriched = enrich_alert(normalized)

        soar_logger.info(
            f"Step 2 Complete | "
            f"ID: {enriched.alert_id}"
        )

        # Step 3: Risk Evaluation
        evaluated = evaluate_alert(enriched)

        soar_logger.info(
            f"Step 3 Complete | "
            f"ID: {evaluated.alert_id} | "
            f"Score: {evaluated.risk_score} | "
            f"Level: {evaluated.risk_level}"
        )

        # Step 4: Playbook Execution
        playbook_result = execute_playbook(evaluated)

        soar_logger.info(
            f"Step 4 Complete | "
            f"ID: {evaluated.alert_id} | "
            f"Action: {playbook_result['action']}"
        )

        # Save Alert
        alert_store.append(evaluated)

        return {
            "message": "Alert processed successfully",
            "alert_id": evaluated.alert_id,
            "risk_score": evaluated.risk_score,
            "risk_level": (
                evaluated.risk_level.value
                if evaluated.risk_level
                else None
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
@app.get(
    "/alerts",
    tags=["Alerts"],
    summary="Get all processed alerts",
)
def get_all_alerts() -> dict:
    return {
        "total": len(alert_store),
        "alerts": alert_store,
    }


# -----------------------------
# Get Alert By ID
# -----------------------------
@app.get(
    "/alerts/{alert_id}",
    tags=["Alerts"],
    summary="Get alert by ID",
)
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
@app.get(
    "/blocked-ips",
    tags=["Containment"],
    summary="Get blocked IPs",
)
def blocked_ips() -> dict:
    ips = get_blocked_ips()

    return {
        "total_blocked": len(ips),
        "blocked_ips": ips,
    }


# -----------------------------
# Isolated Hosts
# -----------------------------
@app.get(
    "/isolated-hosts",
    tags=["Containment"],
    summary="Get isolated hosts",
)
def isolated_hosts() -> dict:
    hosts = get_isolated_hosts()

    return {
        "total_isolated": len(hosts),
        "isolated_hosts": hosts,
    }


# -----------------------------
# Dashboard Stats
# -----------------------------
@app.get(
    "/stats",
    tags=["Dashboard"],
    summary="Get SOAR statistics",
)
def get_stats() -> dict:
    critical = sum(
        1 for a in alert_store
        if a.risk_level == RiskLevel.CRITICAL
    )

    high = sum(
        1 for a in alert_store
        if a.risk_level == RiskLevel.HIGH
    )

    medium = sum(
        1 for a in alert_store
        if a.risk_level == RiskLevel.MEDIUM
    )

    low = sum(
        1 for a in alert_store
        if a.risk_level == RiskLevel.LOW
    )

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