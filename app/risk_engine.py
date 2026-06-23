from app.models import NormalizedAlert, RiskLevel
from app.logger import soar_logger
from app.config import settings


# Base scores assigned according to alert severity
SEVERITY_SCORES = {
    "low": 15,
    "medium": 40,
    "high": 70,
    "critical": 90
}


# Multipliers based on alert type
ALERT_TYPE_MULTIPLIERS = {
    "Brute Force": 1.2,
    "Malware": 1.5,
    "Phishing": 1.3,
    "DDoS": 1.4,
    "Unauthorized Access": 1.6,
    "Ransomware": 2.0
}


def calculate_risk_score(alert: NormalizedAlert) -> float:
    """
    Calculate the risk score based on severity and alert type.

    Args:
        alert (NormalizedAlert): Normalized alert object.

    Returns:
        float: Risk score between 0 and 100.
    """
    try:
        # Base score from severity
        base_score = SEVERITY_SCORES.get(
            alert.severity.lower(),
            SEVERITY_SCORES["low"]
        )

        # Multiplier from alert type
        multiplier = ALERT_TYPE_MULTIPLIERS.get(
            alert.alert_type,
            1.0
        )

        # Final score capped at 100
        score = round(
            min(base_score * multiplier, 100.0),
            2
        )

        soar_logger.info(
            f"Risk score calculated | "
            f"ID: {alert.alert_id} | "
            f"Type: {alert.alert_type} | "
            f"Score: {score}"
        )

        return score

    except Exception:
        soar_logger.exception("Risk score calculation failed")
        raise ValueError("Risk calculation failed")


def assign_risk_level(score: float) -> RiskLevel:
    """
    Assign a risk level based on configured thresholds.

    Args:
        score (float): Risk score.

    Returns:
        RiskLevel: LOW, MEDIUM, HIGH, or CRITICAL.
    """
    try:
        if score >= settings.HIGH_RISK_THRESHOLD:
            level = RiskLevel.CRITICAL

        elif score >= settings.MEDIUM_RISK_THRESHOLD:
            level = RiskLevel.HIGH

        elif score >= settings.LOW_RISK_THRESHOLD:
            level = RiskLevel.MEDIUM

        else:
            level = RiskLevel.LOW

        soar_logger.info(
            f"Risk level assigned | "
            f"Score: {score} | "
            f"Level: {level.value}"
        )

        return level

    except Exception:
        soar_logger.exception("Risk level assignment failed")
        raise ValueError("Risk level assignment failed")


def evaluate_alert(alert: NormalizedAlert) -> NormalizedAlert:
    """
    Evaluate an alert by calculating its risk score
    and assigning a risk level.

    Args:
        alert (NormalizedAlert): Normalized alert object.

    Returns:
        NormalizedAlert: Updated alert.
    """
    try:
        score = calculate_risk_score(alert)
        level = assign_risk_level(score)

        alert.risk_score = score
        alert.risk_level = level

        soar_logger.info(
            f"Alert evaluated | "
            f"ID: {alert.alert_id} | "
            f"Score: {score} | "
            f"Level: {level.value}"
        )

        return alert

    except Exception:
        soar_logger.exception("Alert evaluation failed")
        raise ValueError("Alert evaluation failed")


def is_critical(alert: NormalizedAlert) -> bool:
    """
    Check whether an alert is critical.

    Args:
        alert (NormalizedAlert): Alert object.

    Returns:
        bool: True if critical, otherwise False.
    """
    return alert.risk_level == RiskLevel.CRITICAL