from datetime import timezone
import logging

from app.models import Alert, NormalizedAlert


logger = logging.getLogger(__name__)


def normalize_alert(alert: Alert) -> NormalizedAlert:
    """
    Normalize incoming SIEM alerts into a standard SOAR format.

    Args:
        alert (Alert): Raw SIEM alert.

    Returns:
        NormalizedAlert: Standardized alert object.
    """
    try:
        # Convert timestamp to UTC
        if alert.timestamp.tzinfo is None:
            timestamp_utc = alert.timestamp.replace(tzinfo=timezone.utc)
        else:
            timestamp_utc = alert.timestamp.astimezone(timezone.utc)

        # Human-readable UTC timestamp
        normalized_timestamp = timestamp_utc.strftime(
            "%Y-%m-%d %H:%M:%S UTC"
        )

        normalized_alert = NormalizedAlert(
            alert_type=alert.alert_type.value,
            source_ip=alert.source_ip,
            severity=alert.severity.value,
            timestamp=timestamp_utc,   # Store UTC timestamp
            normalized_timestamp=normalized_timestamp,
            description=alert.description,
            destination_ip=alert.destination_ip,
            port=alert.port
        )

        logger.info(
            "Alert normalized successfully | "
            f"ID: {normalized_alert.alert_id} | "
            f"Type: {normalized_alert.alert_type}"
        )

        return normalized_alert

    except Exception:
        logger.exception("Failed to normalize alert")
        raise ValueError("Alert normalization failed")