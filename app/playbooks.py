from app.models import NormalizedAlert, RiskLevel
from app.logger import soar_logger


# Simulated blocked IPs
# In production, these would be managed via Firewall APIs,
# AWS Security Groups, or cloud-native controls.
BLOCKED_IPS: set[str] = set()


# Simulated isolated hosts
# In production, these would be handled through EDR/XDR platforms.
ISOLATED_HOSTS: set[str] = set()


def block_ip(ip: str) -> dict:
    """
    Simulate blocking a malicious IP address.

    Args:
        ip (str): IP address to block.

    Returns:
        dict: Action result.
    """
    try:
        if ip in BLOCKED_IPS:
            soar_logger.warning(
                f"IP already blocked | IP: {ip}"
            )

            return {
                "action": "block_ip",
                "status": "already_blocked",
                "ip": ip,
                "message": f"IP {ip} is already blocked."
            }

        BLOCKED_IPS.add(ip)

        soar_logger.info(
            f"IP blocked successfully | IP: {ip}"
        )

        return {
            "action": "block_ip",
            "status": "success",
            "ip": ip,
            "message": (
                f"IP {ip} has been blocked "
                f"(simulated firewall action)."
            )
        }

    except Exception:
        soar_logger.exception(
            f"Failed to block IP | IP: {ip}"
        )

        raise ValueError("IP blocking failed")


def isolate_host(host: str) -> dict:
    """
    Simulate isolating a compromised host.

    Args:
        host (str): Host identifier.

    Returns:
        dict: Action result.
    """
    try:
        if host in ISOLATED_HOSTS:
            soar_logger.warning(
                f"Host already isolated | Host: {host}"
            )

            return {
                "action": "isolate_host",
                "status": "already_isolated",
                "host": host,
                "message": f"Host {host} is already isolated."
            }

        ISOLATED_HOSTS.add(host)

        soar_logger.info(
            f"Host isolated successfully | Host: {host}"
        )

        return {
            "action": "isolate_host",
            "status": "success",
            "host": host,
            "message": (
                f"Host {host} has been isolated "
                f"(simulated EDR action)."
            )
        }

    except Exception:
        soar_logger.exception(
            f"Failed to isolate host | Host: {host}"
        )

        raise ValueError("Host isolation failed")


def execute_playbook(alert: NormalizedAlert) -> dict:
    """
    Execute a playbook based on alert risk level.

    LOW      -> Log only
    MEDIUM   -> Notify analyst
    HIGH     -> Block source IP
    CRITICAL -> Isolate source host

    Args:
        alert (NormalizedAlert): Evaluated alert.

    Returns:
        dict: Playbook execution result.
    """
    try:
        if alert.risk_level == RiskLevel.LOW:
            result = {
                "action": "log_only",
                "status": "success",
                "message": (
                    "Low-risk alert logged. "
                    "No automated action taken."
                )
            }

        elif alert.risk_level == RiskLevel.MEDIUM:
            result = {
                "action": "notify_analyst",
                "status": "success",
                "message": (
                    "Analyst notification generated."
                )
            }

        elif alert.risk_level == RiskLevel.HIGH:
            result = block_ip(alert.source_ip)

        elif alert.risk_level == RiskLevel.CRITICAL:
            result = isolate_host(alert.source_ip)

        else:
            result = {
                "action": "unknown",
                "status": "failed",
                "message": (
                    "Unable to determine playbook."
                )
            }

        alert.action_taken = result["action"]

        soar_logger.info(
            f"Playbook executed | "
            f"ID: {alert.alert_id} | "
            f"Action: {result['action']}"
        )

        return result

    except Exception:
        soar_logger.exception(
            f"Playbook execution failed | "
            f"ID: {alert.alert_id}"
        )

        raise ValueError("Playbook execution failed")