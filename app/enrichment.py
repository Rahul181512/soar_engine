import requests
from app.models import NormalizedAlert
from app.logger import soar_logger
from app.config import settings


ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3/ip_addresses"


MOCK_REPUTATION = {
    "192.168.1.100": {
        "abuse_score": 10,
        "country": "US",
        "isp": "Internal Network",
        "total_reports": 0,
        "malicious_votes": 0,
        "suspicious_votes": 0,
        "harmless_votes": 25,
        "is_malicious": False
    },
    "45.67.89.10": {
        "abuse_score": 92,
        "country": "CN",
        "isp": "Mock ISP",
        "total_reports": 142,
        "malicious_votes": 7,
        "suspicious_votes": 2,
        "harmless_votes": 5,
        "is_malicious": True
    }
}


def _get_mock_data(ip: str) -> dict:
    """
    Return realistic mock reputation data.
    """
    return MOCK_REPUTATION.get(
        ip,
        {
            "abuse_score": 30,
            "country": "Unknown",
            "isp": "Unknown ISP",
            "total_reports": 2,
            "malicious_votes": 1,
            "suspicious_votes": 0,
            "harmless_votes": 15,
            "is_malicious": False
        }
    )


def check_abuseipdb(ip: str) -> dict:
    """
    Check IP reputation using AbuseIPDB.
    Falls back to mock data if API key is unavailable.
    """
    try:
        if not settings.ABUSEIPDB_API_KEY:
            soar_logger.warning(
                f"AbuseIPDB API key missing. Using mock data for {ip}"
            )

            mock = _get_mock_data(ip)

            return {
                "source": "AbuseIPDB (Mock)",
                "ip": ip,
                "abuse_score": mock["abuse_score"],
                "country": mock["country"],
                "isp": mock["isp"],
                "total_reports": mock["total_reports"],
                "is_malicious": mock["is_malicious"]
            }

        headers = {
            "Key": settings.ABUSEIPDB_API_KEY,
            "Accept": "application/json"
        }

        params = {
            "ipAddress": ip,
            "maxAgeInDays": 90,
            "verbose": True
        }

        response = requests.get(
            ABUSEIPDB_URL,
            headers=headers,
            params=params,
            timeout=5
        )

        response.raise_for_status()

        data = response.json().get("data", {})

        return {
            "source": "AbuseIPDB",
            "ip": ip,
            "abuse_score": data.get("abuseConfidenceScore", 0),
            "country": data.get("countryCode", "Unknown"),
            "isp": data.get("isp", "Unknown"),
            "total_reports": data.get("totalReports", 0),
            "is_malicious": data.get(
                "abuseConfidenceScore",
                0
            ) >= 50
        }

    except Exception:
        soar_logger.exception(
            f"AbuseIPDB lookup failed for {ip}"
        )

        mock = _get_mock_data(ip)

        return {
            "source": "AbuseIPDB (Mock)",
            "ip": ip,
            "abuse_score": mock["abuse_score"],
            "country": mock["country"],
            "isp": mock["isp"],
            "total_reports": mock["total_reports"],
            "is_malicious": mock["is_malicious"]
        }


def check_virustotal(ip: str) -> dict:
    """
    Check IP reputation using VirusTotal.
    Falls back to mock data if API key is unavailable.
    """
    try:
        if not settings.VIRUSTOTAL_API_KEY:
            soar_logger.warning(
                f"VirusTotal API key missing. Using mock data for {ip}"
            )

            mock = _get_mock_data(ip)

            return {
                "source": "VirusTotal (Mock)",
                "ip": ip,
                "malicious_votes": mock["malicious_votes"],
                "suspicious_votes": mock["suspicious_votes"],
                "harmless_votes": mock["harmless_votes"],
                "is_malicious": mock["is_malicious"]
            }

        response = requests.get(
            f"{VIRUSTOTAL_URL}/{ip}",
            headers={
                "x-apikey": settings.VIRUSTOTAL_API_KEY
            },
            timeout=5
        )

        response.raise_for_status()

        stats = (
            response.json()
            .get("data", {})
            .get("attributes", {})
            .get("last_analysis_stats", {})
        )

        malicious_votes = stats.get("malicious", 0)

        return {
            "source": "VirusTotal",
            "ip": ip,
            "malicious_votes": malicious_votes,
            "suspicious_votes": stats.get(
                "suspicious",
                0
            ),
            "harmless_votes": stats.get(
                "harmless",
                0
            ),
            "is_malicious": malicious_votes >= 3
        }

    except Exception:
        soar_logger.exception(
            f"VirusTotal lookup failed for {ip}"
        )

        mock = _get_mock_data(ip)

        return {
            "source": "VirusTotal (Mock)",
            "ip": ip,
            "malicious_votes": mock["malicious_votes"],
            "suspicious_votes": mock["suspicious_votes"],
            "harmless_votes": mock["harmless_votes"],
            "is_malicious": mock["is_malicious"]
        }


def enrich_alert(alert: NormalizedAlert) -> NormalizedAlert:
    """
    Enrich normalized alerts with threat intelligence.
    """
    try:
        soar_logger.info(
            f"Starting enrichment | ID: {alert.alert_id}"
        )

        abuse_data = check_abuseipdb(alert.source_ip)
        vt_data = check_virustotal(alert.source_ip)

        alert.enrichment_data = {
            "abuseipdb": abuse_data,
            "virustotal": vt_data,
            "is_malicious": (
                abuse_data["is_malicious"]
                or vt_data["is_malicious"]
            )
        }

        soar_logger.info(
            f"Enrichment completed | "
            f"ID: {alert.alert_id}"
        )

        return alert

    except Exception:
        soar_logger.exception(
            f"Enrichment failed | ID: {alert.alert_id}"
        )

        raise ValueError(
            "Alert enrichment failed"
        )