import time
from datetime import datetime, timezone

import requests

from app.config import settings

# SOAR Engine URL
BASE_URL = f"http://{settings.HOST}:{settings.PORT}"


# Sample alerts to simulate
SAMPLE_ALERTS = [
    {
        "alert_type": "Brute Force",
        "source_ip": "45.67.89.10",
        "severity": "high",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "description": "Multiple failed SSH login attempts detected.",
        "destination_ip": "192.168.1.50",
        "port": 22
    },
    {
        "alert_type": "Malware",
        "source_ip": "103.45.67.89",
        "severity": "critical",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "description": "Malware payload detected on endpoint.",
        "destination_ip": "10.0.0.15",
        "port": 443
    },
    {
        "alert_type": "Phishing",
        "source_ip": "198.51.100.42",
        "severity": "medium",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "description": "Phishing email link clicked by user.",
        "destination_ip": None,
        "port": None
    },
    {
        "alert_type": "DDoS",
        "source_ip": "203.0.113.99",
        "severity": "critical",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "description": "High volume traffic detected - possible DDoS.",
        "destination_ip": "10.0.0.1",
        "port": 80
    },
    {
        "alert_type": "Ransomware",
        "source_ip": "185.220.101.45",
        "severity": "critical",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "description": "Ransomware encryption activity detected.",
        "destination_ip": "192.168.1.100",
        "port": 445
    },
    {
        "alert_type": "Unauthorized Access",
        "source_ip": "91.108.56.23",
        "severity": "high",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "description": "Unauthorized access attempt to admin panel.",
        "destination_ip": "10.0.0.5",
        "port": 8080
    },
]


def send_alert(alert: dict) -> None:
    """
    Send a single alert to the SOAR engine.

    Args:
        alert (dict): Alert payload.
    """
    try:
        response = requests.post(
            f"{BASE_URL}/alerts",
            json=alert,
            timeout=10
        )

        if response.status_code == 201:
            data = response.json()

            print(
                f"✅ Alert Sent | "
                f"Type: {alert['alert_type']} | "
                f"IP: {alert['source_ip']} | "
                f"Risk: {data.get('risk_level')} | "
                f"Score: {data.get('risk_score')} | "
                f"Action: {data.get('action_taken')}"
            )

        else:
            print(
                f"❌ Failed | "
                f"Status: {response.status_code} | "
                f"Detail: {response.text}"
            )

    except requests.exceptions.ConnectionError:
        print(
            "\n❌ Connection failed.\n"
            "Make sure the SOAR engine is running:\n"
            "python run.py\n"
        )

    except requests.exceptions.Timeout:
        print(
            f"❌ Request timed out while sending "
            f"{alert['alert_type']} alert."
        )

    except Exception as e:
        print(f"❌ Unexpected Error: {str(e)}")


def run_simulation(delay: float = 1.5) -> None:
    """
    Send all sample alerts to the SOAR engine.

    Args:
        delay (float): Delay between alerts in seconds.
    """
    print("\n" + "=" * 60)
    print("      SOAR ENGINE - SIEM ALERT SIMULATOR")
    print("=" * 60)

    print(f"📡 Target        : {BASE_URL}")
    print(f"📋 Total Alerts : {len(SAMPLE_ALERTS)}")

    print("=" * 60 + "\n")

    for index, alert in enumerate(SAMPLE_ALERTS, start=1):
        # Refresh timestamp before sending
        alert["timestamp"] = datetime.now(
            timezone.utc
        ).isoformat()

        print(
            f"[{index}/{len(SAMPLE_ALERTS)}] "
            f"Sending {alert['alert_type']}..."
        )

        send_alert(alert)

        time.sleep(delay)

    print("\n" + "=" * 60)
    print("✅ Simulation Complete!")
    print("=" * 60)

    # Display SOAR statistics
    try:
        response = requests.get(
            f"{BASE_URL}/stats",
            timeout=5
        )

        if response.status_code == 200:
            stats = response.json()

            print("\n📊 SOAR Engine Statistics")
            print("-" * 60)

            print(
                f"Total Alerts     : {stats['total_alerts']}"
            )

            print(
                f"Critical Alerts  : "
                f"{stats['by_risk_level']['critical']}"
            )

            print(
                f"High Alerts      : "
                f"{stats['by_risk_level']['high']}"
            )

            print(
                f"Medium Alerts    : "
                f"{stats['by_risk_level']['medium']}"
            )

            print(
                f"Low Alerts       : "
                f"{stats['by_risk_level']['low']}"
            )

            print(
                f"Blocked IPs      : "
                f"{stats['total_blocked_ips']}"
            )

            print(
                f"Isolated Hosts   : "
                f"{stats['total_isolated_hosts']}"
            )

            print("=" * 60)

    except Exception:
        pass


if __name__ == "__main__":
    run_simulation()