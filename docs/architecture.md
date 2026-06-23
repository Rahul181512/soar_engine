# SOAR Incident Containment Engine - Architecture

## Overview

The SOAR (Security Orchestration, Automation, and Response) Engine is a FastAPI-based platform designed to automatically ingest, enrich, evaluate, and respond to security alerts from SIEM systems in near real-time.

The system standardizes incoming alerts, enriches them with threat intelligence, calculates a risk score, and executes automated containment actions based on predefined playbooks.

---

## System Architecture

```text
SIEM Alert (JSON)
        │
        ▼
┌─────────────────┐
│   FastAPI App   │
│   (main.py)     │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│   Normalizer    │
│ (normalizer.py) │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│   Enrichment    │
│ (enrichment.py) │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Risk Engine    │
│ (risk_engine.py)│
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│    Playbooks    │
│ (playbooks.py)  │
└────────┬────────┘
         │
         ▼
    Response JSON
```

---

## Processing Flow

1. Alert received from SIEM.
2. Alert validated using Pydantic schemas.
3. Alert normalized into a standard format.
4. Threat intelligence enrichment performed.
5. Risk score calculated.
6. Risk level assigned.
7. Automated playbook executed.
8. Final response returned to analyst or API consumer.

---

## Components

### 1. Alert Ingestion (main.py)

Responsibilities:

* Receives alerts through REST API.
* Validates incoming payloads.
* Orchestrates the complete processing pipeline.
* Stores processed alerts in memory.

Endpoint:

```http
POST /alerts
```

---

### 2. Alert Normalizer (normalizer.py)

Responsibilities:

* Converts timestamps to UTC.
* Generates unique UUID-based alert identifiers.
* Standardizes incoming alert structure.
* Produces normalized alerts for downstream processing.

Output:

```text
NormalizedAlert
```

---

### 3. Threat Enrichment (enrichment.py)

Responsibilities:

* Queries AbuseIPDB.
* Queries VirusTotal.
* Aggregates threat intelligence.
* Falls back to mock data when API keys are unavailable.

Threat Intelligence Sources:

* AbuseIPDB
* VirusTotal

Output:

```text
enrichment_data
```

---

### 4. Risk Engine (risk_engine.py)

Responsibilities:

* Calculates risk score.
* Assigns risk level.
* Supports configurable thresholds.

Risk Levels:

* Low
* Medium
* High
* Critical

---

### 5. Playbook Engine (playbooks.py)

Responsibilities:

* Executes automated response actions.
* Simulates containment workflows.
* Tracks blocked IP addresses.
* Tracks isolated hosts.

Actions:

| Risk Level | Action          |
| ---------- | --------------- |
| Low        | Log Only        |
| Medium     | Notify Analyst  |
| High       | Block Source IP |
| Critical   | Isolate Host    |

---

## Risk Score Calculation

### Severity Base Scores

| Severity | Score |
| -------- | ----- |
| Low      | 15    |
| Medium   | 40    |
| High     | 70    |
| Critical | 90    |

### Alert Type Multipliers

| Alert Type          | Multiplier |
| ------------------- | ---------- |
| Brute Force         | 1.2x       |
| Malware             | 1.5x       |
| Phishing            | 1.3x       |
| DDoS                | 1.4x       |
| Unauthorized Access | 1.6x       |
| Ransomware          | 2.0x       |

### Formula

```text
Risk Score = min(Base Score × Multiplier, 100)
```

Example:

```text
Ransomware + Critical
= 90 × 2.0
= 180

Final Score = 100
```

---

## Technology Stack

| Component           | Technology          |
| ------------------- | ------------------- |
| Backend API         | FastAPI             |
| Validation          | Pydantic v2         |
| Web Server          | Uvicorn             |
| Threat Intelligence | AbuseIPDB           |
| Threat Intelligence | VirusTotal          |
| Logging             | Python Logging      |
| Log Rotation        | RotatingFileHandler |
| Testing             | Pytest              |
| Configuration       | python-dotenv       |

---

## Security Practices

Implemented security controls include:

* Environment variable based secrets management.
* API key protection through `.env`.
* Input validation for all alert fields.
* IPv4 and IPv6 validation.
* Port validation (1–65535).
* Structured application logging.
* Rotating log files.
* Exception handling and safe error reporting.

---

## Project Structure

```text
soar-engine/
├── app/
│   ├── __init__.py
│   ├── main.py
│   ├── models.py
│   ├── normalizer.py
│   ├── enrichment.py
│   ├── risk_engine.py
│   ├── playbooks.py
│   ├── logger.py
│   └── config.py
│
├── sample_alerts/
│   ├── brute_force.json
│   ├── malware.json
│   ├── phishing.json
│   ├── ddos.json
│   ├── ransomware.json
│   └── unauthorized_access.json
│
├── tests/
│   ├── test_normalizer.py
│   ├── test_risk_engine.py
│   └── test_enrichment.py
│
├── docs/
│   ├── architecture.md
│   └── api_examples.md
│
├── simulator.py
├── run.py
├── requirements.txt
├── README.md
├── .env.example
└── .gitignore
```

---

## Future Enhancements

Planned improvements include:

* PostgreSQL integration.
* MongoDB support.
* Real firewall integration.
* Wazuh integration.
* Splunk integration.
* Slack notifications.
* Email notifications.
* Threat intelligence caching.
* Docker containerization.
* CI/CD pipeline using GitHub Actions.
* Dashboard and visualization layer.

---

## Conclusion

The SOAR Incident Containment Engine demonstrates a complete security automation workflow by combining alert ingestion, threat intelligence enrichment, risk evaluation, and automated response. The architecture is modular, extensible, and designed to support future enterprise-grade security operations capabilities.
