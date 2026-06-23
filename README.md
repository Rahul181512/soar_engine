<div align="center">

# 🛡️ SOAR Incident Containment Engine

### Automated Security Orchestration, Automation, and Response Platform

![Python](https://img.shields.io/badge/Python-3.10+-blue?style=flat-square\&logo=python)
![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-green?style=flat-square\&logo=fastapi)
![License](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=flat-square)
![Tests](https://img.shields.io/badge/Tests-Pytest-success?style=flat-square)
![Documentation](https://img.shields.io/badge/Docs-Complete-blueviolet?style=flat-square)

</div>

---

## 📌 Overview

The SOAR Incident Containment Engine is a FastAPI-based security automation platform designed to automatically ingest, enrich, evaluate, and respond to security alerts from SIEM systems in near real-time.

The platform reduces manual analyst workload by automating the complete incident response lifecycle, including alert normalization, threat intelligence enrichment, risk scoring, and automated containment actions.

---

## 🎯 Key Features

* ✅ Real-time SIEM alert ingestion via REST API
* ✅ Alert normalization and validation
* ✅ Threat intelligence enrichment using AbuseIPDB and VirusTotal
* ✅ Dynamic risk scoring engine
* ✅ Automated containment playbooks
* ✅ Source IP blocking simulation
* ✅ Host isolation simulation
* ✅ Interactive API documentation
* ✅ Structured rotating log files
* ✅ Environment-based configuration management
* ✅ Comprehensive Pytest test suite

---

## 🏗️ Project Structure

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
│   ├── __init__.py
│   ├── test_normalizer.py
│   ├── test_enrichment.py
│   └── test_risk_engine.py
│
├── docs/
│   ├── architecture.md
│   └── api_examples.md
│
├── logs/
│
├── simulator.py
├── run.py
├── requirements.txt
├── README.md
├── .env.example
└── .gitignore
```

---

## ⚙️ Technology Stack

| Component           | Technology     |
| ------------------- | -------------- |
| Backend API         | FastAPI        |
| Validation          | Pydantic v2    |
| Web Server          | Uvicorn        |
| Threat Intelligence | AbuseIPDB      |
| Threat Intelligence | VirusTotal     |
| Logging             | Python Logging |
| Testing             | Pytest         |
| Configuration       | python-dotenv  |

---

## 🚀 Getting Started

### Clone Repository

```bash
git clone https://github.com/YOUR_USERNAME/soar-engine.git
cd soar-engine
```

### Create Virtual Environment

```bash
python -m venv venv
```

Windows:

```bash
venv\Scripts\activate
```

Linux / macOS:

```bash
source venv/bin/activate
```

### Install Dependencies

```bash
pip install -r requirements.txt
```

### Configure Environment

```bash
cp .env.example .env
```

Configure API keys if available:

```env
ABUSEIPDB_API_KEY=your_key_here
VIRUSTOTAL_API_KEY=your_key_here
```

If API keys are not configured, the application automatically uses mock data.

### Run Application

```bash
python run.py
```

---

## 📚 API Documentation

After starting the server:

| Interface  | URL                         |
| ---------- | --------------------------- |
| Swagger UI | http://localhost:8000/docs  |
| ReDoc      | http://localhost:8000/redoc |

---

## 🔄 Processing Pipeline

```text
SIEM Alert
    │
    ▼
Normalize Alert
    │
    ▼
Threat Enrichment
    │
    ▼
Risk Evaluation
    │
    ▼
Playbook Execution
    │
    ▼
Response JSON
```

---

## 🎮 Automated Playbooks

| Risk Level  | Score Range | Action          |
| ----------- | ----------- | --------------- |
| 🟢 Low      | 0-29        | Log Only        |
| 🟡 Medium   | 30-59       | Notify Analyst  |
| 🟠 High     | 60-79       | Block Source IP |
| 🔴 Critical | 80-100      | Isolate Host    |

---

## 📊 Risk Scoring

### Formula

```text
Risk Score = min(Base Score × Alert Multiplier, 100)
```

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

---

## 🧪 Running Tests

Run all tests:

```bash
pytest tests/ -v
```

Run specific tests:

```bash
pytest tests/test_normalizer.py -v
pytest tests/test_enrichment.py -v
pytest tests/test_risk_engine.py -v
```

---

## 🎯 Running the Simulator

Terminal 1:

```bash
python run.py
```

Terminal 2:

```bash
python simulator.py
```

Example Output:

```text
============================================================
      SOAR ENGINE - SIEM ALERT SIMULATOR
============================================================

[1/6] Sending Brute Force...
✅ Alert Sent | Type: Brute Force | IP: 45.67.89.10 | Risk: Critical | Score: 84.0 | Action: isolate_host

[2/6] Sending Malware...
✅ Alert Sent | Type: Malware | IP: 103.45.67.89 | Risk: Critical | Score: 100.0 | Action: isolate_host
```

---

## 🔒 Security Practices

* Environment-based secrets management
* No hardcoded API keys
* IPv4 and IPv6 validation
* Port range validation
* Structured logging
* Rotating log files
* Input validation using Pydantic
* Exception handling and safe error reporting

---

## 📖 Documentation

| Document             | Description                       |
| -------------------- | --------------------------------- |
| docs/architecture.md | System architecture and design    |
| docs/api_examples.md | API request and response examples |

---

## 🗺️ Roadmap

* [ ] PostgreSQL integration
* [ ] Redis caching
* [ ] Slack notifications
* [ ] Email notifications
* [ ] Docker support
* [ ] GitHub Actions CI/CD
* [ ] Real firewall integration
* [ ] Wazuh integration
* [ ] Splunk integration
* [ ] Dashboard and analytics

---

## 👨‍💻 Internship Project

Developed as part of an advanced Cybersecurity Engineering internship focused on Security Operations Center (SOC) automation and incident response workflows.

---

## ⭐ Support

If you found this project useful, consider giving it a star on GitHub.

---

<div align="center">

**Built with FastAPI • Python • Cybersecurity Automation**

</div>
