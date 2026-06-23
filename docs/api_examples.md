# SOAR Engine - API Examples

## Base URL

```text
http://localhost:8000
```

---

## Interactive API Docs

FastAPI provides built-in interactive documentation.

| Interface  | URL                         |
| ---------- | --------------------------- |
| Swagger UI | http://localhost:8000/docs  |
| ReDoc      | http://localhost:8000/redoc |

---

## Available API Endpoints

| Method | Endpoint           | Description                |
| ------ | ------------------ | -------------------------- |
| GET    | /health            | Health check               |
| POST   | /alerts            | Process SIEM alert         |
| GET    | /alerts            | Get all processed alerts   |
| GET    | /alerts/{alert_id} | Get alert by ID            |
| GET    | /blocked-ips       | Get blocked IP addresses   |
| GET    | /isolated-hosts    | Get isolated hosts         |
| GET    | /stats             | Get SOAR engine statistics |

---

## 1. Health Check

### Request

```http
GET /health
```

### Response

```json
{
  "status": "healthy",
  "app": "SOAR Incident Containment Engine",
  "version": "1.0.0"
}
```

---

## 2. Ingest Alert

### Request

```http
POST /alerts
Content-Type: application/json
```

### Brute Force Example

```json
{
  "alert_type": "Brute Force",
  "source_ip": "45.67.89.10",
  "severity": "high",
  "timestamp": "2026-06-22T10:00:00Z",
  "description": "Multiple failed SSH login attempts detected.",
  "destination_ip": "192.168.1.50",
  "port": 22
}
```

### Response

```json
{
  "message": "Alert processed successfully",
  "alert_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "risk_score": 84.0,
  "risk_level": "Critical",
  "action_taken": "isolate_host",
  "playbook_message": "Host 45.67.89.10 has been isolated (simulated EDR action)."
}
```

---

### Ransomware Example

```json
{
  "alert_type": "Ransomware",
  "source_ip": "185.220.101.45",
  "severity": "critical",
  "timestamp": "2026-06-22T10:20:00Z",
  "description": "Ransomware encryption activity detected.",
  "destination_ip": "192.168.1.100",
  "port": 445
}
```

### Response

```json
{
  "message": "Alert processed successfully",
  "alert_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "risk_score": 100.0,
  "risk_level": "Critical",
  "action_taken": "isolate_host",
  "playbook_message": "Host 185.220.101.45 has been isolated (simulated EDR action)."
}
```

---

### Phishing Example

```json
{
  "alert_type": "Phishing",
  "source_ip": "198.51.100.42",
  "severity": "medium",
  "timestamp": "2026-06-22T10:10:00Z",
  "description": "Phishing email link clicked by user.",
  "destination_ip": null,
  "port": null
}
```

### Response

```json
{
  "message": "Alert processed successfully",
  "alert_id": "b2c3d4e5-f6a7-8901-bcde-f12345678901",
  "risk_score": 52.0,
  "risk_level": "Medium",
  "action_taken": "notify_analyst",
  "playbook_message": "Analyst notification generated."
}
```

---

## 3. Get All Alerts

### Request

```http
GET /alerts
```

### Response

```json
{
  "total": 2,
  "alerts": [
    {
      "alert_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
      "alert_type": "Brute Force",
      "source_ip": "45.67.89.10",
      "severity": "high",
      "timestamp": "2026-06-22T10:00:00Z",
      "normalized_timestamp": "2026-06-22 10:00:00 UTC",
      "risk_score": 84.0,
      "risk_level": "Critical",
      "action_taken": "isolate_host"
    }
  ]
}
```

---

## 4. Get Alert By ID

### Request

```http
GET /alerts/{alert_id}
```

### Example

```http
GET /alerts/f47ac10b-58cc-4372-a567-0e02b2c3d479
```

### Response

```json
{
  "alert_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "alert_type": "Brute Force",
  "source_ip": "45.67.89.10",
  "severity": "high",
  "risk_score": 84.0,
  "risk_level": "Critical",
  "action_taken": "isolate_host"
}
```

### Not Found Response

```json
{
  "detail": "Alert f47ac10b not found"
}
```

---

## 5. Get Blocked IPs

### Request

```http
GET /blocked-ips
```

### Response

```json
{
  "total_blocked": 2,
  "blocked_ips": [
    "45.67.89.10",
    "91.108.56.23"
  ]
}
```

---

## 6. Get Isolated Hosts

### Request

```http
GET /isolated-hosts
```

### Response

```json
{
  "total_isolated": 1,
  "isolated_hosts": [
    "185.220.101.45"
  ]
}
```

---

## 7. Get Statistics

### Request

```http
GET /stats
```

### Response

```json
{
  "total_alerts": 6,
  "by_risk_level": {
    "critical": 3,
    "high": 2,
    "medium": 1,
    "low": 0
  },
  "total_blocked_ips": 2,
  "total_isolated_hosts": 1
}
```

---

## Validation Errors

### Invalid IP Address

```json
{
  "detail": [
    {
      "loc": ["body", "source_ip"],
      "msg": "Invalid IP address format",
      "type": "value_error"
    }
  ]
}
```

### Invalid Severity

```json
{
  "detail": [
    {
      "loc": ["body", "severity"],
      "msg": "value is not a valid enumeration member",
      "type": "type_error.enum"
    }
  ]
}
```

### Invalid Port

```json
{
  "detail": [
    {
      "loc": ["body", "port"],
      "msg": "ensure this value is less than or equal to 65535",
      "type": "value_error.number.not_le"
    }
  ]
}
```

---

## Running the Simulator

```bash
# Terminal 1
python run.py

# Terminal 2
python simulator.py
```

---

## Running Tests

```bash
# Run all tests
pytest tests/ -v

# Run specific test file
pytest tests/test_normalizer.py -v
pytest tests/test_enrichment.py -v
pytest tests/test_risk_engine.py -v
```
