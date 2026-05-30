# SentinelScan Backend — API Reference

> **Base URL:** `http://localhost:8080`
> **API Base:** `/api`
> **Auth:** Bearer JWT (except `/health`)
> **Content-Type:** `application/json`

---

## 1. Authentication

### 1.1 Auth Header

```
Authorization: Bearer <jwt-token>
```

### 1.2 RBAC Roles

| Role | Permissions |
|------|-------------|
| `admin` | Full access |
| `security_analyst` | Create scans, manage credentials, triage findings, manage tickets |
| `auditor` | View-only |
| `viewer` | Limited view access |

---

## 2. Endpoints

### 2.1 System

#### Health Check

```
GET /health
```

**Response 200:**
```json
{
  "status": "healthy",
  "timestamp": "2026-05-11T10:00:00Z"
}
```

---

### 2.2 Scans

#### Create Scan

```
POST /api/scans
Authorization: Bearer <token>
Content-Type: application/json
```

**Request body:**
```json
{
  "targets": ["http://example.com", "https://test.com"],
  "template_selectors": "{\"severity\":[\"high\",\"critical\"]}",
  "auth_credential_id": 1
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `targets` | `[]string` | Yes | Target URLs to scan |
| `template_selectors` | `string` | No | JSON string for template filter |
| `auth_credential_id` | `uint` | No | Credential vault ID for authenticated scan |

**Response 202:**
```json
{
  "id": 1,
  "targets": ["http://example.com"],
  "status": "pending",
  "created_at": "2026-05-04T10:00:00Z",
  "updated_at": "2026-05-04T10:00:00Z"
}
```

**Errors:** 400 (invalid body / missing targets), 500 (internal)

---

#### Get Scan

```
GET /api/scans/{id}
Authorization: Bearer <token>
```

**Response 200:**
```json
{
  "id": 1,
  "targets": ["http://example.com"],
  "status": "running",
  "progress": {
    "total_tasks": 100,
    "completed": 45,
    "failed": 2,
    "in_progress": 53
  },
  "created_at": "2026-05-04T10:00:00Z"
}
```

**Errors:** 400 (invalid ID), 404 (not found)

---

#### Get Scan Results

```
GET /api/scans/{id}/results
Authorization: Bearer <token>
```

**Response 200:**
```json
[
  {
    "id": 1,
    "scan_id": 1,
    "target": "http://example.com",
    "template_id": "CVE-2023-1234",
    "matched": true,
    "severity": "high",
    "details": {
      "matched_at": "/login",
      "type": "xss"
    },
    "created_at": "2026-05-04T10:00:00Z"
  }
]
```

**Errors:** 400 (invalid ID), 404 (not found)

---

### 2.3 WebSocket Stream

#### Stream Scan Events

```
GET /api/scans/{id}/stream
Authorization: Bearer <token>
Upgrade: websocket
```

Opens a WebSocket connection. Server pushes JSON events:

**Event types:**

| Type | Payload | When |
|------|---------|------|
| `finding` | `{target, template_id, matched, severity, details}` | Vulnerability detected |
| `progress` | `{completed, total}` | Task completed |
| `complete` | `{scan_id}` | All tasks done |
| `failed` | `{scan_id, error}` | Scan failed |

**Example:**
```json
{
  "type": "finding",
  "payload": {
    "target": "http://example.com",
    "template_id": "CVE-2023-1234",
    "matched": true,
    "severity": "high",
    "details": {"matched_at": "/login"}
  }
}
```

---

### 2.4 Reports

#### Get Report Data (JSON)

```
GET /api/scans/{id}/report-data
Authorization: Bearer <token>
```

**Response 200:**
```json
{
  "scan": {
    "id": 1,
    "targets": ["http://example.com"],
    "status": "completed",
    "created_at": "2026-05-04T10:00:00Z"
  },
  "summary": {
    "total": 15,
    "critical": 2,
    "high": 5,
    "medium": 4,
    "low": 3,
    "info": 1
  },
  "findings": [...]
}
```

---

#### Export Report (PDF)

```
POST /api/scans/{id}/report/export
Authorization: Bearer <token>
```

**Response 200:**
```json
{
  "status": "ready",
  "download_url": "/api/scans/1/report/download"
}
```

Generates PDF via chromedp `Page.printToPDF`. PDF cached on disk.

---

#### Download Report

```
GET /api/scans/{id}/report/download
Authorization: Bearer <token>
```

Returns the PDF file if it exists.

---

### 2.5 Credential Vault

#### List Credentials

```
GET /api/credentials
Authorization: Bearer <token>
```

**Response 200:**
```json
[
  {
    "id": 1,
    "name": "My Login Form",
    "method": "login_form",
    "config": {"login_url": "https://example.com/login"},
    "is_active": true,
    "last_verified": null
  }
]
```

Note: Secrets (passwords, tokens, cookies) are masked.

---

#### Create Credential

```
POST /api/credentials
Authorization: Bearer <token>
```

**Request body:**

**login_form method:**
```json
{
  "name": "My Login Form",
  "method": "login_form",
  "config": {
    "login_url": "https://example.com/login",
    "fields": [
      {"selector": "username", "type": "text", "value": "admin"},
      {"selector": "password", "type": "password", "value": "secret123"}
    ],
    "submit_selector": "button[type=submit]"
  },
  "verify_url": "https://example.com/dashboard",
  "verify_pattern": "Welcome, admin"
}
```

**cookie method:**
```json
{
  "name": "Session Cookie",
  "method": "cookie",
  "config": {
    "cookies": [
      {"name": "session", "value": "abc123", "domain": "example.com", "path": "/"}
    ]
  }
}
```

**bearer method:**
```json
{
  "name": "Bearer Token",
  "method": "bearer",
  "config": {
    "token": "eyJhbGciOiJIUzI1NiIs..."
  }
}
```

**api_key method:**
```json
{
  "name": "API Key",
  "method": "api_key",
  "config": {
    "headers": [
      {"name": "X-API-Key", "value": "sk-abc123"}
    ]
  }
}
```

**selenium method:**
```json
{
  "name": "Selenium Auth",
  "method": "selenium",
  "config": {
    "script_path": "/path/to/auth/script.py"
  }
}
```

**Response 201:** Created credential object (secrets masked).

---

#### Get Credential

```
GET /api/credentials/{id}
Authorization: Bearer <token>
```

**Response 200:** Credential object (secrets masked).
**Errors:** 404 (not found)

---

#### Update Credential

```
PUT /api/credentials/{id}
Authorization: Bearer <token>
```

**Response 200:** Updated credential object (secrets masked).

---

#### Delete Credential

```
DELETE /api/credentials/{id}
Authorization: Bearer <token>
```

**Response 204:** No Content.

---

#### Verify Credential

```
POST /api/credentials/{id}/verify
Authorization: Bearer <token>
```

Initiates a test authentication against the target.

**Response 200:**
```json
{
  "status": "verified",
  "message": "Successfully authenticated",
  "cookies": 2,
  "headers": 3
}
```

**Errors:** 401 (auth failed), 404 (credential not found)

---

### 2.6 Templates

#### List Templates

```
GET /api/templates?severity=critical,high&tags=cicd
Authorization: Bearer <token>
```

**Query parameters:**

| Param | Type | Description |
|-------|------|-------------|
| `severity` | string | Comma-separated: info,low,medium,high,critical |
| `tags` | string | Comma-separated tags |

**Response 200:** Array of template metadata.

---

#### Get Template

```
GET /api/templates/{id}
Authorization: Bearer <token>
```

**Response 200:** Template details (name, severity, tags).
**Errors:** 404 (not found)

---

## 3. Error Format

Standard error responses:

```json
{
  "code": "NOT_FOUND",
  "message": "Scan not found",
  "status": 404
}
```

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `NOT_FOUND` | 404 | Resource not found |
| `UNAUTHORIZED` | 401 | Missing or invalid auth |
| `FORBIDDEN` | 403 | Insufficient permissions |
| `INVALID_INPUT` | 400 | Invalid request body or parameters |
| `CONFLICT` | 409 | Resource conflict |
| `INTERNAL_ERROR` | 500 | Unexpected server error |

---

## 4. Postman Collection

Import this OpenAPI-compatible spec from `main.go` annotations (Swagger):

- Swagger UI: `http://localhost:8080/api/docs/`
- Swagger spec: Generated from Go doc comments in `main.go:3-20`
