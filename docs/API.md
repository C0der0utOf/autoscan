# API Documentation

## Base URL

```
http://localhost:8000
```

## Endpoints

### Health Check

**GET** `/health`

Returns the health status of the API.

**Response:**
```json
{
  "status": "healthy"
}
```

### Create Scan

**POST** `/scans`

Create and start a new security scan.

**Request Body:**
```json
{
  "target": "localhost",
  "scan_type": "full",
  "compliance_frameworks": ["cis"]
}
```

**Response:**
```json
{
  "id": 1,
  "target": "localhost",
  "scan_type": "full",
  "status": "running",
  "started_at": "2024-01-01T12:00:00",
  "completed_at": null
}
```

### Get Scan

**GET** `/scans/{scan_id}`

Get details of a specific scan.

**Response:**
```json
{
  "id": 1,
  "target": "localhost",
  "scan_type": "full",
  "status": "completed",
  "started_at": "2024-01-01T12:00:00",
  "completed_at": "2024-01-01T12:05:00"
}
```

### Get Scan Findings

**GET** `/scans/{scan_id}/findings`

Get all findings for a specific scan.

**Response:**
```json
[
  {
    "id": 1,
    "title": "CVE-2024-0001 - package 1.0.0",
    "description": "Vulnerability description",
    "severity": "high",
    "category": "vulnerability",
    "cve_id": "CVE-2024-0001",
    "cvss_score": 7.5,
    "recommendation": "Update package to patched version"
  }
]
```

### List Scans

**GET** `/scans?limit=10`

List recent scans.

**Query Parameters:**
- `limit` (optional): Maximum number of scans to return (default: 10)

**Response:**
```json
[
  {
    "id": 1,
    "target": "localhost",
    "scan_type": "full",
    "status": "completed",
    "started_at": "2024-01-01T12:00:00",
    "completed_at": "2024-01-01T12:05:00"
  }
]
```

## Error Responses

All errors follow this format:

```json
{
  "detail": "Error message"
}
```

**Status Codes:**
- `200`: Success
- `404`: Resource not found
- `500`: Internal server error

