# Architecture Documentation

## Overview

The Security Automation Platform is designed as a modular, extensible system for security scanning, compliance checking, and vulnerability assessment.

## System Architecture

### Core Components

1. **Scanner Engine** (`src/core/scanner.py`)
   - Orchestrates all scanning activities
   - Manages scan lifecycle and status
   - Coordinates between different scanning modules

2. **Compliance Module** (`src/compliance/`)
   - CIS Benchmarks checking
   - Custom policy engine
   - Framework-specific rule evaluation

3. **Vulnerability Module** (`src/vulnerability/`)
   - CVE database integration (NVD API)
   - Package version detection
   - Risk scoring and prioritization

4. **Configuration Analyzer** (`src/config_analyzer/`)
   - System hardening checks
   - Network security assessment
   - File permission validation

5. **API Layer** (`src/api/`)
   - RESTful API using FastAPI
   - JSON-based communication
   - Async request handling

6. **CLI Interface** (`src/cli/`)
   - Command-line interface using Click
   - Rich terminal output
   - Multiple output formats (JSON, CSV, table)

## Data Flow

```
User Request (CLI/API)
    ↓
SecurityScanner.scan()
    ↓
    ├── Compliance Checks → CISBenchmarkChecker
    ├── Vulnerability Scan → CVEScanner
    └── Config Analysis → SystemHardeningAnalyzer
    ↓
Results stored in Database
    ↓
Formatted Output (JSON/CSV/Table)
```

## Database Schema

### Tables

- **scans**: Scan execution records
- **findings**: Security findings from scans
- **compliance_results**: Compliance check results

## Configuration

Configuration is managed through:
- Environment variables (`.env` file)
- `src/core/config.py` (Pydantic settings)
- YAML configuration files in `configs/`

## Extensibility

The platform is designed to be easily extended:

1. **New Compliance Frameworks**: Add new checker classes in `src/compliance/`
2. **New Vulnerability Sources**: Extend `CVEScanner` or create new scanner classes
3. **New Configuration Checks**: Add methods to `SystemHardeningAnalyzer`
4. **Custom Policies**: Use the policy engine in `src/compliance/policy_engine.py`

## Security Considerations

- All external API calls use rate limiting
- CVE data is cached to reduce API calls
- Database connections use connection pooling
- Input validation through Pydantic models
- Structured logging for audit trails

## Deployment

The platform can be deployed as:
- Standalone CLI tool
- REST API server
- Docker container
- Docker Compose stack

