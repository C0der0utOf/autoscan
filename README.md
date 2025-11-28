# Security Automation Platform

A comprehensive security automation platform that combines vulnerability scanning, compliance checking, and security configuration analysis. Built to demonstrate enterprise security expertise through practical, production-ready tooling.

## Features

- **Multi-Framework Compliance Scanner**: CIS Benchmarks, NIST Cybersecurity Framework, and custom policy rules
- **Vulnerability Assessment Engine**: CVE database integration with risk scoring and prioritization
- **Security Configuration Analyzer**: System hardening, network security, and authentication checks
- **Reporting & Dashboard**: CLI interface, web dashboard, and multiple report formats (JSON, CSV, PDF)

## Quick Start

### Installation

#### Automated Setup

```bash
./setup.sh
```

#### Manual Setup

```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Initialize database
python3 -c "from src.core.database import init_db; init_db()"
```

### CLI Usage

```bash
# Activate virtual environment first
source venv/bin/activate

# Run a full security scan
python -m src.cli.main scan --target localhost

# Check compliance against CIS Benchmarks
python -m src.cli.main compliance --framework cis

# Scan for vulnerabilities
python -m src.cli.main vulnerability

# Generate a report (JSON format)
python -m src.cli.main report --scan-id 1 --format json

# Get help
python -m src.cli.main --help
```

### API Server

```bash
# Start the API server
uvicorn src.api.main:app --reload

# API will be available at http://localhost:8000
# API documentation at http://localhost:8000/docs
```

### Dashboard

```bash
# Navigate to dashboard directory
cd dashboard

# Install dependencies
npm install

# Start development server
npm run dev

# Dashboard will be available at http://localhost:3000
```

### Docker

```bash
# Build and start services
docker-compose up -d

# View logs
docker-compose logs -f

# Stop services
docker-compose down
```

## Architecture

- **Backend**: Python 3.11+ with FastAPI
- **Frontend**: React/TypeScript dashboard with Vite
- **Database**: SQLite (local) or PostgreSQL (enterprise)
- **CLI**: Click-based command interface with Rich output
- **Testing**: pytest with coverage reporting

## Project Structure

```
cybersec/
├── src/                    # Source code
│   ├── api/                # REST API endpoints
│   ├── cli/                # Command-line interface
│   ├── compliance/         # Compliance checking modules
│   ├── config_analyzer/    # Configuration analysis
│   ├── core/               # Core utilities and models
│   └── vulnerability/      # Vulnerability scanning
├── dashboard/               # React frontend
├── tests/                  # Test suite
├── docs/                   # Documentation
├── configs/                # Policy templates and rules
└── requirements.txt        # Python dependencies
```

## Features in Detail

### Compliance Scanning

- **CIS Benchmarks**: Automated checking against CIS Linux Benchmark rules
- **Custom Policies**: YAML-based policy engine for custom compliance rules
- **Framework Support**: Extensible architecture for adding new frameworks

### Vulnerability Assessment

- **CVE Integration**: Real-time CVE lookup using NVD API
- **Package Scanning**: Automatic detection of installed packages and versions
- **Risk Scoring**: CVSS-based severity classification
- **Caching**: Local cache to reduce API calls and improve performance

### Configuration Analysis

- **System Hardening**: SSH, firewall, and system configuration checks
- **File Permissions**: Critical file permission validation
- **Network Security**: Network configuration and security settings
- **Password Policies**: Authentication and password policy checks

## Configuration

Configuration is managed through environment variables. See `.env.example` for available options.

Key configuration options:
- `NVD_API_KEY`: NVD API key for vulnerability scanning (optional but recommended)
- `DATABASE_URL`: Database connection string
- `LOG_LEVEL`: Logging level (DEBUG, INFO, WARNING, ERROR)
- `CVE_CACHE_TTL_HOURS`: CVE cache time-to-live in hours

## Development

### Running Tests

```bash
pytest tests/ -v
pytest tests/ --cov=src --cov-report=html
```

### Code Quality

```bash
# Format code
black src tests

# Lint code
ruff check src tests

# Type checking
mypy src
```

## Documentation

See `docs/` for detailed documentation:
- [Architecture Overview](docs/ARCHITECTURE.md)
- [API Reference](docs/API.md)
- [Security Best Practices](docs/SECURITY.md)
- [Contributing Guidelines](docs/CONTRIBUTING.md)

## Requirements

- Python 3.11+
- Node.js 18+ (for dashboard)
- SQLite (included) or PostgreSQL (for production)

## Limitations

- CVE scanning requires NVD API access (free tier available)
- Some compliance checks require root/admin privileges
- Package detection works best on Linux systems
- CVE scanning is limited to first 50 packages for demo purposes

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](docs/CONTRIBUTING.md) for guidelines.

## Security

For security concerns, please see [SECURITY.md](docs/SECURITY.md).

## License

MIT License - see LICENSE file for details


