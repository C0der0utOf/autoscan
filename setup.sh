#!/bin/bash

# Setup script for Security Automation Platform

set -e

echo "Setting up Security Automation Platform..."

# Check Python version
python_version=$(python3 --version 2>&1 | awk '{print $2}')
required_version="3.11"

if [ "$(printf '%s\n' "$required_version" "$python_version" | sort -V | head -n1)" != "$required_version" ]; then
    echo "Error: Python 3.11 or higher is required. Found: $python_version"
    exit 1
fi

# Create virtual environment
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
echo "Activating virtual environment..."
source venv/bin/activate

# Install dependencies
echo "Installing Python dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

# Create necessary directories
echo "Creating directories..."
mkdir -p data/cve_cache
mkdir -p reports
mkdir -p logs

# Copy .env.example to .env if it doesn't exist
if [ ! -f ".env" ]; then
    echo "Creating .env file from .env.example..."
    cp .env.example .env
    echo "Please edit .env file and add your NVD API key if needed"
fi

# Initialize database
echo "Initializing database..."
python3 -c "from src.core.database import init_db; init_db()"

echo ""
echo "Setup complete!"
echo ""
echo "To get started:"
echo "  1. Activate virtual environment: source venv/bin/activate"
echo "  2. Run a scan: python -m src.cli.main scan --target localhost"
echo "  3. Start API server: uvicorn src.api.main:app --reload"
echo "  4. (Optional) Get NVD API key from https://nvd.nist.gov/developers/request-an-api-key"
echo ""

