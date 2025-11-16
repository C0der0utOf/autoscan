# Contributing Guidelines

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/your-username/cybersec.git`
3. Create a virtual environment: `python -m venv venv`
4. Activate the virtual environment: `source venv/bin/activate` (Linux/Mac) or `venv\Scripts\activate` (Windows)
5. Install dependencies: `pip install -r requirements.txt`
6. Install development dependencies: `pip install -r requirements-dev.txt` (if available)

## Development Workflow

1. Create a new branch: `git checkout -b feature/your-feature-name`
2. Make your changes
3. Run tests: `pytest tests/ -v`
4. Run linting: `black src tests && ruff check src tests`
5. Commit your changes: `git commit -m "Add feature: description"`
6. Push to your fork: `git push origin feature/your-feature-name`
7. Create a pull request

## Code Style

- Follow PEP 8 style guide
- Use Black for code formatting (line length: 100)
- Use type hints for function parameters and return values
- Write docstrings for all classes and functions
- Keep functions focused and small

## Testing

- Write tests for all new features
- Aim for >80% code coverage
- Use pytest for testing
- Place tests in the `tests/` directory

## Documentation

- Update README.md if adding new features
- Add docstrings to all new functions and classes
- Update API documentation if changing endpoints
- Keep architecture documentation up to date

## Security Considerations

- Never commit API keys or secrets
- Use environment variables for sensitive configuration
- Follow secure coding practices
- Review security implications of new features

## Pull Request Process

1. Ensure all tests pass
2. Ensure code passes linting checks
3. Update documentation as needed
4. Add a clear description of changes
5. Reference any related issues

## Questions?

Feel free to open an issue for questions or discussions about contributions.

