# Contributing to SKrulll

Thank you for your interest in contributing to SKrulll! This document provides guidelines and instructions for contributing to this project.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Environment](#development-environment)
- [Contribution Workflow](#contribution-workflow)
- [Coding Standards](#coding-standards)
- [Testing](#testing)
- [Documentation](#documentation)
- [Issue Reporting](#issue-reporting)
- [Pull Requests](#pull-requests)
- [Review Process](#review-process)
- [Community](#community)

## Code of Conduct

By participating in this project, you agree to abide by our [Code of Conduct](CODE_OF_CONDUCT.md). Please read it to understand the expectations we have for everyone who contributes to this project.

## Getting Started

1. **Fork the repository** on GitHub
2. **Clone your fork** locally:
   ```bash
   git clone https://github.com/YOUR-USERNAME/SKrulll.git
   cd SKrulll
   ```
3. **Set up the upstream remote**:
   ```bash
   git remote add upstream https://github.com/pixelbrow720/SKrulll.git
   ```
4. **Create a virtual environment** and install dependencies:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -r requirements.txt
   pip install -r requirements-dev.txt  # Development dependencies
   ```

## Development Environment

- Python 3.8+ is required
- We recommend using an IDE with good Python support (PyCharm, VS Code, etc.)
- Install pre-commit hooks to ensure code quality:
  ```bash
  pre-commit install
  ```

## Contribution Workflow

1. **Create a new branch** for your feature or bugfix:
   ```bash
   git checkout -b feature/your-feature-name
   ```
   or
   ```bash
   git checkout -b fix/issue-you-are-fixing
   ```

2. **Make your changes** and commit them with clear, descriptive commit messages:
   ```bash
   git commit -m "Add feature: detailed description of what you did"
   ```

3. **Keep your branch updated** with the upstream main branch:
   ```bash
   git fetch upstream
   git rebase upstream/main
   ```

4. **Push your changes** to your fork:
   ```bash
   git push origin feature/your-feature-name
   ```

5. **Submit a pull request** from your branch to the main repository

## Coding Standards

- Follow [PEP 8](https://www.python.org/dev/peps/pep-0008/) style guidelines
- Use type hints where appropriate
- Keep functions and methods focused on a single responsibility
- Write docstrings for all public functions, classes, and methods
- Use meaningful variable and function names
- Our pre-commit hooks will check for:
  - Code formatting with Black
  - Import sorting with isort
  - Linting with flake8
  - Type checking with mypy

## Testing

- Write tests for all new features and bug fixes
- Ensure all tests pass before submitting a pull request:
  ```bash
  python -m pytest
  ```
- Aim for high test coverage:
  ```bash
  python -m pytest --cov=modules
  ```

## Documentation

- Update documentation for any new features or changes
- Document public APIs, classes, and functions
- Include examples where appropriate
- Update the README.md if necessary

## Issue Reporting

- Use the issue tracker to report bugs or request features
- Check if the issue already exists before creating a new one
- For bugs, include:
  - Steps to reproduce
  - Expected behavior
  - Actual behavior
  - Environment details (OS, Python version, etc.)
  - Screenshots or logs if applicable
- For feature requests, include:
  - Clear description of the feature
  - Rationale for adding the feature
  - Potential implementation details (if you have ideas)

## Pull Requests

- Link the PR to any related issues
- Include a clear description of the changes
- Update documentation as needed
- Ensure all tests pass
- Add new tests for new functionality
- Keep PRs focused on a single change to make review easier

## Review Process

- All PRs require at least one review from a maintainer
- Address all review comments
- Be responsive to feedback
- Be patient - maintainers are often busy
- Once approved, a maintainer will merge your PR

## Community

- Join our [community forum](https://community.skrulll.security) for discussions
- Follow us on [Twitter](https://twitter.com/BrowPixel) for updates
- Participate in discussions on issues and pull requests
- Help others who have questions

Thank you for contributing to SKrulll! Your efforts help make this project better for everyone.
