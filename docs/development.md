# SKrulll Development Guide

This guide provides detailed information for developers who want to contribute to or extend the SKrulll platform.

## Development Environment Setup

### Prerequisites

- Python 3.8+
- Docker and Docker Compose
- Git
- A code editor (VS Code recommended)
- Virtual environment tool (venv, virtualenv, or conda)

### Setting Up the Development Environment

1. Clone the repository:
   ```bash
   git clone https://github.com/pixelbrow720/SKrulll.git
   cd SKrulll
   ```

2. Create and activate a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install development dependencies:
   ```bash
   pip install -r requirements-dev.txt
   ```

4. Set up pre-commit hooks:
   ```bash
   pre-commit install
   ```

5. Start the development databases:
   ```bash
   docker-compose -f templates/docker-compose-dev.yml up -d
   ```

## Project Structure

The SKrulll project follows a modular architecture:

```
SKrulll/
├── main.py                 # Main entry point
├── orchestrator/           # Core orchestration logic
│   ├── __init__.py
│   ├── cli.py              # Command-line interface
│   ├── config.py           # Configuration management
│   ├── logging_config.py   # Logging configuration
│   ├── messaging.py        # Inter-module messaging
│   └── db/                 # Database clients
├── modules/                # Tool modules
│   ├── osint/              # OSINT tools
│   ├── security/           # Security assessment tools
│   └── vulnerability/      # Vulnerability scanning tools
├── web/                    # Web interface
│   ├── __init__.py
│   ├── app.py              # Flask application
│   ├── auth.py             # Authentication
│   ├── routes.py           # Route definitions
│   ├── schemas.py          # Data schemas
│   ├── utils.py            # Utility functions
│   ├── static/             # Static assets
│   └── templates/          # HTML templates
├── scheduler/              # Task scheduling
├── templates/              # Docker and report templates
├── config/                 # Configuration files
├── tests/                  # Test suite
│   ├── __init__.py
│   ├── benchmark.py        # Performance benchmarks
│   ├── test_e2e.py         # End-to-end tests
│   ├── test_integration.py # Integration tests
│   └── test_*.py           # Unit tests
└── docs/                   # Documentation
```

## Coding Standards

SKrulll follows these coding standards:

1. **PEP 8**: Follow the [PEP 8](https://www.python.org/dev/peps/pep-0008/) style guide for Python code.
2. **Docstrings**: Use Google-style docstrings for all modules, classes, and functions.
3. **Type Hints**: Use type hints for function parameters and return values.
4. **Testing**: Write unit tests for all new functionality.
5. **Error Handling**: Use appropriate exception handling and provide meaningful error messages.
6. **Logging**: Use the logging module instead of print statements.

Example of a well-formatted function:

```python
def analyze_domain(domain: str, perform_whois: bool = True) -> Dict[str, Any]:
    """
    Analyze a domain and gather information about it.
    
    Args:
        domain: The domain name to analyze
        perform_whois: Whether to perform a WHOIS lookup
        
    Returns:
        A dictionary containing the analysis results
        
    Raises:
        ValueError: If the domain is invalid
    """
    logger.info(f"Analyzing domain: {domain}")
    
    try:
        # Implementation
        results = {}
        
        # Return results
        return results
    except Exception as e:
        logger.error(f"Error analyzing domain {domain}: {str(e)}")
        raise
```

## Adding New Modules

SKrulll is designed to be easily extensible with new modules. Here's how to add a new module:

### 1. Create the Module Structure

Create a new directory in the appropriate location:

```bash
mkdir -p modules/category/new_module
touch modules/category/new_module/__init__.py
touch modules/category/new_module/main.py
```

### 2. Implement the Module Interface

Each module should implement a standard interface:

```python
# modules/category/new_module/main.py
import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)

class NewModule:
    """
    A new module for SKrulll.
    
    This module provides functionality for...
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        """
        Initialize the module.
        
        Args:
            config: Module configuration
        """
        self.config = config or {}
        logger.debug("Initialized NewModule")
    
    def run(self, target: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Run the module on a target.
        
        Args:
            target: The target to analyze
            options: Additional options for the analysis
            
        Returns:
            A dictionary containing the results
        """
        options = options or {}
        logger.info(f"Running NewModule on {target}")
        
        # Implementation
        results = {
            "module": "new_module",
            "target": target,
            "findings": []
        }
        
        return results
```

### 3. Register the Module with the Orchestrator

Update the orchestrator to include your new module:

```python
# orchestrator/config.py
def register_modules():
    """Register all available modules"""
    modules = {
        # Existing modules...
        "category.new_module": {
            "class": "modules.category.new_module.main.NewModule",
            "description": "A new module for SKrulll",
            "options": {
                "option1": {"type": "string", "default": "value1", "description": "Option 1"},
                "option2": {"type": "boolean", "default": True, "description": "Option 2"}
            }
        }
    }
    return modules
```

### 4. Add CLI Commands

Add CLI commands for your module:

```python
# orchestrator/cli.py
@category.command('new_module')
@click.argument('target')
@click.option('--option1', help='Option 1')
@click.option('--option2', is_flag=True, help='Option 2')
@click.pass_context
def category_new_module(ctx, target, option1, option2):
    """Run the new module on a target."""
    try:
        # Get the module
        from modules.category.new_module.main import NewModule
        
        # Create module instance
        module = NewModule(ctx.obj.get('config', {}).get('category', {}).get('new_module', {}))
        
        # Run the module
        results = module.run(target, {
            'option1': option1,
            'option2': option2
        })
        
        # Display results
        click.echo(f"New Module Results for {target}:")
        # Format and display results
        
    except Exception as e:
        logger.error(f"Error running new module: {str(e)}", exc_info=True)
        click.echo(f"Error: {str(e)}", err=True)
```

### 5. Add Web Interface Components (Optional)

If your module needs a web interface, add routes and templates:

```python
# web/routes.py
@api_bp.route('/category/new_module', methods=['POST'])
@api_key_required
@validate_json_request(NewModuleRequest)
@log_api_call
def api_new_module():
    """API endpoint for the new module"""
    # Get validated data
    data = g.validated_data
    
    # Run the module
    from modules.category.new_module.main import NewModule
    module = NewModule()
    results = module.run(data.target, data.options)
    
    return format_success_response(
        message="New module completed successfully",
        data={"results": results}
    )
```

### 6. Write Tests

Write tests for your module:

```python
# tests/test_new_module.py
import unittest
from unittest.mock import patch, MagicMock
from modules.category.new_module.main import NewModule

class TestNewModule(unittest.TestCase):
    """Test cases for NewModule"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.module = NewModule()
    
    def test_run(self):
        """Test running the module"""
        results = self.module.run("test_target", {"option1": "value1", "option2": True})
        
        # Verify results
        self.assertEqual(results["module"], "new_module")
        self.assertEqual(results["target"], "test_target")
```

## Testing

SKrulll uses unittest for testing. There are several types of tests:

### Unit Tests

Test individual components in isolation:

```bash
python -m unittest tests.test_module_name
```

### Integration Tests

Test how components work together:

```bash
python -m unittest tests.test_integration
```

### End-to-End Tests

Test complete workflows:

```bash
python -m unittest tests.test_e2e
```

### Benchmarks

Measure performance:

```bash
python tests/benchmark.py
```

## Continuous Integration

SKrulll uses GitHub Actions for CI/CD. The workflow includes:

1. Running tests on multiple Python versions
2. Checking code style with flake8
3. Measuring test coverage
4. Building and testing Docker images

## Documentation

Documentation is written in Markdown and stored in the `docs/` directory. To build the documentation:

```bash
mkdocs build
```

To serve the documentation locally:

```bash
mkdocs serve
```

## Release Process

1. Update version number in `orchestrator/config.py`
2. Update CHANGELOG.md
3. Create a new release on GitHub
4. Build and push Docker images
5. Update documentation

## Getting Help

If you need help with development:

- Check the existing documentation
- Look at the code examples
- Open an issue on GitHub
- Contact the maintainers

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Write or update tests
5. Submit a pull request

Please follow the coding standards and include tests for new functionality.
