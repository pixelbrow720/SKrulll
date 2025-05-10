# SKrulll - Advanced Cybersecurity and OSINT Tool Orchestrator

![SKrulll Logo](../static/img/logo.png)

## Overview

SKrulll is a comprehensive cybersecurity and OSINT (Open Source Intelligence) tool orchestrator that provides a unified interface for various security tools, allowing them to work together seamlessly with centralized configuration and data sharing.

Developed by [@pixelbrow720](https://github.com/pixelbrow720) | [Twitter @BrowPixel](https://twitter.com/BrowPixel) | [Email: pixelbrow13@gmail.com](mailto:pixelbrow13@gmail.com)

## Features

- **Modular Architecture**: Easily extensible with new tools and capabilities
- **Unified Interface**: Access all tools through a consistent CLI and web interface
- **Automated Workflows**: Chain tools together for comprehensive security assessments
- **Centralized Reporting**: Consolidated findings from multiple tools
- **Multi-Database Support**: Store and query data using PostgreSQL, MongoDB, Elasticsearch, and Neo4j
- **Visualization**: Generate visual representations of network maps, attack paths, and more
- **Scheduling**: Automate recurring tasks and scans

## Components

SKrulll consists of several key components:

- **OSINT Modules**: Domain reconnaissance, social media analysis, search footprinting
- **Security Modules**: Vulnerability scanning, port scanning, network mapping, attack vector analysis
- **Orchestrator**: Core system that manages tool execution and data flow
- **Web Interface**: User-friendly dashboard for managing scans and viewing results
- **CLI**: Command-line interface for scripting and automation
- **Scheduler**: Task scheduling and management
- **Database Connectors**: Interfaces to various databases for data storage and retrieval

## Installation

### Prerequisites

- Python 3.8+
- Docker and Docker Compose (for containerized components)
- Neo4j (for attack path mapping)
- PostgreSQL (for primary data storage)
- MongoDB (for unstructured data storage)
- Elasticsearch (for search and analytics)

### Basic Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/pixelbrow720/SKrulll.git
   cd SKrulll
   ```

2. Install Python dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Set up the configuration:
   ```bash
   cp config/config.example.yaml config/config.yaml
   # Edit config.yaml with your settings
   ```

4. Start the databases (if using Docker):
   ```bash
   docker-compose -f templates/docker-compose.yml up -d
   ```

5. Run the application:
   ```bash
   python main.py
   ```

### Docker Installation

For a fully containerized setup:

```bash
docker-compose -f templates/docker-compose.yml up -d
```

This will start all required services including the SKrulll application, databases, and supporting services.

## Usage

### Command Line Interface

SKrulll provides a comprehensive CLI for all operations:

```bash
# Get help
python main.py --help

# Run a port scan
python main.py security portscan 192.168.1.1 --ports 1-1000

# Perform domain reconnaissance
python main.py osint domain example.com --whois --dns --subdomains

# Analyze social media presence
python main.py osint social username --platforms twitter,reddit,linkedin

# Run a vulnerability scan
python main.py security vulnscan https://example.com --level high

# Map network topology
python main.py security netmap 192.168.1.0/24 --visualize

# Schedule a recurring task
python main.py schedule add "Daily Port Scan" "security portscan 192.168.1.0/24" --cron "0 0 * * *"
```

### Web Interface

The web interface provides a user-friendly dashboard for managing scans and viewing results:

1. Start the web interface:
   ```bash
   python main.py webui
   ```

2. Open your browser and navigate to `http://localhost:5000`

3. Log in with your credentials

4. Use the dashboard to:
   - Launch scans
   - View results
   - Generate reports
   - Manage scheduled tasks
   - Configure system settings

## Architecture

SKrulll follows a modular architecture with the following key components:

```
SKrulll/
├── main.py                 # Main entry point
├── orchestrator/           # Core orchestration logic
├── modules/                # Tool modules
│   ├── osint/              # OSINT tools
│   ├── security/           # Security assessment tools
│   └── vulnerability/      # Vulnerability scanning tools
├── web/                    # Web interface
├── scheduler/              # Task scheduling
├── templates/              # Docker and report templates
└── config/                 # Configuration files
```

## Development

### Adding New Modules

1. Create a new module in the appropriate directory
2. Implement the required interfaces
3. Register the module with the orchestrator
4. Add CLI commands and web interface components

See the [Developer Guide](development.md) for detailed instructions.

### Testing

SKrulll includes comprehensive tests:

```bash
# Run unit tests
python -m unittest discover tests

# Run integration tests
python -m unittest tests.test_integration

# Run end-to-end tests
python -m unittest tests.test_e2e

# Run benchmarks
python tests/benchmark.py
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Thanks to all the open-source security tools that SKrulll builds upon
- Special thanks to contributors and testers

## Contact

- GitHub: [@pixelbrow720](https://github.com/pixelbrow720)
- Twitter: [@BrowPixel](https://twitter.com/BrowPixel)
- Email: [pixelbrow13@gmail.com](mailto:pixelbrow13@gmail.com)
