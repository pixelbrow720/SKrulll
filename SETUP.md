# SKrulll Setup Guide

This document provides instructions for setting up the SKrulll development environment on different operating systems.

## Setup Scripts

SKrulll includes setup scripts for different operating systems to make the installation process easier:

- `setup.sh` - For Linux users
- `setup.command` - For macOS users
- `setup.bat` - For Windows users

## Usage Instructions

### Linux

1. Open a terminal in the project directory
2. Make the script executable (if not already):
   ```bash
   chmod +x setup.sh
   ```
3. Run the script:
   ```bash
   ./setup.sh
   ```
4. Follow the interactive prompts to install dependencies and set up the environment

### macOS

1. Open a terminal in the project directory
2. Make the script executable (if not already):
   ```bash
   chmod +x setup.command
   ```
3. Run the script:
   ```bash
   ./setup.command
   ```
   Alternatively, you can double-click the `setup.command` file in Finder
4. Follow the interactive prompts to install dependencies and set up the environment

### Windows

1. Open Command Prompt or PowerShell as Administrator
2. Navigate to the project directory
3. Run the script:
   ```
   setup.bat
   ```
4. Follow the interactive prompts to install dependencies and set up the environment

## Manual Setup

If you prefer to set up the environment manually, you'll need to install:

1. **Python 3.8+** - For core functionality
2. **Go 1.18+** - For certain modules
3. **Rust** - For performance-critical components
4. **Docker** (optional) - For containerized deployment
5. **Databases**:
   - PostgreSQL
   - MongoDB
   - Neo4j
   - Elasticsearch

After installing the dependencies, you'll need to:

1. Create a Python virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

2. Install Python dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Install Go dependencies:
   ```bash
   go mod download
   ```

4. Install Rust dependencies:
   ```bash
   cargo fetch
   ```

## Git Issues

If you encounter Git-related issues, such as divergent branches, you can use the included `git-fix.sh` script:

1. Make the script executable:
   ```bash
   chmod +x git-fix.sh
   ```

2. Run the script:
   ```bash
   ./git-fix.sh
   ```

3. Follow the prompts to resolve Git issues

## Troubleshooting

If you encounter issues during setup:

1. Check that all prerequisites are installed correctly
2. Ensure you have appropriate permissions (admin/sudo)
3. Check the logs for error messages
4. Refer to the documentation in the `docs/` directory
5. Open an issue on the GitHub repository

## Next Steps

After setting up the environment:

1. Activate the Python virtual environment:
   ```bash
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

2. Run the application:
   ```bash
   python main.py
   ```

3. For development, refer to the documentation in the `docs/` directory
