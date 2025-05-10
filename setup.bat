@echo off
setlocal enabledelayedexpansion

echo ===================================
echo SKrulll Setup Script for Windows
echo ===================================
echo.

:: Check for admin privileges
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo This script requires administrator privileges.
    echo Please run this script as an administrator.
    pause
    exit /b 1
)

:: Set color codes
set "RED=31"
set "GREEN=32"
set "YELLOW=33"
set "BLUE=34"

:: Function to print colored messages
call :print_message "SKrulll Setup Script for Windows" %BLUE%

:: Check for Python
call :print_message "Checking for Python..." %YELLOW%
where python >nul 2>&1
if %errorLevel% neq 0 (
    call :print_message "Python not found. Please install Python 3.8 or higher." %RED%
    call :print_message "Download from: https://www.python.org/downloads/" %RED%
    pause
    exit /b 1
) else (
    for /f "tokens=*" %%i in ('python --version') do set PYTHON_VERSION=%%i
    call :print_message "Found !PYTHON_VERSION!" %GREEN%
)

:: Check for Go
call :print_message "Checking for Go..." %YELLOW%
where go >nul 2>&1
if %errorLevel% neq 0 (
    call :print_message "Go not found. Please install Go 1.18 or higher." %RED%
    call :print_message "Download from: https://golang.org/dl/" %RED%
    set GO_MISSING=1
) else (
    for /f "tokens=*" %%i in ('go version') do set GO_VERSION=%%i
    call :print_message "Found !GO_VERSION!" %GREEN%
    set GO_MISSING=0
)

:: Check for Rust
call :print_message "Checking for Rust..." %YELLOW%
where rustc >nul 2>&1
if %errorLevel% neq 0 (
    call :print_message "Rust not found. Please install Rust." %RED%
    call :print_message "Download from: https://www.rust-lang.org/tools/install" %RED%
    set RUST_MISSING=1
) else (
    for /f "tokens=*" %%i in ('rustc --version') do set RUST_VERSION=%%i
    call :print_message "Found !RUST_VERSION!" %GREEN%
    set RUST_MISSING=0
)

:: Check for Docker
call :print_message "Checking for Docker..." %YELLOW%
where docker >nul 2>&1
if %errorLevel% neq 0 (
    call :print_message "Docker not found. Please install Docker Desktop for Windows." %RED%
    call :print_message "Download from: https://www.docker.com/products/docker-desktop" %RED%
    set DOCKER_MISSING=1
) else (
    for /f "tokens=*" %%i in ('docker --version') do set DOCKER_VERSION=%%i
    call :print_message "Found !DOCKER_VERSION!" %GREEN%
    set DOCKER_MISSING=0
)

echo.
call :print_message "Setup Options" %BLUE%
echo.

:: Setup Python environment
set /p SETUP_PYTHON="Do you want to set up Python environment? (y/n): "
if /i "!SETUP_PYTHON!"=="y" (
    call :setup_python_env
)

:: Setup Go environment
if %GO_MISSING% equ 0 (
    set /p SETUP_GO="Do you want to set up Go environment? (y/n): "
    if /i "!SETUP_GO!"=="y" (
        call :setup_go_env
    )
)

:: Setup Rust environment
if %RUST_MISSING% equ 0 (
    set /p SETUP_RUST="Do you want to set up Rust environment? (y/n): "
    if /i "!SETUP_RUST!"=="y" (
        call :setup_rust_env
    )
)

:: Setup Docker environment
if %DOCKER_MISSING% equ 0 (
    set /p SETUP_DOCKER="Do you want to set up Docker environment? (y/n): "
    if /i "!SETUP_DOCKER!"=="y" (
        call :setup_docker_env
    )
)

:: Setup databases
set /p SETUP_DB="Do you want to set up databases? (y/n): "
if /i "!SETUP_DB!"=="y" (
    call :setup_databases
)

echo.
call :print_message "Setup Complete!" %GREEN%
call :print_message "To start using SKrulll:" %YELLOW%
call :print_message "1. Activate the Python virtual environment: venv\Scripts\activate" %YELLOW%
call :print_message "2. Run the application: python main.py" %YELLOW%
call :print_message "3. For development, refer to the documentation in docs/" %YELLOW%

pause
exit /b 0

:: ===== Functions =====

:print_message
echo [%~2m%~1[0m
exit /b 0

:setup_python_env
call :print_message "Setting up Python virtual environment..." %YELLOW%
if exist venv (
    call :print_message "Virtual environment already exists. Updating..." %YELLOW%
    call venv\Scripts\activate
) else (
    call :print_message "Creating new virtual environment..." %YELLOW%
    python -m venv venv
    call venv\Scripts\activate
)

call :print_message "Installing Python dependencies..." %YELLOW%
python -m pip install --upgrade pip
pip install -r requirements.txt

call :print_message "Python environment setup complete!" %GREEN%
exit /b 0

:setup_go_env
call :print_message "Setting up Go environment..." %YELLOW%
go mod download

:: Install dependencies for subdirectories with go.mod files
for /f "tokens=*" %%G in ('dir /b /s go.mod ^| findstr /v "\\go.mod$"') do (
    set "GO_DIR=%%~dpG"
    call :print_message "Installing Go dependencies for !GO_DIR!" %YELLOW%
    pushd "!GO_DIR!"
    go mod download
    popd
)

call :print_message "Go environment setup complete!" %GREEN%
exit /b 0

:setup_rust_env
call :print_message "Setting up Rust environment..." %YELLOW%
cargo fetch

:: Install dependencies for subdirectories with Cargo.toml files
for /f "tokens=*" %%G in ('dir /b /s Cargo.toml ^| findstr /v "\\Cargo.toml$"') do (
    set "RUST_DIR=%%~dpG"
    call :print_message "Installing Rust dependencies for !RUST_DIR!" %YELLOW%
    pushd "!RUST_DIR!"
    cargo fetch
    popd
)

call :print_message "Rust environment setup complete!" %GREEN%
exit /b 0

:setup_docker_env
call :print_message "Setting up Docker environment..." %YELLOW%

:: Check if Docker is running
docker info >nul 2>&1
if %errorLevel% neq 0 (
    call :print_message "Docker is not running. Please start Docker Desktop." %RED%
    exit /b 1
)

call :print_message "Building Docker images..." %YELLOW%
docker-compose -f templates/docker-compose.yml build

call :print_message "Docker environment setup complete!" %GREEN%
exit /b 0

:setup_databases
call :print_message "Setting up databases..." %YELLOW%

set /p DB_OPTION="Do you want to set up databases locally (l) or use Docker (d)? "
if /i "!DB_OPTION!"=="d" (
    call :print_message "Setting up databases using Docker..." %YELLOW%
    docker-compose -f templates/docker-compose.yml up -d postgresql mongodb elasticsearch neo4j
    call :print_message "Database containers started!" %GREEN%
) else if /i "!DB_OPTION!"=="l" (
    call :print_message "Please ensure PostgreSQL, MongoDB, Elasticsearch, and Neo4j are running locally." %YELLOW%
    call :print_message "You may need to create databases and users manually." %YELLOW%
    
    set /p INIT_DB="Do you want to initialize the databases? (y/n): "
    if /i "!INIT_DB!"=="y" (
        call :print_message "Initializing databases..." %YELLOW%
        python main.py db init
        call :print_message "Databases initialized!" %GREEN%
    )
) else (
    call :print_message "Invalid option. Skipping database setup." %RED%
)

exit /b 0
