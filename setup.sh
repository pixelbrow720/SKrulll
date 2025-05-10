#!/bin/bash

# SKrulll Setup Script
# This script sets up the development environment for SKrulll

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored messages
print_message() {
    echo -e "${2}${1}${NC}"
}

# Function to print section headers
print_header() {
    echo -e "\n${BLUE}=== $1 ===${NC}\n"
}

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to detect OS
detect_os() {
    case "$(uname -s)" in
        Linux*)     OS="linux";;
        Darwin*)    OS="mac";;
        CYGWIN*|MINGW*|MSYS*) OS="windows";;
        *)          OS="unknown";;
    esac
    echo $OS
}

# Function to detect Linux distribution
detect_linux_distro() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        DISTRO=$ID
    elif command_exists lsb_release; then
        DISTRO=$(lsb_release -si | tr '[:upper:]' '[:lower:]')
    elif [ -f /etc/lsb-release ]; then
        . /etc/lsb-release
        DISTRO=$DISTRIB_ID
    elif [ -f /etc/debian_version ]; then
        DISTRO="debian"
    else
        DISTRO="unknown"
    fi
    echo $DISTRO
}

# Function to install dependencies on Ubuntu/Debian
install_debian_deps() {
    print_message "Installing dependencies for Ubuntu/Debian..." "$YELLOW"
    sudo apt-get update
    sudo apt-get install -y \
        python3 python3-pip python3-venv \
        golang rustc cargo \
        git curl wget \
        build-essential libssl-dev \
        postgresql postgresql-contrib \
        mongodb \
        docker.io docker-compose
    
    # Install Neo4j
    print_message "Installing Neo4j..." "$YELLOW"
    wget -O - https://debian.neo4j.com/neotechnology.gpg.key | sudo apt-key add -
    echo 'deb https://debian.neo4j.com stable latest' | sudo tee -a /etc/apt/sources.list.d/neo4j.list
    sudo apt-get update
    sudo apt-get install -y neo4j
}

# Function to install dependencies on Fedora/RHEL/CentOS
install_fedora_deps() {
    print_message "Installing dependencies for Fedora/RHEL/CentOS..." "$YELLOW"
    sudo dnf install -y \
        python3 python3-pip python3-virtualenv \
        golang rust cargo \
        git curl wget \
        gcc gcc-c++ make openssl-devel \
        postgresql postgresql-server \
        docker docker-compose

    # Install MongoDB
    print_message "Installing MongoDB..." "$YELLOW"
    cat << EOF | sudo tee /etc/yum.repos.d/mongodb-org.repo
[mongodb-org-6.0]
name=MongoDB Repository
baseurl=https://repo.mongodb.org/yum/redhat/\$releasever/mongodb-org/6.0/x86_64/
gpgcheck=1
enabled=1
gpgkey=https://www.mongodb.org/static/pgp/server-6.0.asc
EOF
    sudo dnf install -y mongodb-org
    
    # Install Neo4j
    print_message "Installing Neo4j..." "$YELLOW"
    cat << EOF | sudo tee /etc/yum.repos.d/neo4j.repo
[neo4j]
name=Neo4j Yum Repo
baseurl=https://yum.neo4j.com/stable
enabled=1
gpgcheck=1
gpgkey=https://debian.neo4j.com/neotechnology.gpg.key
EOF
    sudo dnf install -y neo4j
}

# Function to install dependencies on macOS
install_mac_deps() {
    print_message "Installing dependencies for macOS..." "$YELLOW"
    
    # Check if Homebrew is installed
    if ! command_exists brew; then
        print_message "Installing Homebrew..." "$YELLOW"
        /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    fi
    
    # Install dependencies
    brew update
    brew install \
        python3 \
        go rust \
        git curl wget \
        openssl \
        postgresql \
        mongodb-community \
        neo4j \
        docker docker-compose
}

# Function to install dependencies on Windows (using WSL)
install_windows_deps() {
    print_message "For Windows, we recommend using Windows Subsystem for Linux (WSL)." "$YELLOW"
    print_message "Please follow these steps:" "$YELLOW"
    print_message "1. Install WSL by running 'wsl --install' in PowerShell as Administrator" "$YELLOW"
    print_message "2. Install Ubuntu from the Microsoft Store" "$YELLOW"
    print_message "3. Launch Ubuntu and run this script again" "$YELLOW"
    print_message "4. For Docker, install Docker Desktop for Windows" "$YELLOW"
    
    read -p "Do you want to continue with the setup assuming you have WSL installed? (y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
    
    # Assuming WSL with Ubuntu
    install_debian_deps
}

# Function to set up Python virtual environment
setup_python_venv() {
    print_header "Setting up Python virtual environment"
    
    if [ -d "venv" ]; then
        print_message "Virtual environment already exists. Updating..." "$YELLOW"
        source venv/bin/activate || source venv/Scripts/activate
    else
        print_message "Creating new virtual environment..." "$YELLOW"
        python3 -m venv venv
        source venv/bin/activate || source venv/Scripts/activate
    fi
    
    print_message "Installing Python dependencies..." "$YELLOW"
    pip install --upgrade pip
    pip install -r requirements.txt
    
    print_message "Python environment setup complete!" "$GREEN"
}

# Function to set up Go environment
setup_go_env() {
    print_header "Setting up Go environment"
    
    if command_exists go; then
        print_message "Go is installed. Version: $(go version)" "$YELLOW"
        print_message "Installing Go dependencies..." "$YELLOW"
        go mod download
        
        # Install dependencies for subdirectories with go.mod files
        for dir in $(find . -name "go.mod" -not -path "./go.mod" -exec dirname {} \;); do
            print_message "Installing Go dependencies for $dir..." "$YELLOW"
            (cd $dir && go mod download)
        done
        
        print_message "Go environment setup complete!" "$GREEN"
    else
        print_message "Go is not installed. Please install Go manually." "$RED"
    fi
}

# Function to set up Rust environment
setup_rust_env() {
    print_header "Setting up Rust environment"
    
    if command_exists cargo; then
        print_message "Rust is installed. Version: $(rustc --version)" "$YELLOW"
        print_message "Installing Rust dependencies..." "$YELLOW"
        cargo fetch
        
        # Install dependencies for subdirectories with Cargo.toml files
        for dir in $(find . -name "Cargo.toml" -not -path "./Cargo.toml" -exec dirname {} \;); do
            print_message "Installing Rust dependencies for $dir..." "$YELLOW"
            (cd $dir && cargo fetch)
        done
        
        print_message "Rust environment setup complete!" "$GREEN"
    else
        print_message "Rust is not installed. Please install Rust manually." "$RED"
    fi
}

# Function to set up Docker environment
setup_docker_env() {
    print_header "Setting up Docker environment"
    
    if command_exists docker; then
        print_message "Docker is installed. Version: $(docker --version)" "$YELLOW"
        
        # Check if Docker is running
        if docker info >/dev/null 2>&1; then
            print_message "Docker is running." "$GREEN"
        else
            print_message "Docker is not running. Please start Docker daemon." "$RED"
            return
        fi
        
        print_message "Building Docker images..." "$YELLOW"
        docker-compose -f templates/docker-compose.yml build
        
        print_message "Docker environment setup complete!" "$GREEN"
    else
        print_message "Docker is not installed. Please install Docker manually." "$RED"
    fi
}

# Function to set up databases
setup_databases() {
    print_header "Setting up databases"
    
    read -p "Do you want to set up databases locally (l) or use Docker (d)? " -n 1 -r
    echo
    
    if [[ $REPLY =~ ^[Dd]$ ]]; then
        print_message "Setting up databases using Docker..." "$YELLOW"
        docker-compose -f templates/docker-compose.yml up -d postgresql mongodb elasticsearch neo4j
        print_message "Database containers started!" "$GREEN"
    elif [[ $REPLY =~ ^[Ll]$ ]]; then
        print_message "Please ensure PostgreSQL, MongoDB, Elasticsearch, and Neo4j are running locally." "$YELLOW"
        print_message "You may need to create databases and users manually." "$YELLOW"
        
        # Initialize databases if needed
        read -p "Do you want to initialize the databases? (y/n) " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            print_message "Initializing databases..." "$YELLOW"
            python main.py db init
            print_message "Databases initialized!" "$GREEN"
        fi
    else
        print_message "Invalid option. Skipping database setup." "$RED"
    fi
}

# Main function
main() {
    print_header "SKrulll Setup Script"
    
    # Detect OS
    OS=$(detect_os)
    print_message "Detected OS: $OS" "$YELLOW"
    
    # Install dependencies based on OS
    case $OS in
        linux)
            DISTRO=$(detect_linux_distro)
            print_message "Detected Linux distribution: $DISTRO" "$YELLOW"
            
            case $DISTRO in
                ubuntu|debian)
                    install_debian_deps
                    ;;
                fedora|rhel|centos)
                    install_fedora_deps
                    ;;
                *)
                    print_message "Unsupported Linux distribution: $DISTRO" "$RED"
                    print_message "Please install dependencies manually." "$RED"
                    ;;
            esac
            ;;
        mac)
            install_mac_deps
            ;;
        windows)
            install_windows_deps
            ;;
        *)
            print_message "Unsupported OS: $OS" "$RED"
            print_message "Please install dependencies manually." "$RED"
            ;;
    esac
    
    # Setup environments
    read -p "Do you want to set up Python environment? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        setup_python_venv
    fi
    
    read -p "Do you want to set up Go environment? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        setup_go_env
    fi
    
    read -p "Do you want to set up Rust environment? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        setup_rust_env
    fi
    
    read -p "Do you want to set up Docker environment? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        setup_docker_env
    fi
    
    read -p "Do you want to set up databases? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        setup_databases
    fi
    
    print_header "Setup Complete"
    print_message "SKrulll environment has been set up successfully!" "$GREEN"
    print_message "To start using SKrulll:" "$YELLOW"
    print_message "1. Activate the Python virtual environment: source venv/bin/activate" "$YELLOW"
    print_message "2. Run the application: python main.py" "$YELLOW"
    print_message "3. For development, refer to the documentation in docs/" "$YELLOW"
}

# Run the main function
main
