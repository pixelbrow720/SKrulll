#!/bin/bash

# SKrulll Setup Script for macOS
# This script sets up the development environment for SKrulll on macOS

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

# Function to install dependencies on macOS
install_mac_deps() {
    print_message "Installing dependencies for macOS..." "$YELLOW"
    
    # Check if Homebrew is installed
    if ! command_exists brew; then
        print_message "Installing Homebrew..." "$YELLOW"
        /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
        
        # Add Homebrew to PATH
        if [[ $(uname -m) == "arm64" ]]; then
            # For Apple Silicon
            echo 'eval "$(/opt/homebrew/bin/brew shellenv)"' >> ~/.zprofile
            eval "$(/opt/homebrew/bin/brew shellenv)"
        else
            # For Intel
            echo 'eval "$(/usr/local/bin/brew shellenv)"' >> ~/.zprofile
            eval "$(/usr/local/bin/brew shellenv)"
        fi
    fi
    
    # Install dependencies
    print_message "Updating Homebrew..." "$YELLOW"
    brew update
    
    print_message "Installing Python..." "$YELLOW"
    brew install python@3.10
    
    print_message "Installing Go..." "$YELLOW"
    brew install go
    
    print_message "Installing Rust..." "$YELLOW"
    brew install rust
    
    print_message "Installing Git and utilities..." "$YELLOW"
    brew install git curl wget
    
    print_message "Installing OpenSSL..." "$YELLOW"
    brew install openssl
    
    print_message "Installing PostgreSQL..." "$YELLOW"
    brew install postgresql
    
    print_message "Installing MongoDB..." "$YELLOW"
    brew tap mongodb/brew
    brew install mongodb-community
    
    print_message "Installing Neo4j..." "$YELLOW"
    brew install neo4j
    
    print_message "Installing Elasticsearch..." "$YELLOW"
    brew tap elastic/tap
    brew install elastic/tap/elasticsearch
    
    print_message "Installing Docker..." "$YELLOW"
    brew install --cask docker
    
    print_message "All dependencies installed!" "$GREEN"
}

# Function to set up Python virtual environment
setup_python_venv() {
    print_header "Setting up Python virtual environment"
    
    if [ -d "venv" ]; then
        print_message "Virtual environment already exists. Updating..." "$YELLOW"
        source venv/bin/activate
    else
        print_message "Creating new virtual environment..." "$YELLOW"
        python3 -m venv venv
        source venv/bin/activate
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
            print_message "Docker is not running. Please start Docker Desktop." "$RED"
            print_message "You can find Docker Desktop in your Applications folder." "$RED"
            return
        fi
        
        print_message "Building Docker images..." "$YELLOW"
        docker-compose -f templates/docker-compose.yml build
        
        print_message "Docker environment setup complete!" "$GREEN"
    else
        print_message "Docker is not installed. Please install Docker Desktop for Mac." "$RED"
        print_message "Download from: https://www.docker.com/products/docker-desktop" "$RED"
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
        print_message "Setting up local databases..." "$YELLOW"
        
        # Start PostgreSQL
        print_message "Starting PostgreSQL..." "$YELLOW"
        brew services start postgresql
        
        # Start MongoDB
        print_message "Starting MongoDB..." "$YELLOW"
        brew services start mongodb-community
        
        # Start Neo4j
        print_message "Starting Neo4j..." "$YELLOW"
        brew services start neo4j
        
        # Start Elasticsearch
        print_message "Starting Elasticsearch..." "$YELLOW"
        brew services start elasticsearch
        
        print_message "Local databases started!" "$GREEN"
        print_message "You may need to create databases and users manually." "$YELLOW"
        
        # Initialize databases if needed
        read -p "Do you want to initialize the databases? (y/n) " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            print_message "Initializing databases..." "$YELLOW"
            python3 main.py db init
            print_message "Databases initialized!" "$GREEN"
        fi
    else
        print_message "Invalid option. Skipping database setup." "$RED"
    fi
}

# Main function
main() {
    print_header "SKrulll Setup Script for macOS"
    
    # Install dependencies
    read -p "Do you want to install dependencies? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        install_mac_deps
    fi
    
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
    print_message "2. Run the application: python3 main.py" "$YELLOW"
    print_message "3. For development, refer to the documentation in docs/" "$YELLOW"
}

# Run the main function
main
