#!/bin/bash

# Docker Migration Script for SKrulll
# This script helps analyze and migrate from old Docker templates to optimized versions

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

print_header "Docker Migration Analysis"

print_message "This script will help you analyze the Docker files in your project and migrate to the optimized versions." "$YELLOW"
print_message "The analysis shows:" "$YELLOW"

echo
print_message "1. Optimized Dockerfiles (in config/optimized_docker/):" "$GREEN"
print_message "   - Use more recent base images (Python 3.10 vs 3.9, Rust 1.70 vs 1.63)" "$GREEN"
print_message "   - Have more optimizations like Python bytecode compilation" "$GREEN"
print_message "   - Implement better caching strategies" "$GREEN"
print_message "   - Are labeled as 'Optimized' in the comments" "$GREEN"

echo
print_message "2. Base Templates (in templates/docker/):" "$YELLOW"
print_message "   - Use older base images" "$YELLOW"
print_message "   - Have fewer optimizations" "$YELLOW"
print_message "   - Are labeled as 'Base Dockerfile template' in the comments" "$YELLOW"
print_message "   - Include specialized Dockerfiles like api-tester.dockerfile that don't exist in the optimized directory" "$YELLOW"

echo
print_message "Recommendation:" "$BLUE"
print_message "The files in config/optimized_docker/ appear to be upgraded versions of the base templates in templates/docker/." "$BLUE"
print_message "However, templates/docker/ also contains specialized Dockerfiles that don't have optimized versions yet." "$BLUE"

echo
print_header "Migration Options"

echo "1. Keep both directories (current state)"
echo "2. Migrate specialized Dockerfiles to use optimized base images"
echo "3. Move all optimized Dockerfiles to templates/docker/ and remove config/optimized_docker/"
echo "4. Move all Dockerfiles to config/optimized_docker/ and remove templates/docker/"
echo

read -p "Enter your choice (1-4): " choice

case $choice in
    1)
        print_message "Keeping both directories. No changes made." "$GREEN"
        ;;
    2)
        print_header "Migrating Specialized Dockerfiles"
        
        # Create backup directory
        mkdir -p backup/templates/docker
        
        # Backup original files
        print_message "Creating backups in backup/templates/docker/..." "$YELLOW"
        cp templates/docker/*.dockerfile backup/templates/docker/
        
        # Update api-tester.dockerfile
        if [ -f templates/docker/api-tester.dockerfile ]; then
            print_message "Updating api-tester.dockerfile to use optimized base image..." "$YELLOW"
            sed -i 's/FROM golang:.*$/FROM golang:1.20-alpine/' templates/docker/api-tester.dockerfile
            print_message "Updated api-tester.dockerfile" "$GREEN"
        fi
        
        # Update exploit-tester.dockerfile
        if [ -f templates/docker/exploit-tester.dockerfile ]; then
            print_message "Updating exploit-tester.dockerfile to use optimized base image..." "$YELLOW"
            sed -i 's/FROM python:.*$/FROM python:3.10-slim/' templates/docker/exploit-tester.dockerfile
            print_message "Updated exploit-tester.dockerfile" "$GREEN"
        fi
        
        # Update vulnerability-scanner.dockerfile
        if [ -f templates/docker/vulnerability-scanner.dockerfile ]; then
            print_message "Updating vulnerability-scanner.dockerfile to use optimized base image..." "$YELLOW"
            sed -i 's/FROM python:.*$/FROM python:3.10-slim/' templates/docker/vulnerability-scanner.dockerfile
            print_message "Updated vulnerability-scanner.dockerfile" "$GREEN"
        fi
        
        print_message "Specialized Dockerfiles have been updated to use more recent base images." "$GREEN"
        print_message "Original files were backed up to backup/templates/docker/" "$GREEN"
        ;;
    3)
        print_header "Moving Optimized Dockerfiles to templates/docker/"
        
        # Create backup directories
        mkdir -p backup/templates/docker backup/config/optimized_docker
        
        # Backup original files
        print_message "Creating backups..." "$YELLOW"
        cp templates/docker/*.dockerfile backup/templates/docker/
        cp config/optimized_docker/*.dockerfile backup/config/optimized_docker/
        
        # Copy optimized Dockerfiles to templates/docker/
        print_message "Copying optimized Dockerfiles to templates/docker/..." "$YELLOW"
        cp config/optimized_docker/go.dockerfile templates/docker/golang.dockerfile
        cp config/optimized_docker/node.dockerfile templates/docker/nodejs.dockerfile
        cp config/optimized_docker/python.dockerfile templates/docker/python.dockerfile
        cp config/optimized_docker/rust.dockerfile templates/docker/rust.dockerfile
        
        # Ask if user wants to remove the optimized_docker directory
        read -p "Do you want to remove the config/optimized_docker/ directory? (y/n): " remove_dir
        if [[ $remove_dir =~ ^[Yy]$ ]]; then
            print_message "Removing config/optimized_docker/ directory..." "$YELLOW"
            rm -rf config/optimized_docker/
            print_message "Removed config/optimized_docker/ directory" "$GREEN"
        fi
        
        print_message "Optimized Dockerfiles have been moved to templates/docker/" "$GREEN"
        print_message "Original files were backed up to backup/templates/docker/ and backup/config/optimized_docker/" "$GREEN"
        ;;
    4)
        print_header "Moving All Dockerfiles to config/optimized_docker/"
        
        # Create backup directories
        mkdir -p backup/templates/docker backup/config/optimized_docker
        
        # Backup original files
        print_message "Creating backups..." "$YELLOW"
        cp templates/docker/*.dockerfile backup/templates/docker/
        cp config/optimized_docker/*.dockerfile backup/config/optimized_docker/
        
        # Copy specialized Dockerfiles to config/optimized_docker/
        print_message "Copying specialized Dockerfiles to config/optimized_docker/..." "$YELLOW"
        cp templates/docker/api-tester.dockerfile config/optimized_docker/
        cp templates/docker/exploit-tester.dockerfile config/optimized_docker/
        cp templates/docker/vulnerability-scanner.dockerfile config/optimized_docker/
        
        # Ask if user wants to remove the templates/docker directory
        read -p "Do you want to remove the templates/docker/ directory? (y/n): " remove_dir
        if [[ $remove_dir =~ ^[Yy]$ ]]; then
            print_message "Removing templates/docker/ directory..." "$YELLOW"
            rm -rf templates/docker/
            print_message "Removed templates/docker/ directory" "$GREEN"
        fi
        
        print_message "All Dockerfiles have been moved to config/optimized_docker/" "$GREEN"
        print_message "Original files were backed up to backup/templates/docker/ and backup/config/optimized_docker/" "$GREEN"
        ;;
    *)
        print_message "Invalid choice. No changes made." "$RED"
        ;;
esac

print_header "Docker Migration Complete"
print_message "You may need to update any scripts or documentation that reference these Dockerfile paths." "$YELLOW"
print_message "Don't forget to update your docker-compose.yml files if necessary." "$YELLOW"
