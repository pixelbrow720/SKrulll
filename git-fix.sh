#!/bin/bash

# Git Fix Script for SKrulll
# This script helps resolve common Git issues

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

print_header "Git Fix Script"

print_message "Detected divergent branches issue. This is common when working with Git repositories." "$YELLOW"
print_message "This script will help you resolve the issue." "$YELLOW"

echo
print_message "Choose how to reconcile divergent branches:" "$BLUE"
echo "1. Merge (recommended for most cases)"
echo "2. Rebase (good for clean history, but can cause issues if commits were pushed)"
echo "3. Fast-forward only (only works if branches can be fast-forwarded)"
echo

read -p "Enter your choice (1-3): " choice

case $choice in
    1)
        print_message "Setting Git pull strategy to merge..." "$YELLOW"
        git config pull.rebase false
        print_message "Git pull strategy set to merge." "$GREEN"
        ;;
    2)
        print_message "Setting Git pull strategy to rebase..." "$YELLOW"
        git config pull.rebase true
        print_message "Git pull strategy set to rebase." "$GREEN"
        ;;
    3)
        print_message "Setting Git pull strategy to fast-forward only..." "$YELLOW"
        git config pull.ff only
        print_message "Git pull strategy set to fast-forward only." "$GREEN"
        ;;
    *)
        print_message "Invalid choice. Exiting." "$RED"
        exit 1
        ;;
esac

print_message "Would you like to apply this setting globally for all repositories?" "$YELLOW"
read -p "Apply globally? (y/n): " global

if [[ $global =~ ^[Yy]$ ]]; then
    case $choice in
        1)
            git config --global pull.rebase false
            ;;
        2)
            git config --global pull.rebase true
            ;;
        3)
            git config --global pull.ff only
            ;;
    esac
    print_message "Global Git pull strategy updated." "$GREEN"
fi

print_header "Current Status"
git status

print_header "Next Steps"
print_message "Now you can try pulling again with:" "$YELLOW"
print_message "git pull origin main" "$GREEN"
print_message "If you have uncommitted changes, you may want to stash them first:" "$YELLOW"
print_message "git stash" "$GREEN"
print_message "git pull origin main" "$GREEN"
print_message "git stash pop" "$GREEN"

print_header "Additional Git Commands"
print_message "To see what changes are in your local branch:" "$YELLOW"
print_message "git log --oneline --cherry main...origin/main" "$GREEN"
print_message "To discard all local changes and reset to remote branch:" "$YELLOW"
print_message "git fetch origin" "$GREEN"
print_message "git reset --hard origin/main" "$GREEN"

print_message "Git configuration has been updated successfully!" "$GREEN"
