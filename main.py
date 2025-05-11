#!/usr/bin/env python3
"""
SKrulll - A Python-based cybersecurity and OSINT tool orchestrator

This is the main entry point for the application, which launches the web
application and ties together all the components of the system.
"""
import logging
import os
import sys
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

from web.app import create_app
from orchestrator.cli import cli_app
from orchestrator.logging_config import configure_logging

# Configure logging before anything else
configure_logging()
logger = logging.getLogger(__name__)

# Create the Flask app for Gunicorn to use
app = create_app()

if __name__ == "__main__":
    try:
        logger.info("Starting SKrulll Orchestrator")
        cli_app()
    except KeyboardInterrupt:
        logger.info("Received interrupt, shutting down...")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Fatal error: {str(e)}", exc_info=True)
        sys.exit(1)
