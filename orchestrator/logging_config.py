"""
Logging configuration for the CyberOps Orchestrator.

This module sets up logging for the application, including console and file logging,
log rotation, and log formatting.
"""
import logging
import logging.handlers
import os
from pathlib import Path
from typing import Optional


def configure_logging(log_level: str = "INFO", 
                      log_file: Optional[str] = None,
                      log_format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s") -> None:
    """
    Configure logging for the application.
    
    Args:
        log_level: The logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Path to the log file (if None, only console logging is configured)
        log_format: Format string for log messages
    """
    # Convert log level string to logging constant
    numeric_level = getattr(logging, log_level.upper(), None)
    if not isinstance(numeric_level, int):
        numeric_level = logging.INFO
        
    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(numeric_level)
    
    # Remove any existing handlers to avoid duplicate logging
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    
    # Create console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(numeric_level)
    console_formatter = logging.Formatter(log_format)
    console_handler.setFormatter(console_formatter)
    root_logger.addHandler(console_handler)
    
    # Create file handler if log file is specified
    if log_file:
        log_dir = os.path.dirname(log_file)
        if log_dir:
            Path(log_dir).mkdir(parents=True, exist_ok=True)
            
        # Use a rotating file handler to prevent logs from growing too large
        file_handler = logging.handlers.RotatingFileHandler(
            log_file, maxBytes=10*1024*1024, backupCount=5)
        file_handler.setLevel(numeric_level)
        file_formatter = logging.Formatter(log_format)
        file_handler.setFormatter(file_formatter)
        root_logger.addHandler(file_handler)
        
    logging.info(f"Logging configured with level {log_level}")


def get_module_logger(module_name: str) -> logging.Logger:
    """
    Get a logger for a specific module.
    
    Args:
        module_name: Name of the module
        
    Returns:
        Logger configured for the module
    """
    return logging.getLogger(module_name)
