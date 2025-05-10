"""
Configuration management for the SKrulll Orchestrator.

This module provides functionality for loading and managing configuration
settings from environment variables, configuration files, and defaults.
"""
import json
import logging
import os
from pathlib import Path
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

# Default configuration values
DEFAULT_CONFIG = {
    "logging": {
        "level": "INFO",
        "file": None,
        "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    },
    "database": {
        "postgresql": {
            "host": os.environ.get("PGHOST", "localhost"),
            "port": int(os.environ.get("PGPORT", 5432)),
            "user": os.environ.get("PGUSER", "postgres"),
            "password": os.environ.get("PGPASSWORD", ""),
            "database": os.environ.get("PGDATABASE", "cyberops"),
            "url": os.environ.get("DATABASE_URL", "")
        },
        "mongodb": {
            "host": os.environ.get("MONGODB_HOST", "localhost"),
            "port": int(os.environ.get("MONGODB_PORT", 27017)),
            "username": os.environ.get("MONGODB_USERNAME", ""),
            "password": os.environ.get("MONGODB_PASSWORD", ""),
            "database": os.environ.get("MONGODB_DATABASE", "cyberops")
        },
        "elasticsearch": {
            "hosts": [os.environ.get("ELASTICSEARCH_HOST", "localhost:9200")],
            "username": os.environ.get("ELASTICSEARCH_USERNAME", ""),
            "password": os.environ.get("ELASTICSEARCH_PASSWORD", "")
        },
        "neo4j": {
            "uri": os.environ.get("NEO4J_URI", "bolt://localhost:7687"),
            "username": os.environ.get("NEO4J_USERNAME", "neo4j"),
            "password": os.environ.get("NEO4J_PASSWORD", "")
        }
    },
    "messaging": {
        "type": os.environ.get("MESSAGING_TYPE", "rabbitmq"),
        "rabbitmq": {
            "host": os.environ.get("RABBITMQ_HOST", "localhost"),
            "port": int(os.environ.get("RABBITMQ_PORT", 5672)),
            "virtual_host": os.environ.get("RABBITMQ_VHOST", "/"),
            "username": os.environ.get("RABBITMQ_USERNAME", "guest"),
            "password": os.environ.get("RABBITMQ_PASSWORD", "guest")
        },
        "kafka": {
            "bootstrap_servers": os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092"),
            "client_id": os.environ.get("KAFKA_CLIENT_ID", "cyberops")
        }
    },
    "modules": {
        "osint": {
            "domain_recon": {
                "whois_timeout": 10,
                "dns_timeout": 5,
                "subdomain_wordlist": "wordlists/subdomains.txt"
            },
            "social_media": {
                "platforms": ["twitter", "instagram", "linkedin", "github", "facebook"]
            }
        },
        "security": {
            "port_scanner": {
                "default_timeout": 1.0,
                "default_ports": [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]
            },
            "vulnerability_scanner": {
                "timeout": 30,
                "user_agent": "SKrulll Vulnerability Scanner v0.1.0"
            }
        }
    },
    "web": {
        "host": "0.0.0.0",
        "port": 5000,
        "debug": False,
        "secret_key": os.environ.get("SECRET_KEY", os.urandom(24).hex())
    },
    "scheduler": {
        "storage_path": "data/scheduler.json"
    }
}


def load_config(config_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Load configuration from file and merge with defaults.
    
    Args:
        config_path: Path to the configuration file (JSON format).
        
    Returns:
        Dict containing the merged configuration.
    """
    config = DEFAULT_CONFIG.copy()
    
    # If config path is provided, load and merge with defaults
    if config_path:
        try:
            config_file = Path(config_path)
            if config_file.exists():
                logger.info(f"Loading configuration from {config_path}")
                with open(config_file, 'r') as f:
                    file_config = json.load(f)
                    
                # Deep merge the configurations
                deep_merge(config, file_config)
                logger.debug("Configuration loaded and merged successfully")
            else:
                logger.warning(f"Configuration file not found: {config_path}")
        except Exception as e:
            logger.error(f"Error loading configuration: {str(e)}", exc_info=True)
            
    return config


def deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    """
    Deep merge two dictionaries, overriding values in base with those from override.
    
    Args:
        base: Base dictionary
        override: Dictionary with override values
        
    Returns:
        Merged dictionary
    """
    for key, value in override.items():
        if key in base and isinstance(base[key], dict) and isinstance(value, dict):
            deep_merge(base[key], value)
        else:
            base[key] = value
    return base


def get_config_value(config: Dict[str, Any], path: str, default: Any = None) -> Any:
    """
    Get a configuration value using a dot-notation path.
    
    Args:
        config: Configuration dictionary
        path: Dot-notation path to the config value (e.g., 'database.postgresql.host')
        default: Default value to return if path not found
        
    Returns:
        Configuration value or default if not found
    """
    parts = path.split('.')
    current = config
    
    for part in parts:
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return default
            
    return current


def save_config(config: Dict[str, Any], config_path: str) -> bool:
    """
    Save configuration to a file.
    
    Args:
        config: Configuration dictionary
        config_path: Path to save the configuration file
        
    Returns:
        True if successful, False otherwise
    """
    try:
        # Ensure directory exists
        config_file = Path(config_path)
        config_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(config_file, 'w') as f:
            json.dump(config, f, indent=2)
            
        logger.info(f"Configuration saved to {config_path}")
        return True
    except Exception as e:
        logger.error(f"Error saving configuration: {str(e)}", exc_info=True)
        return False
