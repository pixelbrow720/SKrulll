"""
Utility functions for the web application.
Provides common helper functions used across the application.
"""

import os
import re
import uuid
import json
import secrets
import logging
from datetime import datetime
from functools import wraps
from typing import Dict, List, Optional, Union, Callable, Any

from flask import request, g, current_app, jsonify, session, Response


def format_error_response(message: str, code: int = 500, details: Optional[Dict[str, Any]] = None) -> Response:
    """
    Format an error response as JSON
    
    Args:
        message: Error message
        code: HTTP status code
        details: Additional error details
        
    Returns:
        JSON response with error information
    """
    response = {
        'status': 'error',
        'message': message,
        'code': code
    }
    
    if details:
        response['details'] = details
    
    return jsonify(response), code


def format_success_response(message: str, data: Optional[Dict[str, Any]] = None) -> Response:
    """
    Format a success response as JSON
    
    Args:
        message: Success message
        data: Response data
        
    Returns:
        JSON response with success information
    """
    response = {
        'status': 'success',
        'message': message
    }
    
    if data:
        response['data'] = data
    
    return jsonify(response)


def validate_json_request(schema_class: Any) -> Callable:
    """
    Decorator to validate JSON request data against a Pydantic schema
    
    Args:
        schema_class: Pydantic model class to validate against
        
    Returns:
        The decorated function
    """
    def decorator(f: Callable) -> Callable:
        @wraps(f)
        def decorated(*args, **kwargs):
            # Check if request has JSON data
            if not request.is_json and not request.form:
                return format_error_response(
                    message="Request must be JSON or form data",
                    code=400
                )
            
            try:
                # Get data from request
                if request.is_json:
                    data = request.json
                else:
                    # Convert form data to dict
                    data = request.form.to_dict()
                    
                    # Handle special cases for form data
                    # Convert string 'true'/'false' to boolean
                    for key, value in data.items():
                        if value.lower() == 'true':
                            data[key] = True
                        elif value.lower() == 'false':
                            data[key] = False
                
                # Validate data against schema
                validated_data = schema_class(**data)
                
                # Store validated data in request context
                g.validated_data = validated_data
                
                return f(*args, **kwargs)
            except Exception as e:
                # Log validation error
                current_app.logger.warning(f"Validation error: {str(e)}")
                
                # Return error response
                return format_error_response(
                    message="Validation error",
                    code=400,
                    details={"errors": str(e)}
                )
        
        return decorated
    
    return decorator


def log_api_call(f: Callable) -> Callable:
    """
    Decorator to log API calls
    
    Args:
        f: The function to decorate
        
    Returns:
        The decorated function
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        # Get request information
        method = request.method
        path = request.path
        ip = get_client_ip()
        user_id = getattr(g, 'user_id', 'anonymous')
        
        # Log API call
        current_app.logger.info(f"API call: {method} {path} from {ip} by {user_id}")
        
        # Call the original function
        return f(*args, **kwargs)
    
    return decorated


def generate_csrf_token() -> str:
    """
    Generate a CSRF token and store it in the session
    
    Returns:
        CSRF token string
    """
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)
    
    return session['csrf_token']


def generate_unique_id() -> str:
    """
    Generate a unique ID
    
    Returns:
        Unique ID string
    """
    return str(uuid.uuid4())


def get_client_ip() -> str:
    """
    Get the client IP address from the request
    
    Returns:
        Client IP address string
    """
    # Check for X-Forwarded-For header (for proxies)
    if request.headers.get('X-Forwarded-For'):
        ip = request.headers.get('X-Forwarded-For').split(',')[0].strip()
    else:
        ip = request.remote_addr or '127.0.0.1'
    
    return ip


def sanitize_filename(filename: str) -> str:
    """
    Sanitize a filename to prevent directory traversal attacks
    
    Args:
        filename: The filename to sanitize
        
    Returns:
        Sanitized filename
    """
    # Remove any directory components
    filename = os.path.basename(filename)
    
    # Remove any non-alphanumeric characters except for .-_
    filename = re.sub(r'[^\w\.-]', '_', filename)
    
    return filename


def format_datetime(dt: datetime, format_str: str = '%Y-%m-%d %H:%M:%S') -> str:
    """
    Format a datetime object as a string
    
    Args:
        dt: The datetime object to format
        format_str: The format string to use
        
    Returns:
        Formatted datetime string
    """
    return dt.strftime(format_str)


def parse_datetime(dt_str: str, format_str: str = '%Y-%m-%d %H:%M:%S') -> datetime:
    """
    Parse a datetime string into a datetime object
    
    Args:
        dt_str: The datetime string to parse
        format_str: The format string to use
        
    Returns:
        Parsed datetime object
    """
    return datetime.strptime(dt_str, format_str)


def truncate_string(s: str, max_length: int = 100, suffix: str = '...') -> str:
    """
    Truncate a string to a maximum length
    
    Args:
        s: The string to truncate
        max_length: The maximum length
        suffix: The suffix to add if truncated
        
    Returns:
        Truncated string
    """
    if len(s) <= max_length:
        return s
    
    return s[:max_length - len(suffix)] + suffix


def is_valid_domain(domain: str) -> bool:
    """
    Check if a string is a valid domain name
    
    Args:
        domain: The domain name to check
        
    Returns:
        True if valid, False otherwise
    """
    pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    return bool(re.match(pattern, domain))


def is_valid_ip(ip: str) -> bool:
    """
    Check if a string is a valid IP address
    
    Args:
        ip: The IP address to check
        
    Returns:
        True if valid, False otherwise
    """
    # IPv4 pattern
    ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    
    # IPv6 pattern (simplified)
    ipv6_pattern = r'^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$'
    
    if re.match(ipv4_pattern, ip):
        # Check if each octet is valid
        octets = ip.split('.')
        for octet in octets:
            if int(octet) > 255:
                return False
        return True
    
    return bool(re.match(ipv6_pattern, ip))


def is_valid_url(url: str) -> bool:
    """
    Check if a string is a valid URL
    
    Args:
        url: The URL to check
        
    Returns:
        True if valid, False otherwise
    """
    pattern = r'^(https?|ftp)://[^\s/$.?#].[^\s]*$'
    return bool(re.match(pattern, url))


def safe_json_loads(json_str: str, default: Any = None) -> Any:
    """
    Safely load a JSON string
    
    Args:
        json_str: The JSON string to load
        default: The default value to return if loading fails
        
    Returns:
        Parsed JSON object or default value
    """
    try:
        return json.loads(json_str)
    except (json.JSONDecodeError, TypeError):
        return default
