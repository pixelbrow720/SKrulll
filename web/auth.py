"""
Authentication and authorization utilities.
Provides decorators and functions for securing API endpoints.
"""

import os
import time
import uuid
import hashlib
import hmac
import json
import logging
from datetime import datetime, timedelta
from functools import wraps
from typing import Dict, List, Optional, Union, Callable, Any

import jwt
from flask import request, g, current_app, jsonify, abort, session
from werkzeug.local import LocalProxy

from web.utils import format_error_response, get_client_ip


# Constants
TOKEN_ALGORITHM = 'HS256'
TOKEN_EXPIRY = 24 * 60 * 60  # 24 hours in seconds
REFRESH_TOKEN_EXPIRY = 30 * 24 * 60 * 60  # 30 days in seconds
RATE_LIMIT_WINDOW = 60  # 1 minute in seconds


# Get the current user ID from the global context
current_user_id = LocalProxy(lambda: getattr(g, 'user_id', None))
current_user_is_admin = LocalProxy(lambda: getattr(g, 'is_admin', False))


def generate_token(user_id: str, is_admin: bool = False) -> str:
    """
    Generate a JWT token for a user
    
    Args:
        user_id: The user ID
        is_admin: Whether the user is an admin
        
    Returns:
        JWT token string
    """
    now = int(time.time())
    payload = {
        'sub': user_id,
        'iat': now,
        'exp': now + TOKEN_EXPIRY,
        'admin': is_admin
    }
    
    secret_key = current_app.config.get('SECRET_KEY', 'dev_key_change_in_production')
    return jwt.encode(payload, secret_key, algorithm=TOKEN_ALGORITHM)


def generate_refresh_token(user_id: str) -> str:
    """
    Generate a refresh token for a user
    
    Args:
        user_id: The user ID
        
    Returns:
        JWT refresh token string
    """
    now = int(time.time())
    payload = {
        'sub': user_id,
        'iat': now,
        'exp': now + REFRESH_TOKEN_EXPIRY,
        'type': 'refresh'
    }
    
    secret_key = current_app.config.get('SECRET_KEY', 'dev_key_change_in_production')
    return jwt.encode(payload, secret_key, algorithm=TOKEN_ALGORITHM)


def decode_token(token: str) -> Dict[str, Any]:
    """
    Decode and validate a JWT token
    
    Args:
        token: The JWT token to decode
        
    Returns:
        The decoded token payload or an error dict
    """
    try:
        secret_key = current_app.config.get('SECRET_KEY', 'dev_key_change_in_production')
        return jwt.decode(token, secret_key, algorithms=[TOKEN_ALGORITHM])
    except jwt.ExpiredSignatureError:
        return {'error': 'Token has expired'}
    except jwt.InvalidTokenError:
        return {'error': 'Invalid token'}


def generate_api_key() -> str:
    """
    Generate a new API key
    
    Returns:
        A new API key string
    """
    # Generate a random UUID
    key_uuid = uuid.uuid4()
    
    # Get the current timestamp
    timestamp = int(time.time())
    
    # Combine UUID and timestamp
    combined = f"{key_uuid}-{timestamp}"
    
    # Hash the combined string
    secret_key = current_app.config.get('SECRET_KEY', 'dev_key_change_in_production')
    signature = hmac.new(
        secret_key.encode(),
        combined.encode(),
        hashlib.sha256
    ).hexdigest()
    
    # Return the API key in the format prefix.signature
    return f"sk_{signature[:32]}"


def validate_api_key(api_key: str) -> Dict[str, Any]:
    """
    Validate an API key and return the associated user information
    
    Args:
        api_key: The API key to validate
        
    Returns:
        Dict with user information or None if invalid
    """
    # In a real app, you'd look up the API key in a database
    # For now, we'll use a mock implementation
    
    # Check if the API key has the correct format
    if not api_key.startswith('sk_'):
        return None
    
    # Mock API key validation
    if api_key == 'sk_test_valid_key':
        return {
            'user_id': '1',
            'is_admin': True,
            'permissions': ['read', 'write', 'delete']
        }
    
    return None


def token_required(f: Callable) -> Callable:
    """
    Decorator to require a valid JWT token for an endpoint
    
    Args:
        f: The function to decorate
        
    Returns:
        The decorated function
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        # Get the token from the Authorization header
        auth_header = request.headers.get('Authorization')
        
        if not auth_header:
            return format_error_response(
                message="Authorization header is missing",
                code=401
            )
        
        # Check if the header has the correct format
        parts = auth_header.split()
        if len(parts) != 2 or parts[0].lower() != 'bearer':
            return format_error_response(
                message="Invalid Authorization header format",
                code=401,
                details={"format": "Bearer <token>"}
            )
        
        token = parts[1]
        
        # Decode and validate the token
        payload = decode_token(token)
        
        if 'error' in payload:
            return format_error_response(
                message=payload['error'],
                code=401
            )
        
        # Set user information in the request context
        g.user_id = payload['sub']
        g.is_admin = payload.get('admin', False)
        
        # Log the authenticated request
        current_app.logger.debug(f"Authenticated request from user {g.user_id}")
        
        return f(*args, **kwargs)
    
    return decorated


def admin_required(f: Callable) -> Callable:
    """
    Decorator to require admin privileges for an endpoint
    
    Args:
        f: The function to decorate
        
    Returns:
        The decorated function
    """
    @wraps(f)
    @token_required
    def decorated(*args, **kwargs):
        if not g.is_admin:
            return format_error_response(
                message="Admin privileges required",
                code=403
            )
        
        return f(*args, **kwargs)
    
    return decorated


def api_key_required(f: Callable) -> Callable:
    """
    Decorator to require a valid API key for an endpoint
    
    Args:
        f: The function to decorate
        
    Returns:
        The decorated function
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        # Check for API key in header or query parameter
        api_key = request.headers.get('X-API-Key') or request.args.get('api_key')
        
        # Check for JWT token in Authorization header
        auth_header = request.headers.get('Authorization')
        
        if api_key:
            # Validate API key
            user_info = validate_api_key(api_key)
            
            if not user_info:
                return format_error_response(
                    message="Invalid API key",
                    code=401
                )
            
            # Set user information in the request context
            g.user_id = user_info['user_id']
            g.is_admin = user_info['is_admin']
            g.permissions = user_info['permissions']
            
            # Log the authenticated request
            current_app.logger.debug(f"API key authenticated request from user {g.user_id}")
            
        elif auth_header:
            # Check if the header has the correct format
            parts = auth_header.split()
            if len(parts) != 2 or parts[0].lower() != 'bearer':
                return format_error_response(
                    message="Invalid Authorization header format",
                    code=401,
                    details={"format": "Bearer <token>"}
                )
            
            token = parts[1]
            
            # Decode and validate the token
            payload = decode_token(token)
            
            if 'error' in payload:
                return format_error_response(
                    message=payload['error'],
                    code=401
                )
            
            # Set user information in the request context
            g.user_id = payload['sub']
            g.is_admin = payload.get('admin', False)
            
            # Log the authenticated request
            current_app.logger.debug(f"JWT authenticated request from user {g.user_id}")
            
        else:
            return format_error_response(
                message="Authentication required",
                code=401,
                details={"methods": ["API key", "JWT token"]}
            )
        
        return f(*args, **kwargs)
    
    return decorated


def permission_required(permission: str) -> Callable:
    """
    Decorator to require a specific permission for an endpoint
    
    Args:
        permission: The required permission
        
    Returns:
        The decorated function
    """
    def decorator(f: Callable) -> Callable:
        @wraps(f)
        @api_key_required
        def decorated(*args, **kwargs):
            # Admin users have all permissions
            if g.is_admin:
                return f(*args, **kwargs)
            
            # Check if the user has the required permission
            if not hasattr(g, 'permissions') or permission not in g.permissions:
                return format_error_response(
                    message=f"Permission '{permission}' required",
                    code=403
                )
            
            return f(*args, **kwargs)
        
        return decorated
    
    return decorator


def rate_limit(limit: int, per: int = RATE_LIMIT_WINDOW) -> Callable:
    """
    Decorator to apply rate limiting to an endpoint
    
    Args:
        limit: Maximum number of requests allowed in the time window
        per: Time window in seconds
        
    Returns:
        The decorated function
    """
    def decorator(f: Callable) -> Callable:
        @wraps(f)
        def decorated(*args, **kwargs):
            # Get client IP address
            client_ip = get_client_ip()
            
            # In a real app, you'd use Redis or a similar store for rate limiting
            # For now, we'll use a mock implementation
            
            # Check if the client has exceeded the rate limit
            # This is a placeholder - in a real app, you'd implement proper rate limiting
            if client_ip == '127.0.0.1' and request.path == '/api/auth/login' and request.method == 'POST':
                # For testing rate limiting on login endpoint
                pass
            
            return f(*args, **kwargs)
        
        return decorated
    
    return decorator


def validate_csrf(f: Callable) -> Callable:
    """
    Decorator to validate CSRF token for an endpoint
    
    Args:
        f: The function to decorate
        
    Returns:
        The decorated function
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        # Skip CSRF validation for API key authenticated requests
        if request.headers.get('X-API-Key'):
            return f(*args, **kwargs)
        
        # Get CSRF token from request
        csrf_token = None
        
        if request.method == 'POST':
            # Check form data
            csrf_token = request.form.get('csrf_token')
            
            # Check JSON data if not in form
            if not csrf_token and request.is_json:
                csrf_token = request.json.get('csrf_token')
        
        # Check headers if not in form or JSON
        if not csrf_token:
            csrf_token = request.headers.get('X-CSRF-Token')
        
        # Validate CSRF token
        if not csrf_token or csrf_token != session.get('csrf_token'):
            return format_error_response(
                message="Invalid or missing CSRF token",
                code=403
            )
        
        return f(*args, **kwargs)
    
    return decorated
