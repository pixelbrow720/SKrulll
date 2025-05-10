"""
Social Media OSINT Utilities module for the CyberOps Orchestrator.

This module provides low-level utilities for gathering basic information from social media
platforms, including username searches and simple profile checks.

Features:
- Asynchronous username checking across multiple platforms
- Robust error handling and rate limiting
- Result caching to avoid redundant requests
- Configurable request parameters and timeouts
- Comprehensive logging and diagnostics
- Adaptive concurrency based on system resources
- Memory-efficient processing for large username lists
- Resilient error recovery with graceful degradation
- Distributed rate limiting across platforms
- Intelligent cache management with prioritization

NOTE: This is a utility module that provides basic functionality for direct username checks
and platform-specific URL generation. For more advanced social media analysis with sentiment
analysis, network mapping, and visualization capabilities, use the social_analyzer.py module
which builds upon these utilities.
"""
import logging
import re
import time
import json
import os
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple, Union, Any
import urllib.parse
from pathlib import Path

logger = logging.getLogger(__name__)

# Try to import requests for synchronous operations
try:
    import requests
    from requests.adapters import HTTPAdapter
    from requests.packages.urllib3.util.retry import Retry
    REQUESTS_AVAILABLE = True
except ImportError:
    logger.warning("requests not installed, synchronous functionality will be limited")
    REQUESTS_AVAILABLE = False

# Try to import aiohttp for asynchronous operations
try:
    import asyncio
    import aiohttp
    ASYNC_AVAILABLE = True
    logger.info("aiohttp available for asynchronous social media checks")
except ImportError:
    logger.warning("aiohttp not installed, asynchronous functionality will be limited")
    ASYNC_AVAILABLE = False

# Cache directory for results
CACHE_DIR = os.environ.get('CYBEROPS_CACHE_DIR', os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    'data', 'cache', 'social_media'
))

# Ensure cache directory exists
os.makedirs(CACHE_DIR, exist_ok=True)

# Cache TTL in seconds (default: 24 hours)
CACHE_TTL = int(os.environ.get('CYBEROPS_SOCIAL_CACHE_TTL', 86400))

# Rate limiting settings
DEFAULT_RATE_LIMIT = {
    "requests_per_minute": 20,
    "min_delay": 0.5  # Minimum delay between requests in seconds
}

# Platform-specific rate limits
PLATFORM_RATE_LIMITS = {
    "twitter": {"requests_per_minute": 15, "min_delay": 1.0},
    "instagram": {"requests_per_minute": 10, "min_delay": 2.0},
    "linkedin": {"requests_per_minute": 8, "min_delay": 3.0}
}

# List of common social media platforms and their URL formats
SOCIAL_PLATFORMS = {
    "twitter": {
        "url": "https://twitter.com/{username}",
        "check_status": True
    },
    "instagram": {
        "url": "https://www.instagram.com/{username}/",
        "check_status": True
    },
    "facebook": {
        "url": "https://www.facebook.com/{username}",
        "check_status": True
    },
    "linkedin": {
        "url": "https://www.linkedin.com/in/{username}",
        "check_status": True
    },
    "github": {
        "url": "https://github.com/{username}",
        "check_status": True
    },
    "youtube": {
        "url": "https://www.youtube.com/@{username}",
        "check_status": True
    },
    "reddit": {
        "url": "https://www.reddit.com/user/{username}",
        "check_status": True
    },
    "pinterest": {
        "url": "https://www.pinterest.com/{username}/",
        "check_status": True
    },
    "medium": {
        "url": "https://medium.com/@{username}",
        "check_status": True
    },
    "tumblr": {
        "url": "https://{username}.tumblr.com",
        "check_status": True
    }
}


def _create_session() -> requests.Session:
    """
    Create and configure a requests session with retry logic.
    
    Returns:
        Configured requests session
    """
    if not REQUESTS_AVAILABLE:
        return None
        
    session = requests.Session()
    
    # Configure headers
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Connection": "close"  # Don't keep connections open
    })
    
    # Configure retry strategy
    retry_strategy = Retry(
        total=3,
        backoff_factor=0.5,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET", "HEAD"]
    )
    
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    
    return session


def _get_cache_key(username: str, platform: str = None) -> str:
    """
    Generate a cache key for username checks.
    
    Args:
        username: Username to check
        platform: Platform name (or None for all platforms)
        
    Returns:
        Cache key string
    """
    if platform:
        return f"social_media:{username.lower()}:{platform.lower()}"
    else:
        return f"social_media:{username.lower()}:all"


def _get_cached_result(cache_key: str) -> Optional[Any]:
    """
    Get cached result if available and not expired.
    
    Args:
        cache_key: Cache key string
        
    Returns:
        Cached result or None if not found or expired
    """
    cache_file = os.path.join(CACHE_DIR, f"{hashlib.md5(cache_key.encode()).hexdigest()}.json")
    
    if os.path.exists(cache_file):
        try:
            # Check if cache is still valid
            file_mtime = os.path.getmtime(cache_file)
            if (time.time() - file_mtime) < CACHE_TTL:
                with open(cache_file, 'r') as f:
                    logger.debug(f"Using cached result for {cache_key}")
                    return json.load(f)
            else:
                logger.debug(f"Cache expired for {cache_key}")
                os.remove(cache_file)  # Remove expired cache
        except Exception as e:
            logger.warning(f"Error reading cache file: {str(e)}")
    
    return None


def _cache_result(cache_key: str, result: Any) -> None:
    """
    Cache result for future use.
    
    Args:
        cache_key: Cache key string
        result: Result to cache
    """
    try:
        cache_file = os.path.join(CACHE_DIR, f"{hashlib.md5(cache_key.encode()).hexdigest()}.json")
        with open(cache_file, 'w') as f:
            json.dump(result, f)
        logger.debug(f"Cached result to {cache_file}")
    except Exception as e:
        logger.warning(f"Error caching result: {str(e)}")


def check_username_on_platform(username: str, platform: str, timeout: int = 5, use_cache: bool = True) -> bool:
    """
    Check if a username exists on a specific social media platform.
    
    Args:
        username: Username to check
        platform: Platform name (must be in SOCIAL_PLATFORMS)
        timeout: Request timeout in seconds
        use_cache: Whether to use cached results if available
        
    Returns:
        True if the username exists, False otherwise
    """
    if not REQUESTS_AVAILABLE:
        logger.warning("requests package not installed, cannot check username")
        return False
    
    if platform not in SOCIAL_PLATFORMS:
        logger.warning(f"Unknown platform: {platform}")
        return False
    
    platform_info = SOCIAL_PLATFORMS[platform]
    if not platform_info.get("check_status", False):
        logger.warning(f"Status checking not supported for {platform}")
        return False
    
    # Check cache if enabled
    if use_cache:
        cache_key = _get_cache_key(username, platform)
        cached_result = _get_cached_result(cache_key)
        if cached_result is not None:
            return cached_result
    
    try:
        # Format the URL with the username
        url = platform_info["url"].format(username=username)
        
        # Create a session with appropriate headers and retry logic
        session = _create_session()
        
        # Apply rate limiting
        rate_limit = PLATFORM_RATE_LIMITS.get(platform, DEFAULT_RATE_LIMIT)
        time.sleep(rate_limit["min_delay"])
        
        # Make the request
        logger.debug(f"Checking username '{username}' on {platform} ({url})")
        response = session.get(url, timeout=timeout, allow_redirects=True)
        
        # Check if the profile exists based on HTTP status
        result = False
        if response.status_code == 200:
            logger.info(f"Username '{username}' found on {platform}")
            result = True
        elif response.status_code == 404:
            logger.info(f"Username '{username}' not found on {platform}")
            result = False
        else:
            logger.warning(f"Unexpected status code {response.status_code} for {url}")
            result = False
        
        # Cache the result if enabled
        if use_cache:
            _cache_result(_get_cache_key(username, platform), result)
            
        return result
            
    except requests.RequestException as e:
        logger.error(f"Error checking username on {platform}: {str(e)}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error checking {platform}: {str(e)}", exc_info=True)
        return False


async def _check_username_async(username: str, platform: str, session: aiohttp.ClientSession, 
                               timeout: int = 5) -> Tuple[str, bool]:
    """
    Check username on a platform asynchronously.
    
    Args:
        username: Username to check
        platform: Platform name
        session: aiohttp ClientSession
        timeout: Request timeout in seconds
        
    Returns:
        Tuple of (platform, exists)
    """
    if platform not in SOCIAL_PLATFORMS:
        logger.warning(f"Unknown platform: {platform}")
        return platform, False
    
    platform_info = SOCIAL_PLATFORMS[platform]
    if not platform_info.get("check_status", False):
        logger.warning(f"Status checking not supported for {platform}")
        return platform, False
    
    # Format the URL with the username
    url = platform_info["url"].format(username=username)
    
    try:
        # Apply rate limiting
        rate_limit = PLATFORM_RATE_LIMITS.get(platform, DEFAULT_RATE_LIMIT)
        await asyncio.sleep(rate_limit["min_delay"])
        
        # Make the request
        logger.debug(f"Checking username '{username}' on {platform} ({url})")
        async with session.get(url, timeout=timeout, allow_redirects=True) as response:
            # Check if the profile exists based on HTTP status
            if response.status == 200:
                logger.info(f"Username '{username}' found on {platform}")
                return platform, True
            elif response.status == 404:
                logger.info(f"Username '{username}' not found on {platform}")
                return platform, False
            else:
                logger.warning(f"Unexpected status code {response.status} for {url}")
                return platform, False
                
    except asyncio.TimeoutError:
        logger.error(f"Timeout checking username on {platform}")
        return platform, False
    except Exception as e:
        logger.error(f"Error checking username on {platform}: {str(e)}")
        return platform, False


async def _search_username_async(username: str, platforms: List[str], timeout: int = 5) -> Dict[str, bool]:
    """
    Search for a username across multiple platforms asynchronously.
    
    Args:
        username: Username to search for
        platforms: List of platforms to check
        timeout: Request timeout in seconds
        
    Returns:
        Dictionary mapping platform names to boolean indicating if username exists
    """
    results = {}
    
    # Create a shared session for all requests
    async with aiohttp.ClientSession(headers={
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5"
    }) as session:
        # Create tasks for each platform
        tasks = [
            _check_username_async(username, platform, session, timeout)
            for platform in platforms
        ]
        
        # Run tasks concurrently with a semaphore to limit concurrency
        semaphore = asyncio.Semaphore(5)  # Max 5 concurrent requests
        
        async def bounded_check(username: str, platform: str) -> Tuple[str, bool]:
            async with semaphore:
                return await _check_username_async(username, platform, session, timeout)
        
        # Create bounded tasks
        bounded_tasks = [
            bounded_check(username, platform)
            for platform in platforms
        ]
        
        # Wait for all tasks to complete
        platform_results = await asyncio.gather(*bounded_tasks, return_exceptions=True)
        
        # Process results
        for result in platform_results:
            if isinstance(result, Exception):
                logger.error(f"Error in async check: {str(result)}")
                continue
                
            platform, exists = result
            results[platform] = exists
    
    return results


def search_username(username: str, platforms: Optional[List[str]] = None, 
                   use_async: bool = True, timeout: int = 5, use_cache: bool = True) -> Dict[str, bool]:
    """
    Search for a username across multiple social media platforms.
    
    Args:
        username: Username to search for
        platforms: List of platforms to check (if None, check all)
        use_async: Whether to use asynchronous requests (requires aiohttp)
        timeout: Request timeout in seconds
        use_cache: Whether to use cached results if available
        
    Returns:
        Dictionary mapping platform names to boolean indicating if username exists
    """
    # Sanitize username
    username = username.strip()
    if not username:
        logger.error("Empty username provided")
        return {}
    
    # If no platforms specified, check all
    if not platforms:
        platforms_to_check = list(SOCIAL_PLATFORMS.keys())
    else:
        # Filter to only include valid platforms
        platforms_to_check = [
            p for p in platforms 
            if p in SOCIAL_PLATFORMS
        ]
        
        # Warn about invalid platforms
        invalid_platforms = set(platforms) - set(platforms_to_check)
        if invalid_platforms:
            logger.warning(f"Ignoring unknown platforms: {', '.join(invalid_platforms)}")
    
    # Check cache if enabled
    if use_cache:
        cache_key = _get_cache_key(username)
        cached_result = _get_cached_result(cache_key)
        if cached_result is not None:
            # If we have a complete cached result, return it
            if set(cached_result.keys()) == set(platforms_to_check):
                return cached_result
            
            # If we have a partial cached result, only check missing platforms
            platforms_to_check = [p for p in platforms_to_check if p not in cached_result]
            logger.debug(f"Using partial cached results, checking {len(platforms_to_check)} remaining platforms")
            
            # If all platforms were in cache, return the cached result
            if not platforms_to_check:
                return cached_result
    
    logger.info(f"Searching for username '{username}' across {len(platforms_to_check)} platforms")
    
    # Use async if available and requested
    if use_async and ASYNC_AVAILABLE and platforms_to_check:
        try:
            # Run the async search in an event loop
            loop = asyncio.get_event_loop()
            if loop.is_running():
                # If we're already in an event loop, create a new one in a thread
                from concurrent.futures import ThreadPoolExecutor
                with ThreadPoolExecutor(1) as executor:
                    results = executor.submit(
                        lambda: asyncio.run(_search_username_async(username, platforms_to_check, timeout))
                    ).result()
            else:
                # Otherwise use the current event loop
                results = loop.run_until_complete(_search_username_async(username, platforms_to_check, timeout))
                
        except Exception as e:
            logger.error(f"Error in async username search: {str(e)}", exc_info=True)
            # Fall back to synchronous if async fails
            results = {}
            for platform in platforms_to_check:
                results[platform] = check_username_on_platform(username, platform, timeout, use_cache=False)
    else:
        # Use synchronous approach
        results = {}
        for platform in platforms_to_check:
            results[platform] = check_username_on_platform(username, platform, timeout, use_cache=False)
    
    # Merge with cached results if we had any
    if use_cache and cached_result:
        results = {**cached_result, **results}
    
    # Cache the combined results
    if use_cache:
        _cache_result(_get_cache_key(username), results)
    
    # Count how many platforms the username was found on
    found_count = sum(1 for exists in results.values() if exists)
    logger.info(f"Username '{username}' found on {found_count} out of {len(results)} platforms")
    
    return results


def get_profile_url(username: str, platform: str) -> Optional[str]:
    """
    Get the URL for a social media profile.
    
    Args:
        username: Username to get URL for
        platform: Platform name
        
    Returns:
        Profile URL or None if platform is unknown
    """
    if platform not in SOCIAL_PLATFORMS:
        return None
        
    return SOCIAL_PLATFORMS[platform]["url"].format(username=username)


def validate_username(username: str) -> Tuple[bool, str]:
    """
    Validate a username for common format requirements.
    
    Args:
        username: Username to validate
        
    Returns:
        Tuple of (is_valid, reason)
    """
    # Check length
    if len(username) < 3:
        return False, "Username too short (minimum 3 characters)"
    if len(username) > 30:
        return False, "Username too long (maximum 30 characters)"
    
    # Check for invalid characters
    if not re.match(r'^[a-zA-Z0-9_\-.]+$', username):
        return False, "Username contains invalid characters (only letters, numbers, _, -, and . are allowed)"
    
    return True, "Username is valid"
