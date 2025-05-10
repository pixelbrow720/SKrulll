"""
Search Engine Footprint module for the CyberOps Orchestrator.

This module provides functionality for analyzing a target's digital footprint
using search engines, Google dorks, and other search techniques.
"""
import datetime
import functools
import hashlib
import json
import logging
import os
import re
import time
import urllib.parse
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union

import requests
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

# Check if MongoDB is available for persistent history storage
try:
    import pymongo
    from pymongo import MongoClient
    MONGODB_AVAILABLE = True
    logger.info("MongoDB available for persistent history storage")
except ImportError:
    MONGODB_AVAILABLE = False
    logger.warning("MongoDB not installed, using in-memory history storage instead")

# Check if optional dependencies are available
try:
    from serpapi import GoogleSearch
    SERPAPI_AVAILABLE = True
except ImportError:
    logger.warning("serpapi not installed, Google search functionality will be limited")
    SERPAPI_AVAILABLE = False

# Try to import Redis for result caching
try:
    import redis
    REDIS_AVAILABLE = True
    logger.info("Redis available for API result caching")
except ImportError:
    REDIS_AVAILABLE = False
    logger.debug("Redis not available, using file-based caching instead")

# Configure module-level settings
CACHE_DIR = os.environ.get('CYBEROPS_SEARCH_CACHE_DIR', os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    'data', 'cache', 'search_footprint'
))

# Ensure cache directory exists
os.makedirs(CACHE_DIR, exist_ok=True)

# Cache TTL in seconds (default: 24 hours)
CACHE_TTL = int(os.environ.get('CYBEROPS_SEARCH_CACHE_TTL', '86400'))

# Rate limiting settings
RATE_LIMIT_REQUESTS = int(os.environ.get('CYBEROPS_SEARCH_RATE_LIMIT_REQUESTS', '10'))
RATE_LIMIT_PERIOD = int(os.environ.get('CYBEROPS_SEARCH_RATE_LIMIT_PERIOD', '60'))  # in seconds


class RateLimiter:
    """Rate limiter to prevent API throttling"""
    
    def __init__(self, max_requests: int, period: int):
        """
        Initialize rate limiter.
        
        Args:
            max_requests: Maximum number of requests allowed in the period
            period: Time period in seconds
        """
        self.max_requests = max_requests
        self.period = period
        self.request_timestamps = []
    
    def wait_if_needed(self):
        """
        Wait if rate limit would be exceeded.
        """
        now = time.time()
        
        # Remove timestamps older than the period
        self.request_timestamps = [ts for ts in self.request_timestamps if now - ts < self.period]
        
        # If we've reached the maximum requests in the period, wait
        if len(self.request_timestamps) >= self.max_requests:
            oldest = self.request_timestamps[0]
            wait_time = self.period - (now - oldest)
            
            if wait_time > 0:
                logger.info(f"Rate limit reached. Waiting {wait_time:.2f} seconds before next request")
                time.sleep(wait_time)
                # After waiting, the oldest timestamp is now outside the window
                self.request_timestamps.pop(0)
        
        # Add current timestamp
        self.request_timestamps.append(time.time())


def _get_cache_key(prefix: str, data: Any) -> str:
    """
    Generate a cache key for API results.
    
    Args:
        prefix: Key prefix
        data: Data to hash for the key
        
    Returns:
        Cache key string
    """
    # Convert data to a string and hash it
    data_str = json.dumps(data, sort_keys=True)
    hash_obj = hashlib.md5(data_str.encode())
    return f"{prefix}:{hash_obj.hexdigest()}"


def _get_cached_result(cache_key: str) -> Optional[Dict[str, Any]]:
    """
    Get cached API result if available.
    
    Args:
        cache_key: Cache key string
        
    Returns:
        Cached result or None if not found or expired
    """
    # Try Redis cache first if available
    if REDIS_AVAILABLE:
        try:
            redis_host = os.environ.get('REDIS_HOST', 'localhost')
            redis_port = int(os.environ.get('REDIS_PORT', 6379))
            redis_db = int(os.environ.get('REDIS_DB', 0))
            redis_password = os.environ.get('REDIS_PASSWORD', None)
            
            r = redis.Redis(
                host=redis_host,
                port=redis_port,
                db=redis_db,
                password=redis_password,
                decode_responses=False  # Keep as bytes for json.loads
            )
            
            cached_data = r.get(cache_key)
            if cached_data:
                logger.info(f"Using cached API result for {cache_key}")
                return json.loads(cached_data)
        except Exception as e:
            logger.warning(f"Error retrieving from Redis cache: {str(e)}")
    
    # Fall back to file-based cache
    cache_file = os.path.join(CACHE_DIR, f"{hashlib.md5(cache_key.encode()).hexdigest()}.json")
    if os.path.exists(cache_file):
        try:
            # Check if cache is still valid
            file_mtime = os.path.getmtime(cache_file)
            if (time.time() - file_mtime) < CACHE_TTL:
                with open(cache_file, 'r') as f:
                    logger.info(f"Using file-cached API result for {cache_key}")
                    return json.load(f)
            else:
                logger.debug(f"Cache expired for {cache_key}")
                os.remove(cache_file)  # Remove expired cache
        except Exception as e:
            logger.warning(f"Error reading cache file: {str(e)}")
    
    return None


def _cache_result(cache_key: str, result: Dict[str, Any]) -> None:
    """
    Cache API result.
    
    Args:
        cache_key: Cache key string
        result: API result to cache
    """
    # Try Redis cache first if available
    if REDIS_AVAILABLE:
        try:
            redis_host = os.environ.get('REDIS_HOST', 'localhost')
            redis_port = int(os.environ.get('REDIS_PORT', 6379))
            redis_db = int(os.environ.get('REDIS_DB', 0))
            redis_password = os.environ.get('REDIS_PASSWORD', None)
            
            r = redis.Redis(
                host=redis_host,
                port=redis_port,
                db=redis_db,
                password=redis_password
            )
            
            r.setex(
                cache_key,
                CACHE_TTL,
                json.dumps(result)
            )
            logger.debug(f"Cached API result in Redis for {cache_key} (TTL: {CACHE_TTL}s)")
        except Exception as e:
            logger.warning(f"Error caching result in Redis: {str(e)}")
    
    # Also cache to file as backup
    try:
        cache_file = os.path.join(CACHE_DIR, f"{hashlib.md5(cache_key.encode()).hexdigest()}.json")
        with open(cache_file, 'w') as f:
            json.dump(result, f)
        logger.debug(f"Cached API result to file: {cache_file}")
    except Exception as e:
        logger.warning(f"Error caching result to file: {str(e)}")


class SearchFootprint:
    """
    Analyzes a target's digital footprint using search engines.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the search footprint analyzer.
        
        Args:
            config: Configuration dictionary with API keys and settings
        """
        self.config = config or {}
        self.history = {}  # Fallback in-memory storage for historical search results
        
        # Initialize rate limiter
        self.rate_limiter = RateLimiter(
            max_requests=RATE_LIMIT_REQUESTS,
            period=RATE_LIMIT_PERIOD
        )
        
        # Initialize MongoDB connection if available
        self.mongodb_client = None
        self.history_collection = None
        
        if MONGODB_AVAILABLE:
            try:
                # Get MongoDB connection details from config or environment
                mongodb_uri = self.config.get('mongodb_uri', os.environ.get('MONGODB_URI', 'mongodb://localhost:27017'))
                mongodb_db = self.config.get('mongodb_db', os.environ.get('MONGODB_DB', 'cyberops'))
                
                # Connect to MongoDB
                self.mongodb_client = MongoClient(mongodb_uri)
                db = self.mongodb_client[mongodb_db]
                self.history_collection = db['search_history']
                
                # Create indexes for efficient querying
                self.history_collection.create_index([("target", pymongo.ASCENDING)])
                self.history_collection.create_index([("timestamp", pymongo.DESCENDING)])
                
                logger.info(f"Connected to MongoDB for persistent history storage: {mongodb_db}")
                
                # Set up TTL index to automatically expire old records (default: 90 days)
                history_ttl_days = int(self.config.get('history_ttl_days', os.environ.get('HISTORY_TTL_DAYS', '90')))
                self.history_collection.create_index(
                    [("timestamp", pymongo.ASCENDING)],
                    expireAfterSeconds=history_ttl_days * 24 * 60 * 60
                )
                logger.info(f"Set up TTL index for search history: {history_ttl_days} days")
                
            except Exception as e:
                logger.error(f"Failed to connect to MongoDB: {str(e)}")
                logger.warning("Falling back to in-memory history storage")
                self.mongodb_client = None
                self.history_collection = None
        
        logger.info("Search Footprint Analyzer initialized")
    
    def search_google_dorks(self, target: str, dork_types: List[str] = None, max_results: int = 20, use_cache: bool = True) -> Dict[str, Any]:
        """
        Search for a target using Google dorks.
        
        Args:
            target: Target domain or entity to search for
            dork_types: Types of dorks to use (files, exposures, subdomains, etc.)
            max_results: Maximum number of results to return
            use_cache: Whether to use cached results if available
        
        Returns:
            Dictionary containing search results
        """
        if not SERPAPI_AVAILABLE:
            return {
                "status": "error",
                "error": "SerpAPI not available, cannot perform Google dork search"
            }
        
        if "serpapi_key" not in self.config:
            return {
                "status": "error",
                "error": "SerpAPI key not configured, cannot perform Google dork search"
            }
        
        if dork_types is None:
            dork_types = ["files", "exposures", "subdomains", "technology", "credentials"]
        
        # Clean and normalize the target
        target = self._clean_domain(target)
        
        # Check cache if enabled
        if use_cache:
            cache_key = _get_cache_key(f"dorks:{target}", {
                "dork_types": sorted(dork_types),
                "max_results": max_results
            })
            cached_result = _get_cached_result(cache_key)
            if cached_result is not None:
                logger.info(f"Using cached Google dork results for {target}")
                return cached_result
        
        # Define Google dorks by type
        dorks = {
            "files": [
                f"site:{target} filetype:pdf",
                f"site:{target} filetype:doc OR filetype:docx",
                f"site:{target} filetype:xls OR filetype:xlsx",
                f"site:{target} filetype:ppt OR filetype:pptx",
                f"site:{target} filetype:txt",
                f"site:{target} filetype:log",
                f"site:{target} filetype:env OR filetype:cfg OR filetype:conf"
            ],
            "exposures": [
                f"site:{target} intext:password",
                f"site:{target} intext:username password",
                f"site:{target} inurl:login",
                f"site:{target} intext:\"index of /\"",
                f"site:{target} intitle:\"index of\" \"parent directory\"",
                f"site:{target} inurl:wp-content",
                f"site:{target} inurl:phpinfo"
            ],
            "subdomains": [
                f"site:*.{target}",
                f"site:*.*.{target}",
                f"site:*dev*.{target}",
                f"site:*test*.{target}",
                f"site:*stage*.{target}",
                f"site:*qa*.{target}",
                f"site:*admin*.{target}"
            ],
            "technology": [
                f"site:{target} inurl:wp-content",
                f"site:{target} inurl:joomla",
                f"site:{target} intext:\"powered by\"",
                f"site:{target} intext:\"error\"",
                f"site:{target} inurl:phpmyadmin",
                f"site:{target} inurl:cpanel",
                f"site:{target} inurl:admin"
            ],
            "credentials": [
                f"site:{target} intext:\"API_KEY\" OR intext:\"api key\"",
                f"site:{target} intext:\"password\" filetype:log",
                f"site:{target} intext:\"BEGIN RSA PRIVATE KEY\"",
                f"site:{target} intext:\"gmail.com\" intext:\"password\"",
                f"site:{target} intext:\"jdbc:mysql\"",
                f"site:{target} intext:\"SMTP\"",
                f"site:{target} intext:\"SECRET_KEY\""
            ]
        }
        
        # Initialize results structure
        results = {
            "target": target,
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "dork_types": dork_types,
            "dorks_used": [],
            "results_by_type": {},
            "total_results": 0,
            "status": "success"
        }
        
        total_queries = sum(len(dorks[dork_type]) for dork_type in dork_types if dork_type in dorks)
        results_count = 0
        
        # Execute searches for each dork type
        for dork_type in dork_types:
            if dork_type not in dorks:
                logger.warning(f"Dork type {dork_type} not recognized, skipping")
                continue
            
            dork_queries = dorks[dork_type]
            results["results_by_type"][dork_type] = []
            
            for query in dork_queries:
                # Don't exceed max_results
                if results_count >= max_results:
                    break
                
                results["dorks_used"].append(query)
                
                try:
                    # Check cache for this specific query
                    query_cache_key = _get_cache_key(f"query:{target}", {
                        "query": query,
                        "engine": "google",
                        "num": 10
                    })
                    
                    cached_query_result = None
                    if use_cache:
                        cached_query_result = _get_cached_result(query_cache_key)
                    
                    if cached_query_result is not None:
                        search_results = cached_query_result
                        logger.info(f"Using cached results for query: {query}")
                    else:
                        # Apply rate limiting before making the API call
                        self.rate_limiter.wait_if_needed()
                        
                        # Query Google via SerpAPI
                        search_params = {
                            "engine": "google",
                            "q": query,
                            "api_key": self.config["serpapi_key"],
                            "num": 10  # Results per page
                        }
                        
                        search = GoogleSearch(search_params)
                        search_results = search.get_dict()
                        
                        # Cache the results
                        if use_cache and "error" not in search_results:
                            _cache_result(query_cache_key, search_results)
                    
                    # Check for error
                    if "error" in search_results:
                        logger.error(f"SerpAPI error: {search_results['error']}")
                        continue
                    
                    # Process organic results
                    if "organic_results" in search_results:
                        for result in search_results["organic_results"]:
                            if results_count >= max_results:
                                break
                            
                            # Extract relevant fields
                            result_data = {
                                "title": result.get("title", "Untitled"),
                                "link": result.get("link", ""),
                                "snippet": result.get("snippet", ""),
                                "dork_type": dork_type,
                                "dork_query": query
                            }
                            
                            results["results_by_type"][dork_type].append(result_data)
                            results_count += 1
                    
                except Exception as e:
                    logger.error(f"Error executing dork query '{query}': {str(e)}")
                    continue
        
        results["total_results"] = results_count
        
        # Store in history for diff tracking
        self._store_in_history(target, results)
        
        # Cache the final results
        if use_cache:
            _cache_result(cache_key, results)
        
        return results
    
    def classify_exposed_files(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Classify exposed files found in search results.
        
        Args:
            results: Search results from search_google_dorks
            
        Returns:
            Dictionary with classification of exposed files
        """
        if results.get("status") != "success":
            return {
                "status": "error",
                "error": "Invalid search results"
            }
        
        classification = {
            "target": results.get("target", ""),
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "classifications": {
                "high_risk": [],
                "medium_risk": [],
                "low_risk": []
            },
            "summary": {
                "high_risk_count": 0,
                "medium_risk_count": 0,
                "low_risk_count": 0,
                "total_classified": 0
            },
            "status": "success"
        }
        
        # Risk classification patterns
        high_risk_patterns = [
            r"password", r"username", r"admin", r"config", r"backup",
            r"dump", r"private.*key", r"id_rsa", r"\.env", r"\.key",
            r"\.pem", r"\.ppk", r"database", r"creds", r"credentials",
            r"secret", r"token", r"auth", r"oauth", r"\.log$"
        ]
        
        medium_risk_patterns = [
            r"internal", r"staging", r"test", r"dev", r"uat",
            r"temp", r"users", r"staff", r"employee", r"finance",
            r"accounting", r"hr", r"resume", r"cv", r"personal"
        ]
        
        # Compile regex patterns
        high_risk_regex = re.compile("|".join(high_risk_patterns), re.IGNORECASE)
        medium_risk_regex = re.compile("|".join(medium_risk_patterns), re.IGNORECASE)
        
        # Process results for file types
        if "files" in results.get("results_by_type", {}):
            file_results = results["results_by_type"]["files"]
            
            for result in file_results:
                link = result.get("link", "")
                title = result.get("title", "")
                snippet = result.get("snippet", "")
                
                # Check for high risk patterns
                if high_risk_regex.search(link) or high_risk_regex.search(title) or high_risk_regex.search(snippet):
                    classification["classifications"]["high_risk"].append(result)
                    classification["summary"]["high_risk_count"] += 1
                
                # Check for medium risk patterns
                elif medium_risk_regex.search(link) or medium_risk_regex.search(title) or medium_risk_regex.search(snippet):
                    classification["classifications"]["medium_risk"].append(result)
                    classification["summary"]["medium_risk_count"] += 1
                
                # Everything else is low risk
                else:
                    classification["classifications"]["low_risk"].append(result)
                    classification["summary"]["low_risk_count"] += 1
                
                classification["summary"]["total_classified"] += 1
        
        # Process results for exposures
        if "exposures" in results.get("results_by_type", {}):
            exposure_results = results["results_by_type"]["exposures"]
            
            for result in exposure_results:
                link = result.get("link", "")
                title = result.get("title", "")
                snippet = result.get("snippet", "")
                
                # Exposures are generally high risk
                if high_risk_regex.search(link) or high_risk_regex.search(title) or high_risk_regex.search(snippet):
                    classification["classifications"]["high_risk"].append(result)
                    classification["summary"]["high_risk_count"] += 1
                else:
                    classification["classifications"]["medium_risk"].append(result)
                    classification["summary"]["medium_risk_count"] += 1
                
                classification["summary"]["total_classified"] += 1
        
        # Process credentials
        if "credentials" in results.get("results_by_type", {}):
            cred_results = results["results_by_type"]["credentials"]
            
            for result in cred_results:
                # All credential results are high risk
                classification["classifications"]["high_risk"].append(result)
                classification["summary"]["high_risk_count"] += 1
                classification["summary"]["total_classified"] += 1
        
        return classification
    
    def check_url_safety(self, urls: List[str]) -> Dict[str, Any]:
        """
        Check the safety of URLs found in search results.
        
        Args:
            urls: List of URLs to check
            
        Returns:
            Dictionary with safety check results
        """
        results = {
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "urls_checked": len(urls),
            "results": [],
            "summary": {
                "safe": 0,
                "suspicious": 0,
                "malicious": 0,
                "error": 0
            },
            "status": "success"
        }
        
        # Patterns for suspicious and malicious content
        suspicious_patterns = [
            r"login",
            r"password",
            r"credentials",
            r"admin",
            r"phpmyadmin",
            r"wp-admin",
            r"cpanel",
            r"config",
            r"\.env",
            r"\.git",
            r"\.svn",
            r"\.htaccess",
            r"error_log",
        ]
        
        malicious_patterns = [
            r"eval\(",
            r"base64_decode",
            r"exec\(",
            r"shell",
            r"hack",
            r"exploit",
            r"malware",
            r"trojan",
            r"phish",
            r"xss",
            r"csrf",
            r"sql\s*injection",
            r"attack"
        ]
        
        # Compile regex patterns
        suspicious_regex = re.compile("|".join(suspicious_patterns), re.IGNORECASE)
        malicious_regex = re.compile("|".join(malicious_patterns), re.IGNORECASE)
        
        for url in urls:
            result = {
                "url": url,
                "status": "safe",
                "checks": {
                    "suspicious_patterns": False,
                    "malicious_patterns": False,
                    "response_code": None,
                    "content_type": None
                },
                "details": []
            }
            
            # Check URL patterns
            if suspicious_regex.search(url):
                result["status"] = "suspicious"
                result["checks"]["suspicious_patterns"] = True
                result["details"].append("URL contains suspicious patterns")
            
            if malicious_regex.search(url):
                result["status"] = "malicious"
                result["checks"]["malicious_patterns"] = True
                result["details"].append("URL contains potentially malicious patterns")
            
            # Attempt to get headers (without downloading full content)
            try:
                headers = {
                    "User-Agent": "CyberOps OSINT Tool/1.0.0 (Security Check)"
                }
                
                response = requests.head(
                    url,
                    headers=headers,
                    timeout=5,
                    allow_redirects=True
                )
                
                result["checks"]["response_code"] = response.status_code
                result["checks"]["content_type"] = response.headers.get("Content-Type", "")
                
                # Check for suspicious server headers
                server = response.headers.get("Server", "")
                if any(term in server.lower() for term in ["older", "deprecated", "vulnerable"]):
                    result["status"] = "suspicious"
                    result["details"].append(f"Potentially vulnerable server: {server}")
                
            except Exception as e:
                result["status"] = "error"
                result["details"].append(f"Error checking URL: {str(e)}")
                results["summary"]["error"] += 1
                results["results"].append(result)
                continue
            
            # Update summary
            if result["status"] == "safe":
                results["summary"]["safe"] += 1
            elif result["status"] == "suspicious":
                results["summary"]["suspicious"] += 1
            elif result["status"] == "malicious":
                results["summary"]["malicious"] += 1
            
            results["results"].append(result)
        
        return results
    
    def track_changes(self, target: str, days_back: int = 30) -> Dict[str, Any]:
        """
        Track changes in search results over time.
        
        Args:
            target: Target to track changes for
            days_back: Number of days to look back for history
            
        Returns:
            Dictionary with change tracking results
        """
        # Clean and normalize the target
        target = self._clean_domain(target)
        
        # Get history entries from MongoDB if available
        history_entries = []
        
        if self.history_collection is not None:
            try:
                # Calculate the date to look back to
                look_back_date = datetime.datetime.utcnow() - datetime.timedelta(days=days_back)
                
                # Query MongoDB for history entries
                cursor = self.history_collection.find(
                    {
                        "target": target,
                        "timestamp": {"$gte": look_back_date}
                    },
                    sort=[("timestamp", pymongo.DESCENDING)],
                    limit=10  # Limit to most recent 10 entries
                )
                
                # Convert cursor to list
                history_entries = list(cursor)
                
                if len(history_entries) < 2:
                    logger.warning(f"Insufficient history in MongoDB for {target}, falling back to in-memory history")
                    history_entries = []
                
            except Exception as e:
                logger.error(f"Failed to retrieve history from MongoDB: {str(e)}")
                logger.warning("Falling back to in-memory history")
                history_entries = []
        
        # Fall back to in-memory history if needed
        if not history_entries:
            if target not in self.history or len(self.history[target]) < 2:
                return {
                    "status": "error",
                    "error": f"Insufficient history for {target} to track changes"
                }
            
            # Sort history by timestamp
            history_entries = sorted(
                self.history[target],
                key=lambda x: x["timestamp"]
            )
        
        # Get the latest two entries
        current = history_entries[0]  # Most recent (if from MongoDB)
        previous = history_entries[1]  # Second most recent
        
        # Convert MongoDB ObjectId to string if present
        if "_id" in current:
            current = {k: v for k, v in current.items() if k != "_id"}
        if "_id" in previous:
            previous = {k: v for k, v in previous.items() if k != "_id"}
        
        # Initialize results
        results = {
            "target": target,
            "current_timestamp": current["timestamp"],
            "previous_timestamp": previous["timestamp"],
            "changes": {
                "new_results": [],
                "removed_results": [],
                "changed_results": []
            },
            "summary": {
                "new_count": 0,
                "removed_count": 0,
                "changed_count": 0
            },
            "status": "success"
        }
        
        # Helper function to create result ID for comparison
        def get_result_id(result):
            return f"{result.get('link', '')}"
        
        # Create dictionaries for easy lookup
        current_results = {}
        previous_results = {}
        
        # Process current results
        for dork_type, type_results in current.get("results_by_type", {}).items():
            for result in type_results:
                result_id = get_result_id(result)
                if result_id:
                    current_results[result_id] = {
                        "result": result,
                        "dork_type": dork_type
                    }
        
        # Process previous results
        for dork_type, type_results in previous.get("results_by_type", {}).items():
            for result in type_results:
                result_id = get_result_id(result)
                if result_id:
                    previous_results[result_id] = {
                        "result": result,
                        "dork_type": dork_type
                    }
        
        # Find new results
        for result_id, result_data in current_results.items():
            if result_id not in previous_results:
                results["changes"]["new_results"].append({
                    "dork_type": result_data["dork_type"],
                    "result": result_data["result"]
                })
                results["summary"]["new_count"] += 1
        
        # Find removed results
        for result_id, result_data in previous_results.items():
            if result_id not in current_results:
                results["changes"]["removed_results"].append({
                    "dork_type": result_data["dork_type"],
                    "result": result_data["result"]
                })
                results["summary"]["removed_count"] += 1
        
        # Find changed results (same URL but different snippet/title)
        for result_id, current_data in current_results.items():
            if result_id in previous_results:
                current_result = current_data["result"]
                previous_result = previous_results[result_id]["result"]
                
                # Check if title or snippet changed
                if (current_result.get("title") != previous_result.get("title") or
                        current_result.get("snippet") != previous_result.get("snippet")):
                    results["changes"]["changed_results"].append({
                        "dork_type": current_data["dork_type"],
                        "current": current_result,
                        "previous": previous_result
                    })
                    results["summary"]["changed_count"] += 1
        
        return results
    
    def _clean_domain(self, domain: str) -> str:
        """
        Clean and normalize a domain name.
        
        Args:
            domain: Domain to clean
            
        Returns:
            Cleaned domain
        """
        # Remove protocol if present
        domain = re.sub(r'^https?://', '', domain)
        
        # Remove path, query, and fragment
        domain = domain.split('/')[0]
        
        # Remove www.
        domain = re.sub(r'^www\.', '', domain)
        
        return domain
    
    def _store_in_history(self, target: str, results: Dict[str, Any]) -> None:
        """
        Store search results in history for future diff tracking.
        
        Args:
            target: Target domain or entity
            results: Search results to store
        """
        # Create history entry
        history_entry = {
            "target": target,
            "timestamp": results["timestamp"],
            "total_results": results["total_results"],
            "results_by_type": results["results_by_type"]
        }
        
        # Store in MongoDB if available
        if self.history_collection is not None:
            try:
                # Convert string timestamp to datetime object for TTL index
                if isinstance(history_entry["timestamp"], str):
                    history_entry["timestamp"] = datetime.datetime.fromisoformat(history_entry["timestamp"])
                
                # Insert into MongoDB
                self.history_collection.insert_one(history_entry)
                logger.debug(f"Stored search results in MongoDB for target: {target}")
                
                # Clean up old entries (keep last 10)
                self._cleanup_old_entries(target, max_entries=10)
                
            except Exception as e:
                logger.error(f"Failed to store history in MongoDB: {str(e)}")
                logger.warning("Falling back to in-memory history storage")
                # Fall back to in-memory storage
                self._store_in_memory(target, history_entry)
        else:
            # Use in-memory storage
            self._store_in_memory(target, history_entry)
    
    def _store_in_memory(self, target: str, history_entry: Dict[str, Any]) -> None:
        """
        Store search results in memory (fallback method).
        
        Args:
            target: Target domain or entity
            history_entry: History entry to store
        """
        # Initialize target history if not exists
        if target not in self.history:
            self.history[target] = []
        
        # Add current results to history
        self.history[target].append(history_entry)
        
        # Keep only the last 5 entries to avoid excessive memory usage
        if len(self.history[target]) > 5:
            self.history[target] = self.history[target][-5:]
        
        logger.debug(f"Stored search results in memory for target: {target}")
    
    def _cleanup_old_entries(self, target: str, max_entries: int = 10) -> None:
        """
        Clean up old history entries for a target, keeping only the most recent ones.
        
        Args:
            target: Target domain or entity
            max_entries: Maximum number of entries to keep
        """
        if self.history_collection is None:
            return
        
        try:
            # Count entries for this target
            count = self.history_collection.count_documents({"target": target})
            
            if count > max_entries:
                # Find entries to delete (oldest first)
                entries_to_delete = count - max_entries
                
                # Get IDs of oldest entries
                oldest_entries = self.history_collection.find(
                    {"target": target},
                    sort=[("timestamp", pymongo.ASCENDING)],
                    limit=entries_to_delete
                )
                
                # Delete oldest entries
                ids_to_delete = [entry["_id"] for entry in oldest_entries]
                if ids_to_delete:
                    self.history_collection.delete_many({"_id": {"$in": ids_to_delete}})
                    logger.debug(f"Cleaned up {len(ids_to_delete)} old history entries for target: {target}")
        
        except Exception as e:
            logger.error(f"Failed to clean up old history entries: {str(e)}")
    
    def configure_alerts(self, target: str, alert_config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Configure alerts for new exposures.
        
        Args:
            target: Target to set up alerts for
            alert_config: Alert configuration
        
        Returns:
            Dictionary with alert configuration status
        """
        # Clean and normalize the target
        target = self._clean_domain(target)
        
        # Store config (in a real implementation, this would be persisted to a database)
        # This is just a mock implementation
        return {
            "target": target,
            "alert_config": alert_config,
            "status": "success",
            "message": f"Alerts configured for {target}"
        }


# Command-line utility for quick testing
if __name__ == "__main__":
    import argparse
    from dotenv import load_dotenv
    
    load_dotenv()
    
    parser = argparse.ArgumentParser(description="Search Engine Footprint Analyzer")
    parser.add_argument("domain", help="Domain to analyze")
    parser.add_argument("--dork-types", nargs="+", 
                      choices=["files", "exposures", "subdomains", "technology", "credentials"], 
                      default=["files", "exposures", "technology"],
                      help="Types of Google dorks to use")
    parser.add_argument("--max-results", type=int, default=20, help="Maximum number of results to return")
    parser.add_argument("--classify", action="store_true", help="Classify exposed files by risk level")
    parser.add_argument("--output", choices=["json", "pretty"], default="pretty", help="Output format")
    args = parser.parse_args()
    
    # Configure logging
    logging.basicConfig(level=logging.INFO)
    
    # Load configuration from environment variables
    config = {
        "serpapi_key": os.environ.get("SERPAPI_KEY")
    }
    
    if not config["serpapi_key"]:
        print("Warning: SERPAPI_KEY not found in environment variables")
        print("Google dork searches will not work without an API key")
    
    # Initialize analyzer
    analyzer = SearchFootprint(config)
    
    # Run search
    results = analyzer.search_google_dorks(
        args.domain,
        dork_types=args.dork_types,
        max_results=args.max_results
    )
    
    # Classify results if requested
    if args.classify and results["status"] == "success":
        classification = analyzer.classify_exposed_files(results)
        results["classification"] = classification
    
    # Output results
    if args.output == "json":
        print(json.dumps(results))
    else:
        print(json.dumps(results, indent=2))
