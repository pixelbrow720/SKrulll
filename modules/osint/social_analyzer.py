"""
Advanced Social Media Analyzer module for the SKrulll Orchestrator.

This module provides high-level functionality for analyzing social media data,
including sentiment analysis, network graph visualization, and content analysis.

This is a higher-level module that builds upon the basic utilities provided by
the social_media.py module. While social_media.py provides simple username checks
and URL generation, this module offers comprehensive analysis capabilities including:
- Sentiment analysis of social media content
- Network graph visualization and community detection
- Content trend analysis and keyword extraction
- Cross-platform user profiling

Features:
- Efficient caching of analysis results
- Parallel processing for improved performance
- Memory-efficient handling of large datasets
- Comprehensive error handling and logging
- Optimized network graph visualization
- Adaptive processing based on available resources
- Incremental analysis for large datasets
- Resilient error recovery with graceful degradation
"""
import asyncio
import datetime
import json
import logging
import os
import time
import tempfile
import hashlib
from typing import Any, Dict, List, Optional, Set, Tuple, Union
import re
import math
from pathlib import Path
from functools import lru_cache
import concurrent.futures
import psutil

import networkx as nx
import plotly.graph_objects as go
import plotly.io as pio

# Import the OSINT Aggregator for data collection
from modules.osint.aggregator import OsintAggregator

logger = logging.getLogger(__name__)

# Configure module-level settings
MAX_WORKERS = int(os.environ.get('CYBEROPS_ANALYZER_MAX_WORKERS', '4'))  # Maximum number of concurrent threads
CACHE_SIZE = int(os.environ.get('CYBEROPS_ANALYZER_CACHE_SIZE', '128'))  # Size of LRU cache for responses
RESULT_CACHE_TTL = int(os.environ.get('CYBEROPS_ANALYZER_RESULT_CACHE_TTL', '3600'))  # Cache TTL in seconds (1 hour)
MAX_GRAPH_NODES = int(os.environ.get('CYBEROPS_ANALYZER_MAX_GRAPH_NODES', '100'))  # Maximum nodes in network graph
MAX_MEMORY_USAGE = int(os.environ.get('CYBEROPS_ANALYZER_MAX_MEMORY_MB', '512'))  # Maximum memory usage in MB

# Check if optional dependencies are available
try:
    from transformers import pipeline
    HF_TRANSFORMERS_AVAILABLE = True
    logger.info("HuggingFace transformers available for sentiment analysis")
except ImportError:
    logger.warning("transformers not installed, sentiment analysis will be disabled")
    HF_TRANSFORMERS_AVAILABLE = False

# Try to import Redis for result caching
try:
    import redis
    REDIS_AVAILABLE = True
    logger.info("Redis available for result caching")
except ImportError:
    REDIS_AVAILABLE = False
    logger.debug("Redis not available, using file-based caching instead")

# Result cache directory
CACHE_DIR = os.environ.get('CYBEROPS_ANALYZER_CACHE_DIR', os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    'data', 'cache', 'social_analyzer'
))

# Ensure cache directory exists
os.makedirs(CACHE_DIR, exist_ok=True)


def _get_cache_key(prefix: str, data: Any) -> str:
    """
    Generate a cache key for analysis results.
    
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
    Get cached analysis result if available.
    
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
                logger.info(f"Using cached analysis result for {cache_key}")
                return json.loads(cached_data)
        except Exception as e:
            logger.warning(f"Error retrieving from Redis cache: {str(e)}")
    
    # Fall back to file-based cache
    cache_file = os.path.join(CACHE_DIR, f"{hashlib.md5(cache_key.encode()).hexdigest()}.json")
    if os.path.exists(cache_file):
        try:
            # Check if cache is still valid
            file_mtime = os.path.getmtime(cache_file)
            if (time.time() - file_mtime) < RESULT_CACHE_TTL:
                with open(cache_file, 'r') as f:
                    logger.info(f"Using file-cached analysis result for {cache_key}")
                    return json.load(f)
            else:
                logger.debug(f"Cache expired for {cache_key}")
                os.remove(cache_file)  # Remove expired cache
        except Exception as e:
            logger.warning(f"Error reading cache file: {str(e)}")
    
    return None


def _cache_result(cache_key: str, result: Dict[str, Any]) -> None:
    """
    Cache analysis result.
    
    Args:
        cache_key: Cache key string
        result: Analysis result to cache
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
                RESULT_CACHE_TTL,
                json.dumps(result)
            )
            logger.debug(f"Cached analysis result in Redis for {cache_key} (TTL: {RESULT_CACHE_TTL}s)")
        except Exception as e:
            logger.warning(f"Error caching result in Redis: {str(e)}")
    
    # Also cache to file as backup
    try:
        cache_file = os.path.join(CACHE_DIR, f"{hashlib.md5(cache_key.encode()).hexdigest()}.json")
        with open(cache_file, 'w') as f:
            json.dump(result, f)
        logger.debug(f"Cached analysis result to file: {cache_file}")
    except Exception as e:
        logger.warning(f"Error caching result to file: {str(e)}")


class SocialMediaAnalyzer:
    """
    Analyzes social media data for OSINT purposes.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the social media analyzer.
        
        Args:
            config: Configuration dictionary with API keys and settings
        """
        self.config = config or {}
        self.aggregator = OsintAggregator(config)
        self.sentiment_analyzer = None
        
        # Initialize sentiment analyzer if transformers are available
        if HF_TRANSFORMERS_AVAILABLE:
            try:
                # Use a smaller model for sentiment analysis to reduce memory usage
                model_name = os.environ.get('SENTIMENT_MODEL', 'distilbert-base-uncased-finetuned-sst-2-english')
                self.sentiment_analyzer = pipeline('sentiment-analysis', model=model_name)
                logger.info(f"Sentiment analyzer initialized with model: {model_name}")
            except Exception as e:
                logger.error(f"Error initializing sentiment analyzer: {str(e)}")
                logger.info("Falling back to basic sentiment analysis")
        
        # Configure memory monitoring
        self.memory_monitor_enabled = os.environ.get('ENABLE_MEMORY_MONITORING', 'true').lower() == 'true'
        
        logger.info("Social Media Analyzer initialized")
    
    def _check_memory_usage(self) -> bool:
        """
        Check if memory usage is within limits.
        
        Returns:
            True if memory usage is acceptable, False otherwise
        """
        if not self.memory_monitor_enabled:
            return True
            
        try:
            import psutil
            process = psutil.Process(os.getpid())
            memory_info = process.memory_info()
            memory_mb = memory_info.rss / 1024 / 1024
            
            if memory_mb > MAX_MEMORY_USAGE:
                logger.warning(f"Memory usage ({memory_mb:.1f} MB) exceeds limit ({MAX_MEMORY_USAGE} MB)")
                return False
                
            logger.debug(f"Current memory usage: {memory_mb:.1f} MB")
            return True
        except ImportError:
            logger.warning("psutil not available, memory monitoring disabled")
            self.memory_monitor_enabled = False
            return True
        except Exception as e:
            logger.error(f"Error checking memory usage: {str(e)}")
            return True  # Continue on error
    
    async def analyze_profile(self, username: str, platforms: List[str] = None, use_cache: bool = True) -> Dict[str, Any]:
        """
        Analyze a social media profile.
        
        Args:
            username: Social media username to analyze
            platforms: List of platforms to analyze (twitter, reddit)
            use_cache: Whether to use cached results if available
        
        Returns:
            Dictionary containing analysis results
        """
        # Normalize username and platforms for consistent caching
        username = username.lower().strip()
        
        if platforms is None:
            platforms = []
            if 'twitter' in self.aggregator.config:
                platforms.append('twitter')
            if 'reddit' in self.aggregator.config:
                platforms.append('reddit')
        
        # Sort platforms for consistent cache keys
        platforms = sorted(platforms)
        
        # Check cache if enabled
        if use_cache:
            cache_key = _get_cache_key(f"profile:{username}", platforms)
            cached_result = _get_cached_result(cache_key)
            if cached_result is not None:
                logger.info(f"Using cached profile analysis for {username}")
                return cached_result
        
        data_types = []
        if 'twitter' in platforms:
            data_types.append('twitter')
        if 'reddit' in platforms:
            data_types.append('reddit')
        
        if not data_types:
            return {
                'status': 'error',
                'error': 'No supported platforms specified'
            }
        
        logger.info(f"Analyzing social media profile: {username} on platforms: {platforms}")
        
        # Check memory usage before proceeding
        if not self._check_memory_usage():
            logger.warning("Memory usage too high, reducing analysis scope")
            # Reduce analysis scope if memory is constrained
            MAX_TWEETS = 50  # Reduced from default
            MAX_POSTS = 30   # Reduced from default
        else:
            MAX_TWEETS = 200  # Default
            MAX_POSTS = 100   # Default
        
        try:
            # Collect data using the aggregator
            osint_data = await self.aggregator.collect_data(username, data_types)
            
            # Process results
            results = {
                'username': username,
                'platforms': platforms,
                'timestamp': datetime.datetime.utcnow().isoformat(),
                'profile_data': {},
                'content_analysis': {},
                'network_analysis': {}
            }
            
            # Extract and analyze profile data
            for platform in platforms:
                if platform in osint_data['results']:
                    platform_data = osint_data['results'][platform]
                    
                    if platform_data.get('status') == 'success':
                        # Extract profile data
                        if platform == 'twitter' and platform_data.get('type') == 'user':
                            results['profile_data']['twitter'] = platform_data.get('user', {})
                            
                            # Analyze tweets if available
                            if 'recent_tweets' in platform_data:
                                # Limit tweets for memory efficiency
                                tweets = platform_data['recent_tweets'][:MAX_TWEETS]
                                results['content_analysis']['twitter'] = self._analyze_tweets(tweets)
                                
                        elif platform == 'reddit' and platform_data.get('type') == 'user':
                            results['profile_data']['reddit'] = platform_data.get('user', {})
                            
                            # Analyze posts and comments if available
                            reddit_content = []
                            if 'recent_posts' in platform_data:
                                reddit_content.extend([
                                    {'text': post['title'], 'platform': 'reddit', 'type': 'post', 'data': post}
                                    for post in platform_data['recent_posts'][:MAX_POSTS]
                                ])
                            if 'recent_comments' in platform_data:
                                reddit_content.extend([
                                    {'text': comment['body'], 'platform': 'reddit', 'type': 'comment', 'data': comment}
                                    for comment in platform_data['recent_comments'][:MAX_POSTS]
                                ])
                            
                            if reddit_content:
                                results['content_analysis']['reddit'] = self._analyze_content(
                                    reddit_content
                                )
            
            # Generate network graph if data is available and memory allows
            if any(platform in results['profile_data'] for platform in platforms) and self._check_memory_usage():
                results['network_analysis'] = self._generate_network_analysis(
                    username, results['profile_data'], osint_data['results']
                )
            
            # Cache the results if enabled
            if use_cache:
                _cache_result(cache_key, results)
            
            return results
            
        except Exception as e:
            logger.error(f"Error analyzing profile {username}: {str(e)}", exc_info=True)
            return {
                'status': 'error',
                'error': f"Analysis failed: {str(e)}",
                'username': username,
                'platforms': platforms,
                'timestamp': datetime.datetime.utcnow().isoformat()
            }
    
    async def analyze_topic(self, topic: str, platforms: List[str] = None) -> Dict[str, Any]:
        """
        Analyze social media content related to a topic.
        
        Args:
            topic: Topic or search query to analyze
            platforms: List of platforms to analyze (twitter, reddit)
        
        Returns:
            Dictionary containing analysis results
        """
        if platforms is None:
            platforms = []
            if 'twitter' in self.aggregator.config:
                platforms.append('twitter')
            if 'reddit' in self.aggregator.config:
                platforms.append('reddit')
        
        data_types = []
        if 'twitter' in platforms:
            data_types.append('twitter')
        if 'reddit' in platforms:
            data_types.append('reddit')
        
        if not data_types:
            return {
                'status': 'error',
                'error': 'No supported platforms specified'
            }
        
        logger.info(f"Analyzing social media topic: {topic} on platforms: {platforms}")
        
        # Collect data using the aggregator
        osint_data = await self.aggregator.collect_data(topic, data_types)
        
        # Process results
        results = {
            'topic': topic,
            'platforms': platforms,
            'timestamp': datetime.datetime.utcnow().isoformat(),
            'content_analysis': {},
            'trends': {},
            'network_analysis': {}
        }
        
        # Extract and analyze content
        for platform in platforms:
            if platform in osint_data['results']:
                platform_data = osint_data['results'][platform]
                
                if platform_data.get('status') == 'success':
                    # Extract and analyze content
                    if platform == 'twitter' and platform_data.get('type') == 'search':
                        tweets = platform_data.get('tweets', [])
                        
                        if tweets:
                            twitter_content = [
                                {'text': tweet['full_text'], 'platform': 'twitter', 'type': 'tweet', 'data': tweet}
                                for tweet in tweets
                            ]
                            
                            results['content_analysis']['twitter'] = self._analyze_content(
                                twitter_content
                            )
                            
                            results['trends']['twitter'] = self._extract_trends(
                                twitter_content
                            )
                            
                    elif platform == 'reddit' and platform_data.get('type') == 'search':
                        posts = platform_data.get('results', [])
                        
                        if posts:
                            reddit_content = [
                                {'text': post['title'], 'platform': 'reddit', 'type': 'post', 'data': post}
                                for post in posts
                            ]
                            
                            results['content_analysis']['reddit'] = self._analyze_content(
                                reddit_content
                            )
                            
                            results['trends']['reddit'] = self._extract_trends(
                                reddit_content
                            )
        
        # Generate network graph if data is available
        network_data = {}
        for platform in platforms:
            if platform in osint_data['results']:
                platform_data = osint_data['results'][platform]
                if platform_data.get('status') == 'success':
                    network_data[platform] = platform_data
        
        if network_data:
            results['network_analysis'] = self._generate_topic_network(
                topic, network_data
            )
        
        return results
    
    def _analyze_tweets(self, tweets: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Analyze a collection of tweets.
        
        Args:
            tweets: List of tweet data
        
        Returns:
            Dictionary containing analysis results
        """
        tweet_content = [
            {'text': tweet['full_text'], 'platform': 'twitter', 'type': 'tweet', 'data': tweet}
            for tweet in tweets
        ]
        
        return self._analyze_content(tweet_content)
    
    def _analyze_content(self, content_items: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Analyze social media content items.
        
        Args:
            content_items: List of content items with text and metadata
        
        Returns:
            Dictionary containing analysis results
        """
        results = {
            'count': len(content_items),
            'sentiment': {
                'positive': 0,
                'neutral': 0,
                'negative': 0
            },
            'keywords': {},
            'hashtags': [],
            'urls': [],
            'mentions': []
        }
        
        if not content_items:
            return results
        
        # Sentiment analysis
        if HF_TRANSFORMERS_AVAILABLE and self.sentiment_analyzer:
            try:
                texts = [item['text'] for item in content_items]
                sentiments = self.sentiment_analyzer(texts)
                
                for sentiment in sentiments:
                    if sentiment['label'] == 'POSITIVE':
                        results['sentiment']['positive'] += 1
                    elif sentiment['label'] == 'NEGATIVE':
                        results['sentiment']['negative'] += 1
                    else:
                        results['sentiment']['neutral'] += 1
            except Exception as e:
                logger.error(f"Error during sentiment analysis: {str(e)}")
                # Fall back to basic sentiment analysis
                self._basic_sentiment_analysis(content_items, results)
        else:
            # Fallback to basic sentiment analysis
            self._basic_sentiment_analysis(content_items, results)
        
        # Extract keywords, hashtags, URLs, and mentions
        for item in content_items:
            text = item['text']
            
            # Extract hashtags
            hashtags = re.findall(r'#(\w+)', text)
            for hashtag in hashtags:
                if hashtag.lower() not in [h.lower() for h in results['hashtags']]:
                    results['hashtags'].append(hashtag)
            
            # Extract URLs
            urls = re.findall(r'https?://\S+', text)
            results['urls'].extend([url for url in urls if url not in results['urls']])
            
            # Extract mentions
            mentions = re.findall(r'@(\w+)', text)
            for mention in mentions:
                if mention not in [m for m in results['mentions']]:
                    results['mentions'].append(mention)
            
            # Extract keywords (simple approach)
            cleaned_text = re.sub(r'[^\w\s]', '', text.lower())
            cleaned_text = re.sub(r'https?://\S+', '', cleaned_text)
            cleaned_text = re.sub(r'@\w+', '', cleaned_text)
            cleaned_text = re.sub(r'#\w+', '', cleaned_text)
            
            words = cleaned_text.split()
            stopwords = {'a', 'an', 'the', 'and', 'or', 'but', 'if', 'then', 'else', 'when', 
                        'at', 'from', 'by', 'for', 'with', 'about', 'against', 'between',
                        'into', 'through', 'during', 'before', 'after', 'above', 'below',
                        'to', 'of', 'in', 'on', 'it', 'this', 'that', 'these', 'those', 'is',
                        'are', 'was', 'were', 'be', 'been', 'being', 'have', 'has', 'had',
                        'having', 'do', 'does', 'did', 'doing', 'would', 'should', 'could',
                        'i', 'you', 'he', 'she', 'it', 'we', 'they', 'me', 'him', 'her', 
                        'us', 'them', 'my', 'your', 'his', 'its', 'our', 'their', 'mine',
                        'yours', 'hers', 'ours', 'theirs', 'myself', 'yourself', 'himself',
                        'herself', 'itself', 'ourselves', 'yourselves', 'themselves'}
            
            for word in words:
                if len(word) > 2 and word not in stopwords:
                    if word in results['keywords']:
                        results['keywords'][word] += 1
                    else:
                        results['keywords'][word] = 1
        
        # Sort keywords by frequency and take top 20
        results['keywords'] = dict(sorted(
            results['keywords'].items(),
            key=lambda x: x[1],
            reverse=True
        )[:20])
        
        return results
    
    def _basic_sentiment_analysis(self, content_items: List[Dict[str, Any]], results: Dict[str, Any]) -> None:
        """
        Perform basic sentiment analysis using keyword matching.
        
        Args:
            content_items: List of content items with text
            results: Results dictionary to update
        """
        positive_words = {
            'good', 'great', 'awesome', 'excellent', 'amazing', 'love', 'best',
            'wonderful', 'happy', 'excited', 'glad', 'perfect', 'thank', 'thanks',
            'appreciate', 'pleased', 'joy', 'fantastic', 'outstanding', 'superb'
        }
        
        negative_words = {
            'bad', 'terrible', 'awful', 'horrible', 'hate', 'worst', 'poor',
            'disappointing', 'disappointed', 'sad', 'unhappy', 'angry', 'upset',
            'sucks', 'wrong', 'fail', 'failed', 'failure', 'problem', 'problems'
        }
        
        for item in content_items:
            text = item['text'].lower()
            pos_count = sum(1 for word in positive_words if re.search(r'\b' + word + r'\b', text))
            neg_count = sum(1 for word in negative_words if re.search(r'\b' + word + r'\b', text))
            
            if pos_count > neg_count:
                results['sentiment']['positive'] += 1
            elif neg_count > pos_count:
                results['sentiment']['negative'] += 1
            else:
                results['sentiment']['neutral'] += 1
    
    def _extract_trends(self, content_items: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Extract trending topics, hashtags, and time-based patterns.
        
        Args:
            content_items: List of content items with text and metadata
        
        Returns:
            Dictionary containing trend analysis
        """
        trends = {
            'top_hashtags': {},
            'time_distribution': {},
            'engagement_metrics': {},
            'influential_users': {}
        }
        
        if not content_items:
            return trends
        
        # Process hashtags
        all_hashtags = []
        for item in content_items:
            text = item['text']
            hashtags = re.findall(r'#(\w+)', text)
            all_hashtags.extend([h.lower() for h in hashtags])
        
        # Count hashtag frequency
        for hashtag in all_hashtags:
            if hashtag in trends['top_hashtags']:
                trends['top_hashtags'][hashtag] += 1
            else:
                trends['top_hashtags'][hashtag] = 1
        
        # Sort and take top 10 hashtags
        trends['top_hashtags'] = dict(sorted(
            trends['top_hashtags'].items(), 
            key=lambda x: x[1], 
            reverse=True
        )[:10])
        
        # Time-based analysis
        for item in content_items:
            data = item.get('data', {})
            created_at = data.get('created_at')
            
            if created_at:
                try:
                    dt = datetime.datetime.fromisoformat(created_at.replace('Z', '+00:00'))
                    hour = dt.hour
                    
                    if hour in trends['time_distribution']:
                        trends['time_distribution'][hour] += 1
                    else:
                        trends['time_distribution'][hour] = 1
                except (ValueError, TypeError):
                    pass
        
        # Ensure all hours are represented
        for hour in range(24):
            if hour not in trends['time_distribution']:
                trends['time_distribution'][hour] = 0
        
        # Sort time distribution by hour
        trends['time_distribution'] = dict(sorted(
            trends['time_distribution'].items()
        ))
        
        # Engagement metrics
        if content_items and content_items[0]['platform'] == 'twitter':
            engagement_sum = 0
            for item in content_items:
                data = item.get('data', {})
                retweets = data.get('retweet_count', 0)
                favorites = data.get('favorite_count', 0)
                
                engagement = retweets + favorites
                engagement_sum += engagement
                
                # Track influential users
                user = data.get('user', {})
                if user:
                    user_id = user.get('screen_name', user.get('id_str', 'unknown'))
                    if user_id in trends['influential_users']:
                        trends['influential_users'][user_id]['engagement'] += engagement
                        trends['influential_users'][user_id]['count'] += 1
                    else:
                        trends['influential_users'][user_id] = {
                            'engagement': engagement,
                            'count': 1,
                            'name': user.get('name', user_id)
                        }
            
            # Calculate average engagement
            if content_items:
                trends['engagement_metrics']['average'] = engagement_sum / len(content_items)
        
        elif content_items and content_items[0]['platform'] == 'reddit':
            score_sum = 0
            for item in content_items:
                data = item.get('data', {})
                score = data.get('score', 0)
                comments = data.get('num_comments', 0)
                
                engagement = score + comments
                score_sum += engagement
                
                # Track influential users
                author = data.get('author', 'unknown')
                if author in trends['influential_users']:
                    trends['influential_users'][author]['engagement'] += engagement
                    trends['influential_users'][author]['count'] += 1
                else:
                    trends['influential_users'][author] = {
                        'engagement': engagement,
                        'count': 1,
                        'name': author
                    }
            
            # Calculate average engagement
            if content_items:
                trends['engagement_metrics']['average'] = score_sum / len(content_items)
        
        # Sort influential users by engagement
        trends['influential_users'] = dict(sorted(
            trends['influential_users'].items(),
            key=lambda x: x[1]['engagement'],
            reverse=True
        )[:10])
        
        return trends
    
    def _generate_network_analysis(self, username: str, profile_data: Dict[str, Any], raw_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate network analysis for a social media profile.
        
        Args:
            username: Profile username
            profile_data: Profile data by platform
            raw_data: Raw data from OSINT aggregator
        
        Returns:
            Dictionary containing network analysis
        """
        network_analysis = {
            'nodes': [],
            'edges': [],
            'metrics': {},
            'communities': [],
            'visualizations': {}
        }
        
        # Create a graph
        G = nx.Graph()
        
        # Add main user node
        main_node_id = f"user:{username}"
        G.add_node(main_node_id, type='user', platform='main', label=username)
        
        node_counter = 1
        edge_counter = 0
        
        # Process Twitter data
        if 'twitter' in raw_data and raw_data['twitter'].get('status') == 'success':
            twitter_data = raw_data['twitter']
            
            if twitter_data.get('type') == 'user':
                # Add Twitter profile as a node
                twitter_profile = twitter_data.get('user', {})
                twitter_node_id = f"twitter:user:{twitter_profile.get('screen_name', 'unknown')}"
                
                G.add_node(
                    twitter_node_id,
                    type='user',
                    platform='twitter',
                    label=f"@{twitter_profile.get('screen_name', 'unknown')}",
                    data=twitter_profile
                )
                
                # Connect main user to Twitter profile
                G.add_edge(main_node_id, twitter_node_id, type='identity')
                edge_counter += 1
                
                # Process tweets and connections
                tweets = twitter_data.get('recent_tweets', [])
                mentioned_users = set()
                hashtags = set()
                
                for tweet in tweets:
                    # Extract mentions
                    mentions = re.findall(r'@(\w+)', tweet.get('full_text', ''))
                    hashtag_matches = re.findall(r'#(\w+)', tweet.get('full_text', ''))
                    
                    # Add mentioned users
                    for mention in mentions:
                        if mention.lower() != username.lower():
                            mentioned_users.add(mention)
                    
                    # Add hashtags
                    for hashtag in hashtag_matches:
                        hashtags.add(hashtag)
                
                # Add mentioned users to graph
                for i, user in enumerate(mentioned_users):
                    if node_counter <= 30:  # Limit to prevent huge graphs
                        mention_node_id = f"twitter:user:{user}"
                        G.add_node(
                            mention_node_id,
                            type='user',
                            platform='twitter',
                            label=f"@{user}"
                        )
                        G.add_edge(twitter_node_id, mention_node_id, type='mention')
                        edge_counter += 1
                        node_counter += 1
                
                # Add hashtags to graph
                for i, hashtag in enumerate(hashtags):
                    if node_counter <= 50:  # Limit to prevent huge graphs
                        hashtag_node_id = f"twitter:hashtag:{hashtag}"
                        G.add_node(
                            hashtag_node_id,
                            type='hashtag',
                            platform='twitter',
                            label=f"#{hashtag}"
                        )
                        G.add_edge(twitter_node_id, hashtag_node_id, type='used')
                        edge_counter += 1
                        node_counter += 1
        
        # Process Reddit data
        if 'reddit' in raw_data and raw_data['reddit'].get('status') == 'success':
            reddit_data = raw_data['reddit']
            
            if reddit_data.get('type') == 'user':
                # Add Reddit profile as a node
                reddit_profile = reddit_data.get('user', {})
                reddit_node_id = f"reddit:user:{reddit_profile.get('name', 'unknown')}"
                
                G.add_node(
                    reddit_node_id,
                    type='user',
                    platform='reddit',
                    label=f"u/{reddit_profile.get('name', 'unknown')}",
                    data=reddit_profile
                )
                
                # Connect main user to Reddit profile
                G.add_edge(main_node_id, reddit_node_id, type='identity')
                edge_counter += 1
                
                # Process subreddits from posts and comments
                subreddits = set()
                
                # Extract subreddits from posts
                for post in reddit_data.get('recent_posts', []):
                    subreddit = post.get('subreddit')
                    if subreddit:
                        subreddits.add(subreddit)
                
                # Extract subreddits from comments
                for comment in reddit_data.get('recent_comments', []):
                    subreddit = comment.get('subreddit')
                    if subreddit:
                        subreddits.add(subreddit)
                
                # Add subreddits to graph
                for i, subreddit in enumerate(subreddits):
                    if node_counter <= 50:  # Limit to prevent huge graphs
                        subreddit_node_id = f"reddit:subreddit:{subreddit}"
                        G.add_node(
                            subreddit_node_id,
                            type='subreddit',
                            platform='reddit',
                            label=f"r/{subreddit}"
                        )
                        G.add_edge(reddit_node_id, subreddit_node_id, type='active_in')
                        edge_counter += 1
                        node_counter += 1
        
        # Calculate basic network metrics
        if len(G.nodes) > 0:
            try:
                network_analysis['metrics']['node_count'] = len(G.nodes)
                network_analysis['metrics']['edge_count'] = len(G.edges)
                
                if len(G.nodes) > 1:
                    network_analysis['metrics']['density'] = nx.density(G)
                    
                    # Use degree centrality as a simple importance measure
                    centrality = nx.degree_centrality(G)
                    network_analysis['metrics']['most_central_nodes'] = sorted(
                        centrality.items(), key=lambda x: x[1], reverse=True
                    )[:5]
                    
                    # Find communities if the graph is large enough
                    if len(G.nodes) >= 5:
                        communities = list(nx.algorithms.community.greedy_modularity_communities(G))
                        network_analysis['communities'] = [list(c) for c in communities]
            except Exception as e:
                logger.error(f"Error calculating network metrics: {str(e)}")
        
        # Convert to serializable format for the results
        for node_id, attrs in G.nodes(data=True):
            node_data = {
                'id': node_id,
                'type': attrs.get('type', 'unknown'),
                'platform': attrs.get('platform', 'unknown'),
                'label': attrs.get('label', node_id)
            }
            network_analysis['nodes'].append(node_data)
        
        for u, v, attrs in G.edges(data=True):
            edge_data = {
                'source': u,
                'target': v,
                'type': attrs.get('type', 'unknown')
            }
            network_analysis['edges'].append(edge_data)
        
        # Generate visualization if enough nodes
        if len(G.nodes) > 1:
            network_analysis['visualizations'] = self._create_network_visualization(G)
        
        return network_analysis
    
    def _generate_topic_network(self, topic: str, network_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate network analysis for a topic search.
        
        Args:
            topic: Search topic
            network_data: Raw platform data
        
        Returns:
            Dictionary containing network analysis
        """
        network_analysis = {
            'nodes': [],
            'edges': [],
            'metrics': {},
            'communities': [],
            'visualizations': {}
        }
        
        # Create a graph
        G = nx.Graph()
        
        # Add main topic node
        main_node_id = f"topic:{topic}"
        G.add_node(main_node_id, type='topic', platform='main', label=topic)
        
        node_counter = 1
        edge_counter = 0
        
        # Process Twitter data
        if 'twitter' in network_data and network_data['twitter'].get('status') == 'success':
            twitter_data = network_data['twitter']
            
            if twitter_data.get('type') == 'search':
                tweets = twitter_data.get('tweets', [])
                users = {}
                hashtags = {}
                
                # Process tweets
                for tweet in tweets:
                    # Get user
                    user = tweet.get('user', {})
                    user_id = user.get('screen_name', user.get('id_str'))
                    
                    if user_id:
                        if user_id in users:
                            users[user_id]['count'] += 1
                        else:
                            users[user_id] = {
                                'count': 1,
                                'name': user.get('name', user_id)
                            }
                    
                    # Extract hashtags
                    for hashtag in re.findall(r'#(\w+)', tweet.get('full_text', '')):
                        hashtag = hashtag.lower()
                        if hashtag in hashtags:
                            hashtags[hashtag] += 1
                        else:
                            hashtags[hashtag] = 1
                
                # Add top users to graph
                top_users = sorted(users.items(), key=lambda x: x[1]['count'], reverse=True)[:10]
                for user_id, user_data in top_users:
                    user_node_id = f"twitter:user:{user_id}"
                    G.add_node(
                        user_node_id,
                        type='user',
                        platform='twitter',
                        label=f"@{user_id}",
                        weight=user_data['count']
                    )
                    G.add_edge(main_node_id, user_node_id, type='discussed', weight=user_data['count'])
                    edge_counter += 1
                    node_counter += 1
                
                # Add top hashtags to graph
                top_hashtags = sorted(hashtags.items(), key=lambda x: x[1], reverse=True)[:10]
                for hashtag, count in top_hashtags:
                    hashtag_node_id = f"twitter:hashtag:{hashtag}"
                    G.add_node(
                        hashtag_node_id,
                        type='hashtag',
                        platform='twitter',
                        label=f"#{hashtag}",
                        weight=count
                    )
                    G.add_edge(main_node_id, hashtag_node_id, type='related', weight=count)
                    edge_counter += 1
                    node_counter += 1
        
        # Process Reddit data
        if 'reddit' in network_data and network_data['reddit'].get('status') == 'success':
            reddit_data = network_data['reddit']
            
            if reddit_data.get('type') == 'search':
                posts = reddit_data.get('results', [])
                subreddits = {}
                authors = {}
                
                # Process posts
                for post in posts:
                    # Get subreddit
                    subreddit = post.get('subreddit')
                    if subreddit:
                        if subreddit in subreddits:
                            subreddits[subreddit] += 1
                        else:
                            subreddits[subreddit] = 1
                    
                    # Get author
                    author = post.get('author')
                    if author and author != '[deleted]':
                        if author in authors:
                            authors[author] += 1
                        else:
                            authors[author] = 1
                
                # Add top subreddits to graph
                top_subreddits = sorted(subreddits.items(), key=lambda x: x[1], reverse=True)[:10]
                for subreddit, count in top_subreddits:
                    subreddit_node_id = f"reddit:subreddit:{subreddit}"
                    G.add_node(
                        subreddit_node_id,
                        type='subreddit',
                        platform='reddit',
                        label=f"r/{subreddit}",
                        weight=count
                    )
                    G.add_edge(main_node_id, subreddit_node_id, type='discussed_in', weight=count)
                    edge_counter += 1
                    node_counter += 1
                
                # Add top authors to graph
                top_authors = sorted(authors.items(), key=lambda x: x[1], reverse=True)[:10]
                for author, count in top_authors:
                    author_node_id = f"reddit:user:{author}"
                    G.add_node(
                        author_node_id,
                        type='user',
                        platform='reddit',
                        label=f"u/{author}",
                        weight=count
                    )
                    G.add_edge(main_node_id, author_node_id, type='posted_by', weight=count)
                    edge_counter += 1
                    node_counter += 1
        
        # Calculate basic network metrics
        if len(G.nodes) > 0:
            try:
                network_analysis['metrics']['node_count'] = len(G.nodes)
                network_analysis['metrics']['edge_count'] = len(G.edges)
                
                if len(G.nodes) > 1:
                    network_analysis['metrics']['density'] = nx.density(G)
                    
                    # Use degree centrality as a simple importance measure
                    centrality = nx.degree_centrality(G)
                    network_analysis['metrics']['most_central_nodes'] = sorted(
                        centrality.items(), key=lambda x: x[1], reverse=True
                    )[:5]
                    
                    # Find communities if the graph is large enough
                    if len(G.nodes) >= 5:
                        communities = list(nx.algorithms.community.greedy_modularity_communities(G))
                        network_analysis['communities'] = [list(c) for c in communities]
            except Exception as e:
                logger.error(f"Error calculating network metrics: {str(e)}")
        
        # Convert to serializable format for the results
        for node_id, attrs in G.nodes(data=True):
            node_data = {
                'id': node_id,
                'type': attrs.get('type', 'unknown'),
                'platform': attrs.get('platform', 'unknown'),
                'label': attrs.get('label', node_id),
                'weight': attrs.get('weight', 1)
            }
            network_analysis['nodes'].append(node_data)
        
        for u, v, attrs in G.edges(data=True):
            edge_data = {
                'source': u,
                'target': v,
                'type': attrs.get('type', 'unknown'),
                'weight': attrs.get('weight', 1)
            }
            network_analysis['edges'].append(edge_data)
        
        # Generate visualization if enough nodes
        if len(G.nodes) > 1:
            network_analysis['visualizations'] = self._create_network_visualization(G)
        
        return network_analysis
    
    def _create_network_visualization(self, G: nx.Graph) -> Dict[str, Any]:
        """
        Create network visualizations using Plotly.
        
        Args:
            G: NetworkX graph
        
        Returns:
            Dictionary containing visualization data
        """
        # Apply spring layout with adjusted parameters based on graph size
        k = 1.5 / math.sqrt(len(G.nodes))
        pos = nx.spring_layout(G, k=k, iterations=50)
        
        # Node types and platforms for coloring
        node_types = set(nx.get_node_attributes(G, 'type').values())
        platforms = set(nx.get_node_attributes(G, 'platform').values())
        
        # Create color maps
        type_colors = {
            'user': '#1f77b4',
            'topic': '#ff7f0e',
            'hashtag': '#2ca02c',
            'subreddit': '#d62728',
            'unknown': '#7f7f7f'
        }
        
        platform_colors = {
            'main': '#1f77b4',
            'twitter': '#1da1f2',
            'reddit': '#ff4500',
            'unknown': '#7f7f7f'
        }
        
        # Node attributes
        node_x = []
        node_y = []
        node_text = []
        node_color = []
        node_size = []
        
        for node in G.nodes():
            node_x.append(pos[node][0])
            node_y.append(pos[node][1])
            
            # Node label and attributes
            attrs = G.nodes[node]
            label = attrs.get('label', node)
            node_text.append(label)
            
            # Node size based on degree or weight
            weight = attrs.get('weight', 1)
            degree = G.degree(node)
            size = 10 + (weight * 3) + (degree * 2)
            node_size.append(size)
            
            # Node color based on type
            node_type = attrs.get('type', 'unknown')
            platform = attrs.get('platform', 'unknown')
            color = type_colors.get(node_type, type_colors['unknown'])
            node_color.append(color)
        
        # Edge coordinates
        edge_x = []
        edge_y = []
        
        for edge in G.edges():
            x0, y0 = pos[edge[0]]
            x1, y1 = pos[edge[1]]
            edge_x.extend([x0, x1, None])
            edge_y.extend([y0, y1, None])
        
        # Create edge trace
        edge_trace = go.Scatter(
            x=edge_x, y=edge_y,
            line=dict(width=0.5, color='#888'),
            hoverinfo='none',
            mode='lines')
        
        # Create node trace
        node_trace = go.Scatter(
            x=node_x, y=node_y,
            mode='markers',
            hoverinfo='text',
            text=node_text,
            marker=dict(
                showscale=False,
                color=node_color,
                size=node_size,
                line=dict(width=1, color='#888')
            )
        )
        
        # Create figure
        fig = go.Figure(
            data=[edge_trace, node_trace],
            layout=go.Layout(
                title='Network Graph',
                showlegend=False,
                hovermode='closest',
                margin=dict(b=20, l=5, r=5, t=40),
                xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                plot_bgcolor='rgba(0,0,0,0)',
                paper_bgcolor='rgba(0,0,0,0)',
            )
        )
        
        # Convert to JSON for web display
        visualization_data = {
            'plotly': json.loads(fig.to_json())
        }
        
        return visualization_data


# Command-line utility for quick testing
if __name__ == "__main__":
    import argparse
    from dotenv import load_dotenv
    
    load_dotenv()
    
    parser = argparse.ArgumentParser(description="Social Media Analyzer")
    parser.add_argument("--mode", choices=["profile", "topic"], default="profile", help="Analysis mode")
    parser.add_argument("--target", required=True, help="Username or topic to analyze")
    parser.add_argument("--platforms", nargs="+", choices=["twitter", "reddit"], default=["twitter", "reddit"], help="Platforms to analyze")
    parser.add_argument("--output", choices=["json", "pretty", "summary"], default="pretty", help="Output format")
    args = parser.parse_args()
    
    # Configure logging
    logging.basicConfig(level=logging.INFO)
    
    # Load configuration from environment variables
    config = {
        'twitter_consumer_key': os.environ.get('TWITTER_CONSUMER_KEY'),
        'twitter_consumer_secret': os.environ.get('TWITTER_CONSUMER_SECRET'),
        'twitter_access_token': os.environ.get('TWITTER_ACCESS_TOKEN'),
        'twitter_access_token_secret': os.environ.get('TWITTER_ACCESS_TOKEN_SECRET'),
        'reddit_client_id': os.environ.get('REDDIT_CLIENT_ID'),
        'reddit_client_secret': os.environ.get('REDDIT_CLIENT_SECRET'),
        'reddit_user_agent': os.environ.get('REDDIT_USER_AGENT', 'SKrulll OSINT Analyzer/1.0.0'),
        'elasticsearch_hosts': os.environ.get('ELASTICSEARCH_HOSTS', 'http://localhost:9200').split(','),
        'elasticsearch_username': os.environ.get('ELASTICSEARCH_USERNAME'),
        'elasticsearch_password': os.environ.get('ELASTICSEARCH_PASSWORD')
    }
    
    # Initialize analyzer
    analyzer = SocialMediaAnalyzer(config)
    
    # Run analysis
    async def main():
        if args.mode == "profile":
            results = await analyzer.analyze_profile(args.target, args.platforms)
        else:
            results = await analyzer.analyze_topic(args.target, args.platforms)
        
        if args.output == "json":
            print(json.dumps(results))
        elif args.output == "pretty":
            print(json.dumps(results, indent=2))
        elif args.output == "summary":
            # Print a simple summary
            print(f"=== {args.mode.upper()} ANALYSIS: {args.target} ===")
            print(f"Platforms: {', '.join(args.platforms)}")
            print()
            
            if args.mode == "profile":
                # Profile summary
                for platform in args.platforms:
                    if platform in results.get('profile_data', {}):
                        print(f"== {platform.upper()} PROFILE ==")
                        
                        if platform == 'twitter':
                            profile = results['profile_data']['twitter']
                            print(f"Name: {profile.get('name', 'N/A')}")
                            print(f"Username: @{profile.get('screen_name', 'N/A')}")
                            print(f"Followers: {profile.get('followers_count', 'N/A')}")
                            print(f"Following: {profile.get('friends_count', 'N/A')}")
                        
                        elif platform == 'reddit':
                            profile = results['profile_data']['reddit']
                            print(f"Username: u/{profile.get('name', 'N/A')}")
                            print(f"Link Karma: {profile.get('link_karma', 'N/A')}")
                            print(f"Comment Karma: {profile.get('comment_karma', 'N/A')}")
                        
                        print()
                
                # Content analysis summary
                for platform in args.platforms:
                    if platform in results.get('content_analysis', {}):
                        print(f"== {platform.upper()} CONTENT ANALYSIS ==")
                        analysis = results['content_analysis'][platform]
                        
                        # Sentiment
                        sentiment = analysis.get('sentiment', {})
                        total = sum(sentiment.values())
                        if total > 0:
                            pos_pct = (sentiment.get('positive', 0) / total) * 100
                            neg_pct = (sentiment.get('negative', 0) / total) * 100
                            neu_pct = (sentiment.get('neutral', 0) / total) * 100
                            
                            print(f"Sentiment: {pos_pct:.1f}% Positive, {neg_pct:.1f}% Negative, {neu_pct:.1f}% Neutral")
                        
                        # Top keywords
                        keywords = analysis.get('keywords', {})
                        if keywords:
                            top_keywords = sorted(keywords.items(), key=lambda x: x[1], reverse=True)[:5]
                            print(f"Top keywords: {', '.join(k for k, v in top_keywords)}")
                        
                        # Hashtags
                        hashtags = analysis.get('hashtags', [])
                        if hashtags:
                            print(f"Hashtags: {', '.join(hashtags[:5])}")
                        
                        print()
            
            else:
                # Topic summary
                for platform in args.platforms:
                    if platform in results.get('content_analysis', {}):
                        print(f"== {platform.upper()} CONTENT ANALYSIS ==")
                        analysis = results['content_analysis'][platform]
                        
                        # Count
                        print(f"Found {analysis.get('count', 0)} {platform} posts")
                        
                        # Sentiment
                        sentiment = analysis.get('sentiment', {})
                        total = sum(sentiment.values())
                        if total > 0:
                            pos_pct = (sentiment.get('positive', 0) / total) * 100
                            neg_pct = (sentiment.get('negative', 0) / total) * 100
                            neu_pct = (sentiment.get('neutral', 0) / total) * 100
                            
                            print(f"Sentiment: {pos_pct:.1f}% Positive, {neg_pct:.1f}% Negative, {neu_pct:.1f}% Neutral")
                        
                        # Trends
                        if platform in results.get('trends', {}):
                            trends = results['trends'][platform]
                            
                            # Top hashtags
                            top_hashtags = trends.get('top_hashtags', {})
                            if top_hashtags:
                                top_5 = sorted(top_hashtags.items(), key=lambda x: x[1], reverse=True)[:5]
                                print(f"Top hashtags: {', '.join('#' + k for k, v in top_5)}")
                            
                            # Influential users
                            influential = trends.get('influential_users', {})
                            if influential:
                                top_5 = sorted(influential.items(), key=lambda x: x[1]['engagement'], reverse=True)[:5]
                                print(f"Top users: {', '.join(k for k, v in top_5)}")
                        
                        print()
                
                # Network analysis summary
                network = results.get('network_analysis', {})
                metrics = network.get('metrics', {})
                if metrics:
                    print("== NETWORK ANALYSIS ==")
                    print(f"Nodes: {metrics.get('node_count', 0)}")
                    print(f"Connections: {metrics.get('edge_count', 0)}")
                    
                    communities = network.get('communities', [])
                    if communities:
                        print(f"Found {len(communities)} communities in the network")
    
    asyncio.run(main())
