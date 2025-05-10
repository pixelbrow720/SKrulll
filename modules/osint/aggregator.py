"""
OSINT Aggregator module for the CyberOps Orchestrator.

This module provides functionality for aggregating data from various OSINT sources
including social media platforms, WHOIS data, and web scraping, with standardized output.
"""
import asyncio
import datetime
import json
import logging
import os
import time
from typing import Any, Dict, List, Optional, Union
import urllib.parse

import whois
import requests
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

# Check if optional dependencies are available
try:
    import tweepy
    TWITTER_AVAILABLE = True
except ImportError:
    logger.warning("tweepy not installed, Twitter data collection will be disabled")
    TWITTER_AVAILABLE = False

try:
    import praw
    REDDIT_AVAILABLE = True
except ImportError:
    logger.warning("praw not installed, Reddit data collection will be disabled")
    REDDIT_AVAILABLE = False

try:
    from elasticsearch import Elasticsearch
    ELASTICSEARCH_AVAILABLE = True
except ImportError:
    logger.warning("elasticsearch not installed, Elasticsearch integration will be disabled")
    ELASTICSEARCH_AVAILABLE = False


class OsintAggregator:
    """
    Aggregates data from various OSINT sources.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the OSINT aggregator.
        
        Args:
            config: Configuration dictionary with API keys and settings
        """
        self.config = config or {}
        self.twitter_client = None
        self.reddit_client = None
        self.elasticsearch_client = None
        
        # Initialize clients based on available dependencies and config
        self._init_twitter()
        self._init_reddit()
        self._init_elasticsearch()
        
        logger.info("OSINT Aggregator initialized")
    
    def _init_twitter(self):
        """Initialize Twitter API client if available."""
        if not TWITTER_AVAILABLE:
            return
        
        # Check for required config keys
        required_keys = [
            'twitter_consumer_key', 
            'twitter_consumer_secret',
            'twitter_access_token',
            'twitter_access_token_secret'
        ]
        
        if all(key in self.config for key in required_keys):
            try:
                auth = tweepy.OAuth1UserHandler(
                    self.config['twitter_consumer_key'],
                    self.config['twitter_consumer_secret'],
                    self.config['twitter_access_token'],
                    self.config['twitter_access_token_secret']
                )
                self.twitter_client = tweepy.API(auth)
                logger.info("Twitter API client initialized")
            except Exception as e:
                logger.error(f"Error initializing Twitter client: {str(e)}")
        else:
            logger.warning("Twitter API configuration incomplete, client not initialized")
    
    def _init_reddit(self):
        """Initialize Reddit API client if available."""
        if not REDDIT_AVAILABLE:
            return
        
        # Check for required config keys
        required_keys = [
            'reddit_client_id',
            'reddit_client_secret',
            'reddit_user_agent'
        ]
        
        if all(key in self.config for key in required_keys):
            try:
                self.reddit_client = praw.Reddit(
                    client_id=self.config['reddit_client_id'],
                    client_secret=self.config['reddit_client_secret'],
                    user_agent=self.config['reddit_user_agent']
                )
                logger.info("Reddit API client initialized")
            except Exception as e:
                logger.error(f"Error initializing Reddit client: {str(e)}")
        else:
            logger.warning("Reddit API configuration incomplete, client not initialized")
    
    def _init_elasticsearch(self):
        """Initialize Elasticsearch client if available."""
        if not ELASTICSEARCH_AVAILABLE:
            return
        
        # Check for required config keys
        if 'elasticsearch_hosts' in self.config:
            try:
                if 'elasticsearch_api_key' in self.config:
                    # Use API key authentication
                    self.elasticsearch_client = Elasticsearch(
                        self.config['elasticsearch_hosts'],
                        api_key=self.config['elasticsearch_api_key']
                    )
                elif all(k in self.config for k in ['elasticsearch_username', 'elasticsearch_password']):
                    # Use username/password authentication
                    self.elasticsearch_client = Elasticsearch(
                        self.config['elasticsearch_hosts'],
                        basic_auth=(
                            self.config['elasticsearch_username'],
                            self.config['elasticsearch_password']
                        )
                    )
                else:
                    # Use without authentication (not recommended for production)
                    self.elasticsearch_client = Elasticsearch(self.config['elasticsearch_hosts'])
                
                # Test connection
                if self.elasticsearch_client.ping():
                    logger.info("Elasticsearch client initialized and connected")
                else:
                    logger.warning("Elasticsearch client initialized but connection failed")
            except Exception as e:
                logger.error(f"Error initializing Elasticsearch client: {str(e)}")
        else:
            logger.warning("Elasticsearch configuration incomplete, client not initialized")
    
    async def collect_data(self, target: str, data_types: List[str] = None) -> Dict[str, Any]:
        """
        Collect OSINT data about a target asynchronously.
        
        Args:
            target: Target to collect data about (domain, username, etc.)
            data_types: Types of data to collect (twitter, reddit, whois, web)
        
        Returns:
            Dictionary containing collected data
        """
        if data_types is None:
            data_types = ['whois', 'web']
            if TWITTER_AVAILABLE and self.twitter_client:
                data_types.append('twitter')
            if REDDIT_AVAILABLE and self.reddit_client:
                data_types.append('reddit')
        
        logger.info(f"Collecting OSINT data for target: {target}, types: {data_types}")
        
        # Create tasks for each data type
        tasks = []
        if 'whois' in data_types:
            tasks.append(self._collect_whois_data(target))
        if 'web' in data_types:
            tasks.append(self._collect_web_data(target))
        if 'twitter' in data_types and TWITTER_AVAILABLE and self.twitter_client:
            tasks.append(self._collect_twitter_data(target))
        if 'reddit' in data_types and REDDIT_AVAILABLE and self.reddit_client:
            tasks.append(self._collect_reddit_data(target))
        
        # Run tasks concurrently
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results
        data = {
            'target': target,
            'timestamp': datetime.datetime.utcnow().isoformat(),
            'data_types': data_types,
            'results': {}
        }
        
        for i, data_type in enumerate([t for t in data_types if t in ['whois', 'web', 'twitter', 'reddit']]):
            if i < len(results):
                if isinstance(results[i], Exception):
                    logger.error(f"Error collecting {data_type} data: {str(results[i])}")
                    data['results'][data_type] = {
                        'status': 'error',
                        'error': str(results[i])
                    }
                else:
                    data['results'][data_type] = results[i]
        
        # Store in Elasticsearch if available
        if ELASTICSEARCH_AVAILABLE and self.elasticsearch_client:
            await self._store_in_elasticsearch(data)
        
        return data
    
    async def _collect_whois_data(self, domain: str) -> Dict[str, Any]:
        """
        Collect WHOIS data for a domain.
        
        Args:
            domain: Domain to collect WHOIS data for
        
        Returns:
            Dictionary containing WHOIS data
        """
        try:
            # Run WHOIS query in a separate thread to avoid blocking
            loop = asyncio.get_event_loop()
            whois_data = await loop.run_in_executor(None, whois.whois, domain)
            
            # Convert to serializable format
            result = {}
            for key, value in whois_data.items():
                if isinstance(value, (list, str, int, float, bool, type(None))):
                    result[key] = value
                elif isinstance(value, (datetime.datetime, datetime.date)):
                    result[key] = value.isoformat()
                else:
                    result[key] = str(value)
            
            return {
                'status': 'success',
                'whois_data': result
            }
            
        except Exception as e:
            logger.error(f"Error collecting WHOIS data for {domain}: {str(e)}")
            return {
                'status': 'error',
                'error': str(e)
            }
    
    async def _collect_web_data(self, url: str) -> Dict[str, Any]:
        """
        Collect web data by scraping a URL.
        
        Args:
            url: URL to scrape
        
        Returns:
            Dictionary containing scraped data
        """
        # Ensure URL has a scheme
        if not url.startswith(('http://', 'https://')):
            url = f"https://{url}"
            
        try:
            # Make request in a separate thread to avoid blocking
            loop = asyncio.get_event_loop()
            response = await loop.run_in_executor(
                None,
                lambda: requests.get(
                    url,
                    headers={
                        'User-Agent': 'CyberOps OSINT Scraper/1.0.0',
                        'Accept': 'text/html,application/xhtml+xml,application/xml'
                    },
                    timeout=10
                )
            )
            
            response.raise_for_status()
            
            # Parse HTML with BeautifulSoup
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Extract key information
            data = {
                'title': soup.title.string if soup.title else None,
                'meta_tags': {},
                'links': [],
                'headers': []
            }
            
            # Get meta tags
            for meta in soup.find_all('meta'):
                name = meta.get('name') or meta.get('property')
                content = meta.get('content')
                if name and content:
                    data['meta_tags'][name] = content
            
            # Get links (limit to 50)
            for i, link in enumerate(soup.find_all('a', href=True)):
                if i >= 50:
                    break
                href = link.get('href')
                if href:
                    # Convert relative URLs to absolute
                    if not href.startswith(('http://', 'https://')):
                        href = urllib.parse.urljoin(url, href)
                    data['links'].append({
                        'url': href,
                        'text': link.text.strip()
                    })
            
            # Get headers
            for tag in soup.find_all(['h1', 'h2', 'h3']):
                data['headers'].append({
                    'level': int(tag.name[1]),
                    'text': tag.text.strip()
                })
            
            return {
                'status': 'success',
                'url': url,
                'http_status': response.status_code,
                'content_type': response.headers.get('Content-Type', ''),
                'data': data
            }
            
        except Exception as e:
            logger.error(f"Error collecting web data for {url}: {str(e)}")
            return {
                'status': 'error',
                'url': url,
                'error': str(e)
            }
    
    async def _collect_twitter_data(self, query: str) -> Dict[str, Any]:
        """
        Collect Twitter data for a query.
        
        Args:
            query: Search query or username
        
        Returns:
            Dictionary containing Twitter data
        """
        if not TWITTER_AVAILABLE or not self.twitter_client:
            return {
                'status': 'error',
                'error': 'Twitter API client not available'
            }
        
        try:
            # Determine if query is a username or search term
            is_username = not query.startswith('#') and ' ' not in query
            
            # Run Twitter API calls in a separate thread to avoid blocking
            loop = asyncio.get_event_loop()
            
            if is_username:
                # Strip @ if present
                username = query.lstrip('@')
                
                # Get user profile
                user_info = await loop.run_in_executor(
                    None,
                    lambda: self.twitter_client.get_user(screen_name=username)
                )
                
                # Get recent tweets
                tweets = await loop.run_in_executor(
                    None,
                    lambda: self.twitter_client.user_timeline(
                        screen_name=username,
                        count=10,
                        tweet_mode='extended'
                    )
                )
                
                # Format user data
                user_data = {
                    'id': user_info.id_str,
                    'screen_name': user_info.screen_name,
                    'name': user_info.name,
                    'description': user_info.description,
                    'location': user_info.location,
                    'followers_count': user_info.followers_count,
                    'friends_count': user_info.friends_count,
                    'created_at': user_info.created_at.isoformat(),
                    'verified': user_info.verified
                }
                
                # Format tweets
                tweets_data = []
                for tweet in tweets:
                    tweets_data.append({
                        'id': tweet.id_str,
                        'created_at': tweet.created_at.isoformat(),
                        'full_text': tweet.full_text,
                        'retweet_count': tweet.retweet_count,
                        'favorite_count': tweet.favorite_count,
                        'hashtags': [h['text'] for h in tweet.entities.get('hashtags', [])]
                    })
                
                return {
                    'status': 'success',
                    'type': 'user',
                    'user': user_data,
                    'recent_tweets': tweets_data
                }
            else:
                # Search for tweets
                search_results = await loop.run_in_executor(
                    None,
                    lambda: self.twitter_client.search_tweets(
                        q=query,
                        count=20,
                        tweet_mode='extended',
                        result_type='recent'
                    )
                )
                
                # Format search results
                tweets_data = []
                for tweet in search_results:
                    tweets_data.append({
                        'id': tweet.id_str,
                        'created_at': tweet.created_at.isoformat(),
                        'user': {
                            'id': tweet.user.id_str,
                            'screen_name': tweet.user.screen_name,
                            'name': tweet.user.name
                        },
                        'full_text': tweet.full_text,
                        'retweet_count': tweet.retweet_count,
                        'favorite_count': tweet.favorite_count,
                        'hashtags': [h['text'] for h in tweet.entities.get('hashtags', [])]
                    })
                
                return {
                    'status': 'success',
                    'type': 'search',
                    'query': query,
                    'tweets': tweets_data
                }
                
        except Exception as e:
            logger.error(f"Error collecting Twitter data for {query}: {str(e)}")
            return {
                'status': 'error',
                'error': str(e)
            }
    
    async def _collect_reddit_data(self, query: str) -> Dict[str, Any]:
        """
        Collect Reddit data for a query.
        
        Args:
            query: Subreddit name, username, or search query
        
        Returns:
            Dictionary containing Reddit data
        """
        if not REDDIT_AVAILABLE or not self.reddit_client:
            return {
                'status': 'error',
                'error': 'Reddit API client not available'
            }
        
        try:
            # Determine query type (subreddit, user, or search)
            is_subreddit = query.startswith('r/')
            is_user = query.startswith('u/')
            
            # Run Reddit API calls in a separate thread to avoid blocking
            loop = asyncio.get_event_loop()
            
            if is_subreddit:
                # Get subreddit info and posts
                subreddit_name = query[2:] if query.startswith('r/') else query
                
                subreddit = await loop.run_in_executor(
                    None,
                    lambda: self.reddit_client.subreddit(subreddit_name)
                )
                
                # Get subreddit info
                subreddit_data = {
                    'display_name': subreddit.display_name,
                    'title': subreddit.title,
                    'description': subreddit.public_description,
                    'subscribers': subreddit.subscribers,
                    'created_utc': datetime.datetime.fromtimestamp(subreddit.created_utc).isoformat(),
                    'nsfw': subreddit.over18
                }
                
                # Get recent posts
                posts = await loop.run_in_executor(
                    None,
                    lambda: list(subreddit.hot(limit=10))
                )
                
                posts_data = []
                for post in posts:
                    posts_data.append({
                        'id': post.id,
                        'title': post.title,
                        'author': post.author.name if post.author else '[deleted]',
                        'created_utc': datetime.datetime.fromtimestamp(post.created_utc).isoformat(),
                        'score': post.score,
                        'url': post.url,
                        'num_comments': post.num_comments,
                        'permalink': f"https://www.reddit.com{post.permalink}"
                    })
                
                return {
                    'status': 'success',
                    'type': 'subreddit',
                    'subreddit': subreddit_data,
                    'recent_posts': posts_data
                }
                
            elif is_user:
                # Get user info and posts
                username = query[2:] if query.startswith('u/') else query
                
                redditor = await loop.run_in_executor(
                    None,
                    lambda: self.reddit_client.redditor(username)
                )
                
                # Check if user exists and is not suspended
                try:
                    created_utc = await loop.run_in_executor(
                        None,
                        lambda: redditor.created_utc
                    )
                    
                    # Get user info
                    user_data = {
                        'name': redditor.name,
                        'created_utc': datetime.datetime.fromtimestamp(created_utc).isoformat(),
                        'comment_karma': redditor.comment_karma,
                        'link_karma': redditor.link_karma
                    }
                    
                    # Get recent posts and comments
                    posts = await loop.run_in_executor(
                        None,
                        lambda: list(redditor.submissions.new(limit=5))
                    )
                    
                    comments = await loop.run_in_executor(
                        None,
                        lambda: list(redditor.comments.new(limit=5))
                    )
                    
                    posts_data = []
                    for post in posts:
                        posts_data.append({
                            'id': post.id,
                            'title': post.title,
                            'subreddit': post.subreddit.display_name,
                            'created_utc': datetime.datetime.fromtimestamp(post.created_utc).isoformat(),
                            'score': post.score,
                            'permalink': f"https://www.reddit.com{post.permalink}"
                        })
                    
                    comments_data = []
                    for comment in comments:
                        comments_data.append({
                            'id': comment.id,
                            'body': comment.body,
                            'subreddit': comment.subreddit.display_name,
                            'created_utc': datetime.datetime.fromtimestamp(comment.created_utc).isoformat(),
                            'score': comment.score,
                            'permalink': f"https://www.reddit.com{comment.permalink}"
                        })
                    
                    return {
                        'status': 'success',
                        'type': 'user',
                        'user': user_data,
                        'recent_posts': posts_data,
                        'recent_comments': comments_data
                    }
                except Exception as e:
                    # User might be suspended or deleted
                    return {
                        'status': 'error',
                        'type': 'user',
                        'error': f"Cannot retrieve user data: {str(e)}"
                    }
                
            else:
                # Search for posts
                search_results = await loop.run_in_executor(
                    None,
                    lambda: list(self.reddit_client.subreddit('all').search(query, limit=15))
                )
                
                results_data = []
                for post in search_results:
                    results_data.append({
                        'id': post.id,
                        'title': post.title,
                        'author': post.author.name if post.author else '[deleted]',
                        'subreddit': post.subreddit.display_name,
                        'created_utc': datetime.datetime.fromtimestamp(post.created_utc).isoformat(),
                        'score': post.score,
                        'url': post.url,
                        'num_comments': post.num_comments,
                        'permalink': f"https://www.reddit.com{post.permalink}"
                    })
                
                return {
                    'status': 'success',
                    'type': 'search',
                    'query': query,
                    'results': results_data
                }
                
        except Exception as e:
            logger.error(f"Error collecting Reddit data for {query}: {str(e)}")
            return {
                'status': 'error',
                'error': str(e)
            }
    
    async def _store_in_elasticsearch(self, data: Dict[str, Any]) -> bool:
        """
        Store collected data in Elasticsearch.
        
        Args:
            data: Data to store
        
        Returns:
            True if successful, False otherwise
        """
        if not ELASTICSEARCH_AVAILABLE or not self.elasticsearch_client:
            return False
        
        try:
            # Create index name based on date
            index_name = f"osint-{datetime.datetime.now().strftime('%Y-%m-%d')}"
            
            # Run Elasticsearch operation in a separate thread to avoid blocking
            loop = asyncio.get_event_loop()
            response = await loop.run_in_executor(
                None,
                lambda: self.elasticsearch_client.index(
                    index=index_name,
                    document=data
                )
            )
            
            logger.info(f"Data stored in Elasticsearch, index: {index_name}, id: {response['_id']}")
            return True
            
        except Exception as e:
            logger.error(f"Error storing data in Elasticsearch: {str(e)}")
            return False
    
    def format_output(self, data: Dict[str, Any], output_format: str = 'json') -> str:
        """
        Format output data in the specified format.
        
        Args:
            data: Data to format
            output_format: Output format (json, pretty, summary)
        
        Returns:
            Formatted data as string
        """
        if output_format == 'json':
            return json.dumps(data)
        elif output_format == 'pretty':
            return json.dumps(data, indent=2)
        elif output_format == 'summary':
            # Create a text summary of the data
            lines = [
                f"OSINT Data for: {data['target']}",
                f"Collected at: {data['timestamp']}",
                f"Data types: {', '.join(data['data_types'])}",
                ""
            ]
            
            for data_type, result in data['results'].items():
                lines.append(f"=== {data_type.upper()} ===")
                
                if result.get('status') == 'error':
                    lines.append(f"Error: {result.get('error', 'Unknown error')}")
                elif data_type == 'whois':
                    whois_data = result.get('whois_data', {})
                    lines.append(f"Domain: {whois_data.get('domain_name', 'N/A')}")
                    lines.append(f"Registrar: {whois_data.get('registrar', 'N/A')}")
                    lines.append(f"Creation Date: {whois_data.get('creation_date', 'N/A')}")
                    lines.append(f"Expiration Date: {whois_data.get('expiration_date', 'N/A')}")
                    if isinstance(whois_data.get('name_servers'), list):
                        lines.append(f"Name Servers: {', '.join(whois_data.get('name_servers', []))}")
                elif data_type == 'web':
                    web_data = result.get('data', {})
                    lines.append(f"URL: {result.get('url', 'N/A')}")
                    lines.append(f"Title: {web_data.get('title', 'N/A')}")
                    lines.append(f"Links: {len(web_data.get('links', []))} links found")
                elif data_type == 'twitter':
                    if result.get('type') == 'user':
                        user = result.get('user', {})
                        lines.append(f"Twitter User: @{user.get('screen_name', 'N/A')}")
                        lines.append(f"Name: {user.get('name', 'N/A')}")
                        lines.append(f"Followers: {user.get('followers_count', 'N/A')}")
                        lines.append(f"Recent Tweets: {len(result.get('recent_tweets', []))}")
                    elif result.get('type') == 'search':
                        lines.append(f"Twitter Search: {result.get('query', 'N/A')}")
                        lines.append(f"Results: {len(result.get('tweets', []))}")
                elif data_type == 'reddit':
                    if result.get('type') == 'subreddit':
                        subreddit = result.get('subreddit', {})
                        lines.append(f"Subreddit: r/{subreddit.get('display_name', 'N/A')}")
                        lines.append(f"Subscribers: {subreddit.get('subscribers', 'N/A')}")
                        lines.append(f"Recent Posts: {len(result.get('recent_posts', []))}")
                    elif result.get('type') == 'user':
                        user = result.get('user', {})
                        lines.append(f"Reddit User: u/{user.get('name', 'N/A')}")
                        lines.append(f"Karma: {user.get('link_karma', 0)} (post) / {user.get('comment_karma', 0)} (comment)")
                    elif result.get('type') == 'search':
                        lines.append(f"Reddit Search: {result.get('query', 'N/A')}")
                        lines.append(f"Results: {len(result.get('results', []))}")
                
                lines.append("")
                
            return "\n".join(lines)
        else:
            return json.dumps(data)


# Command-line utility for quick testing
if __name__ == "__main__":
    import argparse
    from dotenv import load_dotenv
    
    load_dotenv()
    
    parser = argparse.ArgumentParser(description="OSINT Aggregator")
    parser.add_argument("target", help="Target to collect data for (domain, username, etc.)")
    parser.add_argument("--types", nargs="+", choices=["whois", "web", "twitter", "reddit"], default=["whois", "web", "twitter", "reddit"], help="Data types to collect")
    parser.add_argument("--format", choices=["json", "pretty", "summary"], default="summary", help="Output format")
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
        'reddit_user_agent': os.environ.get('REDDIT_USER_AGENT', 'CyberOps OSINT Aggregator/1.0.0'),
        'elasticsearch_hosts': os.environ.get('ELASTICSEARCH_HOSTS', 'http://localhost:9200').split(','),
        'elasticsearch_username': os.environ.get('ELASTICSEARCH_USERNAME'),
        'elasticsearch_password': os.environ.get('ELASTICSEARCH_PASSWORD')
    }
    
    # Initialize aggregator
    aggregator = OsintAggregator(config)
    
    # Run collection
    async def main():
        data = await aggregator.collect_data(args.target, args.types)
        print(aggregator.format_output(data, args.format))
    
    asyncio.run(main())