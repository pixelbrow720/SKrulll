
"""Data leak detector module for finding exposed sensitive information."""

import asyncio
import logging
import re
from datetime import datetime
from typing import Dict, List, Optional
import aiohttp
from motor.motor_asyncio import AsyncIOMotorClient
from pymongo import ASCENDING, TEXT

logger = logging.getLogger(__name__)

class DataLeakDetector:
    def __init__(self, config: Dict):
        self.config = config
        self.db = AsyncIOMotorClient(config["mongodb_uri"]).leaks
        self.patterns = self._compile_patterns()
        
        # Setup indexes
        asyncio.create_task(self._setup_indexes())
        
    async def _setup_indexes(self):
        await self.db.leaks.create_index([("hash", ASCENDING)], unique=True)
        await self.db.leaks.create_index([("content", TEXT)])
        
    def _compile_patterns(self) -> Dict[str, re.Pattern]:
        return {
            "api_key": re.compile(r"[a-zA-Z0-9]{32,45}"),
            "email": re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"),
            "ip": re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"),
            "credit_card": re.compile(r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b")
        }
        
    async def scan_pastebin(self, api_key: str):
        """Scan recent Pastebin posts for leaks."""
        async with aiohttp.ClientSession() as session:
            url = f"https://scrape.pastebin.com/api_scraping.php?limit=100"
            headers = {"API-Key": api_key}
            
            try:
                async with session.get(url, headers=headers) as resp:
                    if resp.status == 200:
                        pastes = await resp.json()
                        
                        for paste in pastes:
                            await self.analyze_content(
                                paste["full_url"],
                                paste["content"],
                                "pastebin"
                            )
            except Exception as e:
                logger.error(f"Pastebin scan error: {str(e)}")
                
    async def analyze_content(self, source_url: str, content: str, source_type: str):
        """Analyze content for potential data leaks."""
        matches = {}
        
        # Apply regex patterns
        for pattern_name, pattern in self.patterns.items():
            if found := pattern.findall(content):
                matches[pattern_name] = found
                
        if matches:
            # Hash content to prevent duplicates
            content_hash = hashlib.sha256(content.encode()).hexdigest()
            
            # Store in database if new
            try:
                await self.db.leaks.insert_one({
                    "hash": content_hash,
                    "source_url": source_url,
                    "source_type": source_type,
                    "discovered_at": datetime.utcnow(),
                    "matches": matches,
                    "content": content
                })
                
                # Send alerts
                await self.send_alerts(source_url, matches)
                
            except Exception as e:
                if "duplicate key" not in str(e):
                    logger.error(f"Database error: {str(e)}")
                    
    async def send_alerts(self, source_url: str, matches: Dict):
        """Send alerts to configured webhooks."""
        message = {
            "text": f"🚨 Potential data leak detected!\nSource: {source_url}\nFindings:",
            "attachments": [{
                "color": "#ff0000",
                "fields": [{
                    "title": pattern,
                    "value": f"Found {len(items)} matches",
                    "short": True
                } for pattern, items in matches.items()]
            }]
        }
        
        # Send to Slack
        if webhook_url := self.config.get("slack_webhook"):
            try:
                async with aiohttp.ClientSession() as session:
                    await session.post(webhook_url, json=message)
            except Exception as e:
                logger.error(f"Slack alert error: {str(e)}")
