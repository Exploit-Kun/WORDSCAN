"""
Professional HTTP engine with connection pooling, retry, adaptive timeout
"""

import asyncio
import aiohttp
import random
import time
from typing import Dict, Optional, Any


class HTTPEngine:
    """Professional HTTP engine with connection pooling, retry, adaptive timeout"""

    def __init__(self, config: Dict):
        self.config = config
        self.session = None
        self.semaphore = asyncio.Semaphore(config.get("concurrency", 50))
        self.retry_count = config.get("retries", 2)
        self.timeout = config.get("timeout", 10)
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0.0.0",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0",
        ]
        self.ua_index = 0

    async def __aenter__(self):
        timeout = aiohttp.ClientTimeout(total=self.timeout * 2)
        connector = aiohttp.TCPConnector(limit=100, limit_per_host=10, ssl=False)
        self.session = aiohttp.ClientSession(
            timeout=timeout,
            connector=connector,
            headers={"User-Agent": self._get_user_agent()},
        )
        return self

    async def __aexit__(self, *args):
        if self.session:
            await self.session.close()

    def _get_user_agent(self) -> str:
        ua = self.user_agents[self.ua_index % len(self.user_agents)]
        self.ua_index += 1
        return ua

    async def get(
        self, url: str, headers: Dict = None, allow_redirects: bool = True
    ) -> Optional[Dict]:
        """GET request with retry and exponential backoff"""
        for attempt in range(self.retry_count + 1):
            try:
                async with self.semaphore:
                    async with self.session.get(
                        url,
                        headers=headers or {},
                        allow_redirects=allow_redirects,
                        timeout=self.timeout,
                    ) as response:
                        return {
                            "status": response.status,
                            "headers": dict(response.headers),
                            "html": await response.text(),
                            "url": str(response.url),
                            "elapsed": response.elapsed.total_seconds() * 1000,
                        }
            except asyncio.TimeoutError:
                if attempt == self.retry_count:
                    return {"error": "Timeout", "status": 0}
                await asyncio.sleep(2**attempt + random.uniform(0, 1))
            except Exception as e:
                if attempt == self.retry_count:
                    return {"error": str(e), "status": 0}
                await asyncio.sleep(2**attempt + random.uniform(0, 1))
        return {"error": "Max retries exceeded", "status": 0}

    async def head(self, url: str) -> Optional[Dict]:
        """HEAD request for asset checking"""
        try:
            async with self.semaphore:
                async with self.session.head(
                    url, timeout=self.timeout // 2
                ) as response:
                    return {
                        "status": response.status,
                        "headers": dict(response.headers),
                    }
        except:
            return {"status": 0, "error": "Failed"}
