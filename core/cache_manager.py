"""
Intelligent cache manager with TTL per resource type
"""

import time
from typing import Dict, Optional


class CacheManager:
    """Intelligent cache manager with TTL per resource type"""

    def __init__(self):
        self._cache = {}
        self._ttl = {
            "homepage": 3600,
            "readme": 21600,
            "asset": 86400,
            "head": 21600,
            "rest": 900,
        }
        self._hits = 0
        self._misses = 0

    def get(self, key: str, ttl_type: str = "homepage") -> Optional[Dict]:
        """Get from cache"""
        if key in self._cache:
            data, timestamp = self._cache[key]
            if time.time() - timestamp < self._ttl.get(ttl_type, 3600):
                self._hits += 1
                return data
            del self._cache[key]
        self._misses += 1
        return None

    def set(self, key: str, value: Dict, ttl_type: str = "homepage"):
        """Set cache"""
        self._cache[key] = (value, time.time())

    def clear(self):
        """Clear all cache"""
        self._cache.clear()

    def get_stats(self) -> Dict:
        """Get cache statistics"""
        total = self._hits + self._misses
        return {
            "size": len(self._cache),
            "hits": self._hits,
            "misses": self._misses,
            "hit_ratio": (self._hits / total * 100) if total > 0 else 0,
        }
