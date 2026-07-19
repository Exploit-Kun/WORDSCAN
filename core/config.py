"""
Configuration manager with profiles
"""

import json
from pathlib import Path
from typing import Dict, Any

PROFILES = {
    "fast": {
        "concurrency": 100,
        "timeout": 5,
        "retries": 1,
        "fingerprint_depth": "shallow",
        "cache_ttl": 3600,
        "max_redirects": 3,
        "enable_exploit": False,
        "enable_theme_detection": False,
        "enable_technology_detection": False,
    },
    "balanced": {
        "concurrency": 50,
        "timeout": 10,
        "retries": 2,
        "fingerprint_depth": "medium",
        "cache_ttl": 1800,
        "max_redirects": 5,
        "enable_exploit": True,
        "enable_theme_detection": True,
        "enable_technology_detection": True,
    },
    "deep": {
        "concurrency": 20,
        "timeout": 20,
        "retries": 3,
        "fingerprint_depth": "deep",
        "cache_ttl": 600,
        "max_redirects": 5,
        "enable_exploit": True,
        "enable_theme_detection": True,
        "enable_technology_detection": True,
    }
}


class ConfigManager:
    """Configuration manager with profile support"""
    
    @staticmethod
    def load(profile: str = "balanced") -> Dict[str, Any]:
        """Load configuration for a profile"""
        if profile not in PROFILES:
            profile = "balanced"
        return PROFILES[profile].copy()
    
    @staticmethod
    def list_profiles() -> list:
        """List available profiles"""
        return list(PROFILES.keys())
    
    @staticmethod
    def get_profile(profile: str) -> Dict[str, Any]:
        """Get profile configuration"""
        return PROFILES.get(profile, PROFILES["balanced"]).copy()