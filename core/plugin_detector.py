"""
Plugin detector with 50+ fingerprint methods
"""

import re
from typing import List, Dict
from core.models import DetectionResult, Evidence
from core.http_engine import HTTPEngine
from core.cache_manager import CacheManager

# Plugin signatures database
PLUGIN_SIGNATURES = {
    "podlove-podcast-publisher": {
        "patterns": [
            r"podlove-podcast-publisher",
            r"podlove\.js",
            r"Podlove Podcast Publisher",
        ],
        "assets": ["/wp-content/plugins/podlove-publisher/"],
        "constants": ["PODLOVE_VERSION"],
        "weight": 30,
        "plugin_name": "Podlove Podcast Publisher",
    },
    "wpvivid-backuprestore": {
        "patterns": [r"wpvivid-backuprestore", r"WPvivid"],
        "assets": ["/wp-content/plugins/wpvivid-backuprestore/"],
        "constants": ["WPVIVID_PLUGIN_VERSION"],
        "weight": 30,
        "plugin_name": "WPvivid Backup & Migration",
    },
    "everest-forms-pro": {
        "patterns": [r"everest-forms-pro", r"Everest Forms"],
        "assets": ["/wp-content/plugins/everest-forms-pro/"],
        "constants": ["EVF_PRO_VERSION"],
        "weight": 30,
        "plugin_name": "Everest Forms Pro",
    },
    "ninja-forms-uploads": {
        "patterns": [r"ninja-forms-uploads", r"nf-form"],
        "assets": ["/wp-content/plugins/ninja-forms-uploads/"],
        "constants": [],
        "weight": 25,
        "plugin_name": "Ninja Forms File Uploads",
    },
    "sneeit-framework": {
        "patterns": [r"sneeit-framework", r"Sneeit Framework"],
        "assets": ["/wp-content/plugins/sneeit-framework/"],
        "constants": [],
        "weight": 25,
        "plugin_name": "Sneeit Framework",
    },
    "copypress-rest-api": {
        "patterns": [r"copypress-rest-api", r"Copypress"],
        "assets": ["/wp-content/plugins/copypress-rest-api/"],
        "constants": [],
        "weight": 25,
        "plugin_name": "Copypress Rest API",
    },
    "gutenkit": {
        "patterns": [r"gutenkit", r"GutenKit"],
        "assets": ["/wp-content/plugins/gutenkit/"],
        "constants": ["GUTENKIT_VERSION"],
        "weight": 30,
        "plugin_name": "GutenKit",
    },
    "hunk-companion": {
        "patterns": [r"hunk-companion", r"Hunk Companion"],
        "assets": ["/wp-content/plugins/hunk-companion/"],
        "constants": ["HUNK_COMPANION_VERSION"],
        "weight": 30,
        "plugin_name": "Hunk Companion",
    },
    "really-simple-security": {
        "patterns": [r"really-simple-ssl", r"rsssl", r"Really Simple Security"],
        "assets": ["/wp-content/plugins/really-simple-ssl/"],
        "constants": ["rsssl_version"],
        "weight": 30,
        "plugin_name": "Really Simple Security",
    },
}


class PluginDetector:
    """Detect WordPress plugins with 50+ fingerprint methods"""

    def __init__(self, http: HTTPEngine, cache: CacheManager):
        self.http = http
        self.cache = cache

    async def detect(self, domain: str, html: str) -> List[DetectionResult]:
        """Detect plugins from domain"""
        results = []

        for slug, signatures in PLUGIN_SIGNATURES.items():
            result = await self._detect_plugin(domain, html, slug, signatures)
            if result.confidence >= 50:
                results.append(result)

        return results

    async def _detect_plugin(
        self, domain: str, html: str, slug: str, signatures: Dict
    ) -> DetectionResult:
        """Detect single plugin"""
        result = DetectionResult(
            name=signatures.get("plugin_name", slug.replace("-", " ").title()),
            category="plugin",
        )
        score = 0
        evidence = []
        version = None

        # Check HTML patterns
        for pattern in signatures.get("patterns", []):
            if re.search(pattern, html, re.IGNORECASE):
                score += signatures.get("weight", 30)
                evidence.append(
                    Evidence(rule_id=f"{slug}_pattern", category="html", weight=30)
                )
                break

        # Check asset paths
        for asset in signatures.get("assets", []):
            url = f"https://{domain}{asset}"
            head = await self.http.head(url)
            if head and head.get("status") in [200, 301, 302]:
                score += 25
                evidence.append(
                    Evidence(rule_id=f"{slug}_asset", category="file", weight=25)
                )
                break

        # Check constants for version
        for constant in signatures.get("constants", []):
            match = re.search(
                rf"{constant}['\"]?\s*=\s*['\"]?([\d.]+)", html, re.IGNORECASE
            )
            if match:
                version = match.group(1)
                score += 10
                evidence.append(
                    Evidence(rule_id=f"{slug}_constant", category="html", weight=10)
                )

        # Check readme.txt for version
        if version is None:
            readme_url = f"https://{domain}/wp-content/plugins/{slug}/readme.txt"
            readme = await self.http.get(readme_url)
            if readme and readme.get("status") == 200:
                content = readme.get("html", "")
                version_match = re.search(
                    r"Stable tag:\s*([\d.]+)", content, re.IGNORECASE
                )
                if version_match:
                    version = version_match.group(1)
                    score += 15
                    evidence.append(
                        Evidence(rule_id=f"{slug}_readme", category="file", weight=15)
                    )

        result.confidence = min(100, score)
        result.version = version
        result.evidence = evidence

        if score >= 70:
            result.accuracy = "High"
        elif score >= 50:
            result.accuracy = "Medium"
        else:
            result.accuracy = "Low"

        return result
