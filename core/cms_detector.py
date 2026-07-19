"""
CMS detector with confidence scoring
"""

import re
from typing import Dict, Optional
from core.models import DetectionResult, Evidence, NegativeEvidence
from core.http_engine import HTTPEngine
from core.cache_manager import CacheManager

# CMS Signatures
CMS_SIGNATURES = {
    "wordpress": {
        "positive": [
            {
                "pattern": r'<meta name="generator" content="WordPress ([\d.]+)"',
                "weight": 20,
                "category": "html",
            },
            {
                "pattern": r"(/wp-content/|/wp-includes/)",
                "weight": 15,
                "category": "html",
            },
            {"pattern": r"/wp-json/", "weight": 15, "category": "html"},
            {
                "pattern": r'rel="https://api.w.org/"',
                "weight": 15,
                "category": "header",
            },
            {"file": "/readme.html", "weight": 10},
            {"file": "/wp-login.php", "weight": 10},
            {"file": "/xmlrpc.php", "weight": 5},
        ],
        "negative": [
            {"pattern": r'<meta name="generator" content="Joomla', "weight": -40},
            {"pattern": r'<meta name="Generator" content="Drupal', "weight": -40},
            {"pattern": r'<meta name="generator" content="Ghost', "weight": -30},
            {"pattern": r"/media/jui/", "weight": -30},
            {"pattern": r"/sites/default/", "weight": -30},
        ],
    }
}


class CMSDetector:
    """Auto detect CMS with confidence scoring"""

    def __init__(self, http: HTTPEngine, cache: CacheManager):
        self.http = http
        self.cache = cache

    async def detect(self, domain: str) -> DetectionResult:
        """Detect CMS from domain"""
        result = DetectionResult(name="Unknown", category="cms")

        # Try HTTPS first, fallback to HTTP
        for protocol in ["https", "http"]:
            url = f"{protocol}://{domain}"

            # Check cache
            cache_key = f"homepage:{url}"
            cached = self.cache.get(cache_key)
            if cached:
                response = cached
            else:
                response = await self.http.get(url)
                if response and response.get("status") == 200:
                    self.cache.set(cache_key, response)

            if not response or response.get("status") != 200:
                continue

            html = response.get("html", "")
            headers = response.get("headers", {})

            # Check WordPress
            wp_result = await self._check_wordpress(html, headers, domain)
            if wp_result.confidence > result.confidence:
                result = wp_result

            # Check Joomla
            joomla_result = await self._check_joomla(html, headers)
            if joomla_result.confidence > result.confidence:
                result = joomla_result

            # Check Drupal
            drupal_result = await self._check_drupal(html, headers)
            if drupal_result.confidence > result.confidence:
                result = drupal_result

            if result.confidence >= 70:
                break

        return result

    async def _check_wordpress(
        self, html: str, headers: Dict, domain: str
    ) -> DetectionResult:
        """Check WordPress fingerprints"""
        result = DetectionResult(name="WordPress", category="cms")
        score = 0
        evidence = []
        negative_evidence = []

        # Check positive patterns
        for rule in CMS_SIGNATURES.get("wordpress", {}).get("positive", []):
            if "pattern" in rule:
                if re.search(rule["pattern"], html, re.IGNORECASE):
                    score += rule["weight"]
                    evidence.append(
                        Evidence(
                            rule_id="wp_positive",
                            category=rule["category"],
                            weight=rule["weight"],
                        )
                    )
            elif "file" in rule:
                url = f"https://{domain}{rule['file']}"
                head = await self.http.head(url)
                if head and head.get("status") in [200, 301, 302]:
                    score += rule["weight"]
                    evidence.append(
                        Evidence(
                            rule_id=f"wp_{rule['file'].replace('/', '')}",
                            category="file",
                            weight=rule["weight"],
                        )
                    )

        # Check negative patterns
        for rule in CMS_SIGNATURES.get("wordpress", {}).get("negative", []):
            if re.search(rule["pattern"], html, re.IGNORECASE):
                score += rule["weight"]  # negative weight
                negative_evidence.append(
                    NegativeEvidence(
                        rule_id="wp_negative",
                        category=rule.get("category", "html"),
                        weight=rule["weight"],
                    )
                )

        result.confidence = max(0, min(100, score))
        result.evidence = evidence
        result.negative_evidence = negative_evidence

        # Extract version
        version_match = re.search(
            r'<meta name="generator" content="WordPress ([\d.]+)"', html, re.IGNORECASE
        )
        if version_match:
            result.version = version_match.group(1)
            result.accuracy = "Verified"
        elif result.confidence >= 70:
            result.accuracy = "High"
        elif result.confidence >= 40:
            result.accuracy = "Medium"
        else:
            result.accuracy = "Low"

        return result

    async def _check_joomla(self, html: str, headers: Dict) -> DetectionResult:
        """Check Joomla fingerprints"""
        result = DetectionResult(name="Joomla", category="cms")
        score = 0

        if re.search(r'<meta name="generator" content="Joomla', html, re.IGNORECASE):
            score += 25
        if re.search(r"/media/jui/", html, re.IGNORECASE):
            score += 15
        if re.search(r"/components/com_", html, re.IGNORECASE):
            score += 15

        result.confidence = min(100, score)
        if score >= 40:
            result.accuracy = "High"
        elif score >= 20:
            result.accuracy = "Medium"
        else:
            result.accuracy = "Low"

        return result

    async def _check_drupal(self, html: str, headers: Dict) -> DetectionResult:
        """Check Drupal fingerprints"""
        result = DetectionResult(name="Drupal", category="cms")
        score = 0

        if re.search(
            r'<meta name="Generator" content="Drupal ([\d.]+)"', html, re.IGNORECASE
        ):
            score += 25
            version_match = re.search(
                r'<meta name="Generator" content="Drupal ([\d.]+)"', html, re.IGNORECASE
            )
            if version_match:
                result.version = version_match.group(1)
        if re.search(r"/sites/default/", html, re.IGNORECASE):
            score += 15

        result.confidence = min(100, score)
        if score >= 40:
            result.accuracy = "High"
        elif score >= 20:
            result.accuracy = "Medium"
        else:
            result.accuracy = "Low"

        return result
