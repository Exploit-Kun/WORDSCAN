"""
Data models for WordScan
"""

from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from datetime import datetime


@dataclass
class Evidence:
    """Single piece of evidence for detection"""

    rule_id: str
    category: str  # html, header, file
    weight: int
    value: Optional[str] = None
    confidence: int = 100


@dataclass
class NegativeEvidence:
    """Negative evidence (reduces confidence)"""

    rule_id: str
    category: str
    weight: int
    value: Optional[str] = None


@dataclass
class DetectionResult:
    """Result from a detector"""

    name: str
    category: str  # cms, plugin, theme, technology
    version: Optional[str] = None
    confidence: int = 0
    reliability: int = 0
    accuracy: str = "Unknown"  # Verified, High, Medium, Low, Unknown
    evidence: List[Evidence] = field(default_factory=list)
    negative_evidence: List[NegativeEvidence] = field(default_factory=list)


@dataclass
class PluginVulnerability:
    """CVE vulnerability data"""

    cve: str
    cvss: float
    severity: str  # Critical, High, Medium, Low
    description: str
    affected_versions: List[str]
    fixed_version: Optional[str] = None
    poc_url: Optional[str] = None


@dataclass
class ScanResult:
    """Complete scan result for a domain"""

    domain: str
    status: str  # live, dead, redirect
    protocol: str  # http, https
    status_code: int
    response_time_ms: int
    cms: Optional[DetectionResult] = None
    plugins: List[DetectionResult] = field(default_factory=list)
    theme: Optional[DetectionResult] = None
    technologies: List[DetectionResult] = field(default_factory=list)
    vulnerabilities: List[PluginVulnerability] = field(default_factory=list)
    exploited: bool = False
    shell_url: Optional[str] = None
    error: Optional[str] = None
    detection_time: str = field(default_factory=lambda: datetime.now().isoformat())
