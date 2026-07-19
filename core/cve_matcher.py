"""
CVE matcher for plugin vulnerabilities
"""

from typing import Optional
from core.models import PluginVulnerability
from core.version_parser import VersionParser

# CVE Database
CVE_DATABASE = {
    "podlove-podcast-publisher": {
        "cve": "CVE-2026-13001",
        "cvss": 9.8,
        "severity": "Critical",
        "description": "Unauthenticated arbitrary file upload leading to RCE",
        "poc_url": "https://github.com/Raimu0x19/CVE-2026-13001",
        "affected_versions": ["<= 4.5.1"],
        "fixed_version": "4.5.2",
    },
    "wpvivid-backuprestore": {
        "cve": "CVE-2026-1357",
        "cvss": 9.8,
        "severity": "Critical",
        "description": "Unauthenticated arbitrary file upload → RCE",
        "poc_url": "https://github.com/LucasM0ntes/POC-CVE-2026-1357",
        "affected_versions": ["<= 0.9.123"],
        "fixed_version": "0.9.124",
    },
    "everest-forms-pro": {
        "cve": "CVE-2026-3300",
        "cvss": 9.8,
        "severity": "Critical",
        "description": "RCE via PHP Code Injection",
        "poc_url": "https://github.com/adamshaikhma/CVE-2026-3300",
        "affected_versions": ["<= 1.9.12"],
        "fixed_version": "1.9.13",
    },
    "ninja-forms-uploads": {
        "cve": "CVE-2026-0740",
        "cvss": 9.8,
        "severity": "Critical",
        "description": "Unauthenticated arbitrary file upload → RCE",
        "poc_url": "https://github.com/xShadow-Here/CVE-2026-0740",
        "affected_versions": ["<= 3.3.26"],
        "fixed_version": "3.3.27",
    },
    "sneeit-framework": {
        "cve": "CVE-2025-6389",
        "cvss": 9.8,
        "severity": "Critical",
        "description": "RCE via assert() injection",
        "poc_url": "https://github.com/itsismarcos/SneeitScanner-CVE-2025-6389",
        "affected_versions": ["<= 8.3"],
        "fixed_version": "8.4",
    },
    "copypress-rest-api": {
        "cve": "CVE-2025-8625",
        "cvss": 9.8,
        "severity": "Critical",
        "description": "Unauthenticated RCE via JWT bypass",
        "poc_url": "https://github.com/Nxploited/CVE-2025-8625",
        "affected_versions": ["1.1 - 1.2"],
        "fixed_version": "1.3",
    },
    "gutenkit": {
        "cve": "CVE-2024-9234",
        "cvss": 9.8,
        "severity": "Critical",
        "description": "Unauthenticated arbitrary file upload → RCE",
        "poc_url": "https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/gutenkit",
        "affected_versions": ["<= 2.1.0"],
        "fixed_version": "2.1.1",
    },
    "hunk-companion": {
        "cve": "CVE-2024-9707 & CVE-2024-11972",
        "cvss": 9.8,
        "severity": "Critical",
        "description": "Unauthenticated arbitrary plugin installation → RCE",
        "poc_url": "https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/hunk-companion",
        "affected_versions": ["<= 1.8.4"],
        "fixed_version": "1.8.5",
    },
    "really-simple-security": {
        "cve": "CVE-2024-10924",
        "cvss": 9.8,
        "severity": "Critical",
        "description": "Authentication Bypass (2FA) → RCE",
        "poc_url": "https://github.com/JoshuaProvoste/0-click-RCE-Exploit-for-CVE-2024-10924",
        "affected_versions": ["<= 8.1.3"],
        "fixed_version": "8.1.4",
    },
}


class CVEMatcher:
    """Match plugin version with CVE database"""

    @staticmethod
    def match(plugin_slug: str, version: str) -> Optional[PluginVulnerability]:
        """Check if plugin version is vulnerable"""
        cve_info = CVE_DATABASE.get(plugin_slug)
        if not cve_info:
            return None

        if version in ["unknown", None, ""]:
            # Version unknown → assume vulnerable
            return PluginVulnerability(
                cve=cve_info["cve"],
                cvss=cve_info["cvss"],
                severity=cve_info["severity"],
                description=cve_info["description"],
                affected_versions=cve_info["affected_versions"],
                fixed_version=cve_info.get("fixed_version"),
                poc_url=cve_info.get("poc_url"),
            )

        for affected in cve_info["affected_versions"]:
            if affected.startswith("<="):
                target = affected.replace("<= ", "").strip()
                if VersionParser.compare(version, target) <= 0:
                    return PluginVulnerability(
                        cve=cve_info["cve"],
                        cvss=cve_info["cvss"],
                        severity=cve_info["severity"],
                        description=cve_info["description"],
                        affected_versions=cve_info["affected_versions"],
                        fixed_version=cve_info.get("fixed_version"),
                        poc_url=cve_info.get("poc_url"),
                    )
            elif affected.startswith("<"):
                target = affected.replace("< ", "").strip()
                if VersionParser.compare(version, target) < 0:
                    return PluginVulnerability(
                        cve=cve_info["cve"],
                        cvss=cve_info["cvss"],
                        severity=cve_info["severity"],
                        description=cve_info["description"],
                        affected_versions=cve_info["affected_versions"],
                        fixed_version=cve_info.get("fixed_version"),
                        poc_url=cve_info.get("poc_url"),
                    )
            elif affected.startswith("="):
                target = affected.replace("= ", "").strip()
                if version == target:
                    return PluginVulnerability(
                        cve=cve_info["cve"],
                        cvss=cve_info["cvss"],
                        severity=cve_info["severity"],
                        description=cve_info["description"],
                        affected_versions=cve_info["affected_versions"],
                        fixed_version=cve_info.get("fixed_version"),
                        poc_url=cve_info.get("poc_url"),
                    )

        return None
