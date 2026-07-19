"""
JSON reporter
"""

import json
from typing import List
from pathlib import Path
from datetime import datetime
from reporters.base import BaseReporter
from core.models import ScanResult


class JSONReporter(BaseReporter):
    """Export results to JSON format"""

    async def export(self, results: List[ScanResult]) -> None:
        filepath = self.output_dir / "report.json"

        data = {
            "scan_date": datetime.now().isoformat(),
            "total_domains": len(results),
            "results": [],
        }

        for result in results:
            data["results"].append(
                {
                    "domain": result.domain,
                    "status": result.status,
                    "protocol": result.protocol,
                    "status_code": result.status_code,
                    "response_time_ms": result.response_time_ms,
                    "cms": (
                        {
                            "name": result.cms.name if result.cms else None,
                            "version": result.cms.version if result.cms else None,
                            "confidence": result.cms.confidence if result.cms else 0,
                        }
                        if result.cms
                        else None
                    ),
                    "plugins": [
                        {
                            "name": p.name,
                            "version": p.version,
                            "confidence": p.confidence,
                        }
                        for p in result.plugins
                    ],
                    "vulnerabilities": [
                        {
                            "cve": v.cve,
                            "cvss": v.cvss,
                            "severity": v.severity,
                            "description": v.description,
                        }
                        for v in result.vulnerabilities
                    ],
                    "exploited": result.exploited,
                    "shell_url": result.shell_url,
                    "error": result.error,
                    "detection_time": result.detection_time,
                }
            )

        with open(filepath, "w") as f:
            json.dump(data, f, indent=2)
