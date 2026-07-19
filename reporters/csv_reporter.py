"""
CSV reporter
"""

import csv
from typing import List
from pathlib import Path
from reporters.base import BaseReporter
from core.models import ScanResult


class CSVReporter(BaseReporter):
    """Export results to CSV format"""

    async def export(self, results: List[ScanResult]) -> None:
        filepath = self.output_dir / "report.csv"

        with open(filepath, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(
                [
                    "Domain",
                    "Status",
                    "Protocol",
                    "Status_Code",
                    "Response_Time_ms",
                    "CMS",
                    "CMS_Version",
                    "CMS_Confidence",
                    "Plugin",
                    "Plugin_Version",
                    "Plugin_Confidence",
                    "CVE",
                    "CVSS",
                    "Severity",
                    "Exploited",
                    "Shell_URL",
                    "Error",
                ]
            )

            for result in results:
                if result.plugins:
                    for plugin in result.plugins:
                        vuln = (
                            result.vulnerabilities[0]
                            if result.vulnerabilities
                            else None
                        )
                        writer.writerow(
                            [
                                result.domain,
                                result.status,
                                result.protocol,
                                result.status_code,
                                result.response_time_ms,
                                result.cms.name if result.cms else "",
                                result.cms.version if result.cms else "",
                                result.cms.confidence if result.cms else 0,
                                plugin.name,
                                plugin.version,
                                plugin.confidence,
                                vuln.cve if vuln else "",
                                vuln.cvss if vuln else "",
                                vuln.severity if vuln else "",
                                "Yes" if result.exploited else "No",
                                result.shell_url or "",
                                result.error or "",
                            ]
                        )
                else:
                    writer.writerow(
                        [
                            result.domain,
                            result.status,
                            result.protocol,
                            result.status_code,
                            result.response_time_ms,
                            result.cms.name if result.cms else "",
                            result.cms.version if result.cms else "",
                            result.cms.confidence if result.cms else 0,
                            "",
                            "",
                            "",
                            "",
                            "",
                            "",
                            "No",
                            "",
                            result.error or "",
                        ]
                    )
