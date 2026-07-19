"""
SQLite reporter
"""

import sqlite3
from typing import List
from pathlib import Path
from reporters.base import BaseReporter
from core.models import ScanResult


class SQLiteReporter(BaseReporter):
    """Export results to SQLite database"""

    async def export(self, results: List[ScanResult]) -> None:
        filepath = self.output_dir / "report.db"

        conn = sqlite3.connect(filepath)
        cursor = conn.cursor()

        # Create tables
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS domains (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT,
                status TEXT,
                protocol TEXT,
                status_code INTEGER,
                response_time_ms INTEGER,
                cms TEXT,
                cms_version TEXT,
                cms_confidence INTEGER,
                exploited INTEGER,
                shell_url TEXT,
                error TEXT,
                detection_time TEXT
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS plugins (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain_id INTEGER,
                name TEXT,
                version TEXT,
                confidence INTEGER,
                FOREIGN KEY (domain_id) REFERENCES domains (id)
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                plugin_id INTEGER,
                cve TEXT,
                cvss REAL,
                severity TEXT,
                description TEXT,
                FOREIGN KEY (plugin_id) REFERENCES plugins (id)
            )
        """)

        # Insert data
        for result in results:
            cursor.execute(
                """
                INSERT INTO domains (
                    domain, status, protocol, status_code, response_time_ms,
                    cms, cms_version, cms_confidence,
                    exploited, shell_url, error, detection_time
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    result.domain,
                    result.status,
                    result.protocol,
                    result.status_code,
                    result.response_time_ms,
                    result.cms.name if result.cms else "",
                    result.cms.version if result.cms else "",
                    result.cms.confidence if result.cms else 0,
                    1 if result.exploited else 0,
                    result.shell_url or "",
                    result.error or "",
                    result.detection_time,
                ),
            )

            domain_id = cursor.lastrowid

            for plugin in result.plugins:
                cursor.execute(
                    """
                    INSERT INTO plugins (domain_id, name, version, confidence)
                    VALUES (?, ?, ?, ?)
                """,
                    (domain_id, plugin.name, plugin.version, plugin.confidence),
                )

                plugin_id = cursor.lastrowid

                for vuln in result.vulnerabilities:
                    cursor.execute(
                        """
                        INSERT INTO vulnerabilities (plugin_id, cve, cvss, severity, description)
                        VALUES (?, ?, ?, ?, ?)
                    """,
                        (
                            plugin_id,
                            vuln.cve,
                            vuln.cvss,
                            vuln.severity,
                            vuln.description,
                        ),
                    )

        conn.commit()
        conn.close()
