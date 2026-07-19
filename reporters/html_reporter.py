"""
HTML reporter
"""

from typing import List
from pathlib import Path
from datetime import datetime
from reporters.base import BaseReporter
from core.models import ScanResult


class HTMLReporter(BaseReporter):
    """Export results to HTML format"""

    async def export(self, results: List[ScanResult]) -> None:
        filepath = self.output_dir / "report.html"

        # Count statistics
        total = len(results)
        vulnerable = sum(1 for r in results if r.vulnerabilities)
        exploited = sum(1 for r in results if r.exploited)
        live = sum(1 for r in results if r.status == "live")
        dead = sum(1 for r in results if r.status == "dead")

        # Build HTML table rows
        rows = ""
        for r in results:
            if r.plugins:
                for plugin in r.plugins:
                    vuln = r.vulnerabilities[0] if r.vulnerabilities else None
                    status_color = (
                        "danger" if vuln else ("warning" if r.exploited else "success")
                    )
                    rows += f"""
                    <tr class="table-{status_color}">
                        <td>{r.domain}</td>
                        <td>{r.status}</td>
                        <td>{r.protocol}</td>
                        <td>{r.response_time_ms}ms</td>
                        <td>{r.cms.name if r.cms else ''} {r.cms.version if r.cms else ''}</td>
                        <td>{plugin.name} v{plugin.version}</td>
                        <td>{vuln.cve if vuln else '✅'}</td>
                        <td>{vuln.cvss if vuln else ''}</td>
                        <td>{vuln.severity if vuln else ''}</td>
                        <td>{'✅ Yes' if r.exploited else 'No'}</td>
                        <td>{r.shell_url or ''}</td>
                    </tr>
                    """
            else:
                rows += f"""
                <tr>
                    <td>{r.domain}</td>
                    <td>{r.status}</td>
                    <td>{r.protocol}</td>
                    <td>{r.response_time_ms}ms</td>
                    <td>{r.cms.name if r.cms else ''}</td>
                    <td>-</td>
                    <td>-</td>
                    <td>-</td>
                    <td>-</td>
                    <td>No</td>
                    <td></td>
                </tr>
                """

        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>WordScan - Scan Report</title>
            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.2.3/dist/css/bootstrap.min.css" rel="stylesheet">
            <style>
                body {{ padding: 20px; }}
                .badge-exploited {{ background-color: #dc3545; }}
                .badge-vulnerable {{ background-color: #ffc107; }}
                .badge-safe {{ background-color: #198754; }}
            </style>
        </head>
        <body>
            <div class="container-fluid">
                <h1 class="mb-4">🔍 WordScan v8.2 — Scan Report</h1>
                <p class="text-muted">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                
                <div class="row mb-4">
                    <div class="col-md-3">
                        <div class="card">
                            <div class="card-body">
                                <h5 class="card-title">Total Domains</h5>
                                <h2>{total}</h2>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="card border-success">
                            <div class="card-body">
                                <h5 class="card-title text-success">🌐 Live</h5>
                                <h2>{live}</h2>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="card border-danger">
                            <div class="card-body">
                                <h5 class="card-title text-danger">💀 Dead</h5>
                                <h2>{dead}</h2>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="card border-warning">
                            <div class="card-body">
                                <h5 class="card-title text-warning">🔴 Vulnerable</h5>
                                <h2>{vulnerable}</h2>
                            </div>
                        </div>
                    </div>
                </div>
                
                <div class="row mb-4">
                    <div class="col-md-6">
                        <div class="card border-danger">
                            <div class="card-body">
                                <h5 class="card-title text-danger">💀 Exploited</h5>
                                <h2>{exploited}</h2>
                            </div>
                        </div>
                    </div>
                </div>
                
                <h3 class="mt-4">📋 Detailed Results</h3>
                <div class="table-responsive">
                    <table class="table table-striped table-hover">
                        <thead>
                            <tr>
                                <th>Domain</th>
                                <th>Status</th>
                                <th>Protocol</th>
                                <th>Response</th>
                                <th>CMS</th>
                                <th>Plugin</th>
                                <th>CVE</th>
                                <th>CVSS</th>
                                <th>Severity</th>
                                <th>Exploited</th>
                                <th>Shell URL</th>
                            </tr>
                        </thead>
                        <tbody>
                            {rows}
                        </tbody>
                    </table>
                </div>
                
                <footer class="mt-5 text-muted">
                    <hr>
                    <p>Generated by WordScan v8.2</p>
                </footer>
            </div>
        </body>
        </html>
        """

        with open(filepath, "w") as f:
            f.write(html)
