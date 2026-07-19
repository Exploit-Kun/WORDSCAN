"""
Telegram reporter for real-time notifications
"""

import aiohttp
from typing import Optional


class TelegramReporter:
    """Send notifications to Telegram"""

    def __init__(self, bot_token: str, chat_id: str):
        self.bot_token = bot_token
        self.chat_id = chat_id
        self.api_url = f"https://api.telegram.org/bot{bot_token}/sendMessage"

    async def send(self, message: str) -> None:
        """Send message to Telegram"""
        try:
            async with aiohttp.ClientSession() as session:
                data = {"chat_id": self.chat_id, "text": message, "parse_mode": "HTML"}
                await session.post(self.api_url, json=data)
        except:
            pass

    async def send_start(self, total_domains: int, profile: str) -> None:
        """Send scan start notification"""
        message = f"""
🚀 <b>WordScan v8.2 — SCAN STARTED</b>

📊 Total Domains  : {total_domains:,}
⚙️ Profile        : {profile}
🕐 Started        : {__import__('datetime').datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
─────────────────────────────────
📌 You will receive notifications
   for each vulnerable domain found.
"""
        await self.send(message)

    async def send_exploited(
        self, domain: str, plugin: str, version: str, cve: str, shell_url: str
    ) -> None:
        """Send exploited notification"""
        message = f"""
✅ <b>EXPLOITED!</b>

📌 Domain    : {domain}
🔌 Plugin   : {plugin}
📦 Version  : {version}
🆔 CVE      : {cve}
💀 Shell    : <a href="{shell_url}">{shell_url}</a>
🔑 Command  : ?cmd=id
🕐 Time     : {__import__('datetime').datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
─────────────────────────────────
📁 Output   : result/scan_{__import__('datetime').datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}/
"""
        await self.send(message)

    async def send_vulnerable_not_exploitable(
        self, domain: str, plugin: str, version: str, cve: str, reason: str
    ) -> None:
        """Send vulnerable but not exploitable notification"""
        message = f"""
⚠️ <b>VULNERABLE — NOT EXPLOITABLE</b>

📌 Domain    : {domain}
🔌 Plugin   : {plugin}
📦 Version  : {version}
🆔 CVE      : {cve}
❌ Reason   : {reason}
🕐 Time     : {__import__('datetime').datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
─────────────────────────────────
💡 Try: proxy, VPN, or different User-Agent
"""
        await self.send(message)

    async def send_complete(
        self,
        total: int,
        scanned: int,
        vulnerable: int,
        exploited: int,
        dead: int,
        duration: float,
    ) -> None:
        """Send scan complete notification"""
        message = f"""
✅ <b>WORDSCAN v8.2 — SCAN COMPLETED</b>

📊 Total Domains  : {total:,}
🌐 Live          : {scanned - dead:,}
💀 Dead          : {dead:,}
🔴 Vulnerable    : {vulnerable}
💀 Exploited     : {exploited}
⏱ Duration      : {int(duration)}s
─────────────────────────────────
📁 Output        : result/scan_{__import__('datetime').datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}/
📄 Reports       : JSON, CSV, SQLite, HTML
─────────────────────────────────
✅ Scan finished successfully!
"""
        await self.send(message)
