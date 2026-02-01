import requests
import os
import json
from sin.utils.logger import get_logger

logger = get_logger("sin.response.alert")

class DiscordAlerter:
    """
    Sends security alerts to a configured Discord Webhook.
    """
    def __init__(self):
        self.webhook_url = os.getenv("DISCORD_WEBHOOK_URL")

    def send_critical_alert(self, ip: str, vulnerabilities: list):
        if not self.webhook_url:
            return

        # Format the vulnerabilities into a scary message
        vuln_text = ""
        for v in vulnerabilities:
            vuln_text += f"• **{v['type']}**: {v['description']}\n"

        payload = {
            "username": "SIN Security Overseer",
            "avatar_url": "https://i.imgur.com/4M34hi2.png",
            "embeds": [
                {
                    "title": f"🚨 CRITICAL ALERT: {ip}",
                    "description": f"The Agent detected active vulnerabilities on device `{ip}`.\n\n{vuln_text}",
                    "color": 16711680,  # Red Color
                    "footer": {"text": "Immediate Action Required"}
                }
            ]
        }

        try:
            requests.post(self.webhook_url, json=payload)
            logger.info(f"🚨 Sent Discord alert for {ip}")
        except Exception as e:
            logger.error(f"Failed to send Discord alert: {e}")
