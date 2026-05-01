import requests
import os
import json
import redis
from sin.utils.logger import get_logger

logger = get_logger("sin.response.alert")

class DiscordAlerter:
    """
    Sends security alerts to a configured Discord Webhook with Redis-backed deduplication.
    """
    def __init__(self):
        self.webhook_url = os.getenv("DISCORD_WEBHOOK_URL")
        # Connect to your existing Redis instance
        self.redis_client = redis.Redis(host='redis', port=6379, db=0)
        self.cache_key_prefix = "sin:alerted:"
        # Set expiry to 24 hours (86400 seconds) so you get a reminder once a day if the threat persists
        self.expiry = 86400 

    def send_critical_alert(self, ip: str, vulnerabilities: list):
        if not self.webhook_url:
            return

        # DEDUPLICATION LOGIC:
        # Check if the key exists in Redis for this IP
        redis_key = f"{self.cache_key_prefix}{ip}"
        if self.redis_client.exists(redis_key):
            logger.debug(f"Alert for {ip} suppressed (Redis record found)")
            return

        # Format the vulnerabilities into a message
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
            response = requests.post(self.webhook_url, json=payload, timeout=5)
            if response.status_code == 204: # Discord success code
                # Mark this IP as alerted in Redis with an expiry
                self.redis_client.setex(redis_key, self.expiry, "1")
                logger.info(f"🚨 Sent Discord alert for {ip}")
            else:
                logger.error(f"Discord API returned status {response.status_code}")
        except Exception as e:
            logger.error(f"Failed to send Discord alert: {e}")
