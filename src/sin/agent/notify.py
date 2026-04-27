"""
sin.agent.notify
Sends threat alerts via Telegram and/or webhook.
Set TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID in .env to enable.
"""
import os
import json
import urllib.request
from sin.utils.logger import get_logger

logger = get_logger("sin.agent.notify")

TELEGRAM_TOKEN  = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT   = os.getenv("TELEGRAM_CHAT_ID", "")
WEBHOOK_URL     = os.getenv("WEBHOOK_URL", "")


class NotificationRouter:

    def send_threat(self, verdict, host: dict) -> None:
        ip  = host.get("ip_address", "?")
        mfr = host.get("manufacturer", "Unknown")
        msg = (
            f"🚨 SIN ALERT\n"
            f"IP: {ip}\n"
            f"Vendor: {mfr}\n"
            f"Severity: {verdict.severity}\n"
            f"Confidence: {verdict.confidence:.0%}\n"
            f"Reasons:\n" +
            "\n".join(f"  • {r}" for r in verdict.reasons[:5])
        )
        self._telegram(msg)
        self._webhook(verdict, host)

    def _telegram(self, text: str) -> None:
        if not TELEGRAM_TOKEN or not TELEGRAM_CHAT:
            return
        try:
            url  = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
            data = json.dumps({"chat_id": TELEGRAM_CHAT, "text": text}).encode()
            req  = urllib.request.Request(url, data=data,
                                          headers={"Content-Type": "application/json"})
            urllib.request.urlopen(req, timeout=5)
            logger.info("Telegram alert sent")
        except Exception as e:
            logger.error(f"Telegram failed: {e}")

    def _webhook(self, verdict, host: dict) -> None:
        if not WEBHOOK_URL:
            return
        try:
            payload = json.dumps({
                "ip":         host.get("ip_address"),
                "severity":   verdict.severity,
                "confidence": verdict.confidence,
                "reasons":    verdict.reasons,
            }).encode()
            req = urllib.request.Request(WEBHOOK_URL, data=payload,
                                         headers={"Content-Type": "application/json"})
            urllib.request.urlopen(req, timeout=5)
            logger.info("Webhook alert sent")
        except Exception as e:
            logger.error(f"Webhook failed: {e}")
