"""
sin.scanner.kev_intel
══════════════════════
CISA Known Exploited Vulnerabilities (KEV) catalog integration.

What this does
───────────────
CISA maintains a live JSON feed of every CVE that has been confirmed
actively exploited in the wild. Cross-referencing a device's CVEs against
the KEV catalog turns "possible risk" into "confirmed active exploit chain."

A CVE in KEV means:
  • Real attackers are using it right now
  • CISA mandates federal agencies patch it within 2 weeks
  • It should be treated as CRITICAL regardless of CVSS score

Architecture
─────────────
• Fetches KEV JSON once every 6 hours, cached in Redis
• Falls back to a hardcoded seed set of IoT-specific KEV entries
  so scoring works even if the network fetch fails
• Thread-safe — single shared instance via module-level singleton
"""

from __future__ import annotations

import json
import os
import time
import urllib.request
from typing import Dict, List, Set

from sin.utils.logger import get_logger

logger = get_logger("sin.scanner.kev_intel")

KEV_URL      = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CACHE_TTL_S  = 6 * 3600   # 6 hours
REDIS_KEY    = "sin:kev:catalog"

# ── Hardcoded IoT/Camera KEV seed (always available offline) ──────────────────
# These are confirmed KEV entries relevant to CCTV/ICS/IoT hardware
_IOT_KEV_SEED: Set[str] = {
    "CVE-2017-7921",   # Hikvision improper auth — backdoor
    "CVE-2021-36260",  # Hikvision command injection — RCE
    "CVE-2021-33044",  # Dahua authentication bypass
    "CVE-2021-33045",  # Dahua authentication bypass variant
    "CVE-2018-10088",  # Xiongmai DVR RCE via port 34567
    "CVE-2018-9995",   # Generic DVR authentication bypass
    "CVE-2019-11510",  # Pulse Secure VPN (often on same network)
    "CVE-2021-26855",  # Microsoft Exchange (ProxyLogon)
    "CVE-2022-30525",  # Zyxel firewall OS command injection
    "CVE-2023-20198",  # Cisco IOS XE privilege escalation
}


class KEVIntel:
    """
    CISA KEV catalog engine.
    Use the module-level singleton `kev` rather than instantiating directly.
    """

    def __init__(self) -> None:
        self._kev_set: Set[str] = set(_IOT_KEV_SEED)
        self._last_fetch: float = 0.0
        self._redis = self._connect_redis()
        self._refresh()

    # ── Public API ─────────────────────────────────────────────────────────────

    def is_in_kev(self, cve_id: str) -> bool:
        """Return True if cve_id is in the CISA KEV catalog."""
        return cve_id.upper() in self._kev_set

    def flag_kev_matches(self, findings: List[Dict]) -> List[Dict]:
        """
        Annotate findings that are in the KEV catalog.
        Sets in_kev=True, upgrades severity to CRITICAL, adds kev_label.
        Non-destructive — findings without a CVE pass through unchanged.
        """
        self._maybe_refresh()
        for f in findings:
            cve = f.get("cve", "")
            if cve and self.is_in_kev(cve):
                f["in_kev"]   = True
                f["severity"] = "CRITICAL"
                f["kev_label"] = (
                    f"[CISA KEV] {cve} is actively exploited in the wild. "
                    "Immediate remediation required."
                )
            else:
                f.setdefault("in_kev", False)
        return findings

    def kev_count(self) -> int:
        return len(self._kev_set)

    # ── Refresh logic ──────────────────────────────────────────────────────────

    def _maybe_refresh(self) -> None:
        if time.time() - self._last_fetch > CACHE_TTL_S:
            self._refresh()

    def _refresh(self) -> None:
        # 1. Try Redis cache first
        if self._redis:
            try:
                cached = self._redis.get(REDIS_KEY)
                if cached:
                    self._kev_set = set(json.loads(cached)) | _IOT_KEV_SEED
                    self._last_fetch = time.time()
                    logger.info(f"KEV loaded from Redis | entries={len(self._kev_set)}")
                    return
            except Exception as exc:
                logger.warning(f"KEV Redis read failed: {exc}")

        # 2. Fetch live from CISA
        self._fetch_live()

    def _fetch_live(self) -> None:
        try:
            req = urllib.request.Request(
                KEV_URL,
                headers={"User-Agent": "SIN-Scanner/3.0"}
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode())

            cve_ids = {
                v["cveID"].upper()
                for v in data.get("vulnerabilities", [])
                if v.get("cveID")
            }
            self._kev_set = cve_ids | _IOT_KEV_SEED
            self._last_fetch = time.time()

            # Cache in Redis for 6h
            if self._redis:
                try:
                    self._redis.setex(
                        REDIS_KEY,
                        CACHE_TTL_S,
                        json.dumps(list(self._kev_set))
                    )
                except Exception as exc:
                    logger.warning(f"KEV Redis write failed: {exc}")

            logger.info(f"KEV refreshed from CISA | entries={len(self._kev_set)}")

        except Exception as exc:
            logger.warning(
                f"KEV live fetch failed: {exc} — "
                f"using seed set ({len(self._kev_set)} entries)"
            )

    def _connect_redis(self):
        try:
            import redis
            r = redis.Redis(
                host=os.getenv("SIN_REDIS_HOST", "redis"),
                port=int(os.getenv("SIN_REDIS_PORT", "6379")),
                password=os.getenv("SIN_REDIS_PASSWORD", ""),
                decode_responses=True,
                socket_connect_timeout=2,
            )
            r.ping()
            return r
        except Exception:
            logger.warning("KEV: Redis unavailable — will fetch directly from CISA")
            return None


# ── Module-level singleton — import this, don't instantiate KEVIntel directly ──
kev = KEVIntel()
