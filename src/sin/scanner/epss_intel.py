"""
sin.scanner.epss_intel
══════════════════════
FIRST EPSS (Exploit Prediction Scoring System) integration.

EPSS is a probability score (0.0–1.0) that a CVE will be exploited in the
next 30 days, updated daily. A score of 0.9 means 90% chance of real-world
exploitation. Combined with CVSS it gives a much sharper risk picture than
either metric alone.

Architecture
─────────────
• Fetches EPSS scores per CVE from api.first.org on demand
• Caches each score in Redis for 6 hours (key: sin:epss:<CVE-ID>)
• Falls back to 0.0 gracefully if Redis or the API is unavailable
• Provides enrich_findings() to annotate a vulnerability list in-place
  and compute a boosted priority score: cvss * (1 + epss * 3)
"""

from __future__ import annotations

import json
import os
import time
import urllib.request
import urllib.parse
from typing import Dict, List, Optional

from sin.utils.logger import get_logger

logger = get_logger("sin.scanner.epss_intel")

EPSS_API     = "https://api.first.org/data/v1/epss"
CACHE_TTL_S  = 6 * 3600   # 6 hours
REDIS_PREFIX = "sin:epss:"
BATCH_SIZE   = 100         # max CVEs per API request


class EPSSIntel:
    """
    FIRST EPSS scoring engine.
    Use the module-level singleton `epss` rather than instantiating directly.
    """

    def __init__(self) -> None:
        self._redis = self._connect_redis()
        logger.info("EPSS Intel ready | redis=%s", "yes" if self._redis else "no (direct fetch)")

    # ── Public API ─────────────────────────────────────────────────────────────

    def get_score(self, cve_id: str) -> float:
        """Return EPSS probability (0.0–1.0) for a single CVE."""
        if not cve_id:
            return 0.0
        cve_id = cve_id.upper()

        cached = self._redis_get(cve_id)
        if cached is not None:
            return cached

        scores = self._fetch_batch([cve_id])
        score = scores.get(cve_id, 0.0)
        self._redis_set(cve_id, score)
        return score

    def get_scores_batch(self, cve_ids: List[str]) -> Dict[str, float]:
        """Return a dict of {CVE-ID: epss_score} for a list of CVEs."""
        if not cve_ids:
            return {}

        cve_ids = [c.upper() for c in cve_ids if c]
        result: Dict[str, float] = {}
        missing: List[str] = []

        for cve_id in cve_ids:
            cached = self._redis_get(cve_id)
            if cached is not None:
                result[cve_id] = cached
            else:
                missing.append(cve_id)

        if missing:
            fetched = self._fetch_batch(missing)
            for cve_id in missing:
                score = fetched.get(cve_id, 0.0)
                result[cve_id] = score
                self._redis_set(cve_id, score)

        return result

    def enrich_findings(self, findings: List[Dict]) -> List[Dict]:
        """
        Annotate each finding with its EPSS score and compute priority_score.

        Adds two fields per finding:
          epss         — float 0.0–1.0 (probability of exploitation in 30 days)
          priority_score — float: cvss * (1 + epss * 3)
                          boosts high-CVSS CVEs that are also likely to be exploited

        Non-destructive: findings without a CVE get epss=0.0, priority_score=cvss.
        """
        cve_ids = [f.get("cve", "") for f in findings if f.get("cve")]
        scores = self.get_scores_batch(cve_ids) if cve_ids else {}

        _sev_cvss = {"CRITICAL": 9.5, "HIGH": 7.5, "MEDIUM": 5.0, "LOW": 2.5}

        for f in findings:
            cve_id = (f.get("cve") or "").upper()
            epss_score = scores.get(cve_id, 0.0)
            cvss = float(f.get("cvss") or _sev_cvss.get(f.get("severity", ""), 5.0))
            priority = cvss * (1.0 + epss_score * 3.0)

            f["epss"] = round(epss_score, 4)
            f["priority_score"] = round(priority, 2)

            if epss_score >= 0.5:
                logger.warning(
                    "⚡ High EPSS: %s epss=%.3f priority=%.1f",
                    cve_id, epss_score, priority
                )

        return findings

    # ── Fetch layer ────────────────────────────────────────────────────────────

    def _fetch_batch(self, cve_ids: List[str]) -> Dict[str, float]:
        """Fetch EPSS scores for up to BATCH_SIZE CVEs in one API call."""
        results: Dict[str, float] = {}
        for i in range(0, len(cve_ids), BATCH_SIZE):
            batch = cve_ids[i:i + BATCH_SIZE]
            results.update(self._fetch_page(batch))
        return results

    def _fetch_page(self, cve_ids: List[str]) -> Dict[str, float]:
        cve_param = ",".join(cve_ids)
        url = f"{EPSS_API}?{urllib.parse.urlencode({'cve': cve_param})}"
        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "SIN-Scanner/3.0", "Accept": "application/json"}
            )
            with urllib.request.urlopen(req, timeout=8) as resp:
                data = json.loads(resp.read().decode())

            scores: Dict[str, float] = {}
            for entry in data.get("data", []):
                cve_id = entry.get("cve", "").upper()
                try:
                    scores[cve_id] = float(entry.get("epss", 0.0))
                except (TypeError, ValueError):
                    scores[cve_id] = 0.0

            logger.debug("EPSS fetched %d/%d scores", len(scores), len(cve_ids))
            return scores

        except Exception as exc:
            logger.warning("EPSS fetch failed: %s — defaulting to 0.0", exc)
            return {}

    # ── Redis helpers ──────────────────────────────────────────────────────────

    def _redis_get(self, cve_id: str) -> Optional[float]:
        if not self._redis:
            return None
        try:
            val = self._redis.get(REDIS_PREFIX + cve_id)
            return float(val) if val is not None else None
        except Exception:
            return None

    def _redis_set(self, cve_id: str, score: float) -> None:
        if not self._redis:
            return
        try:
            self._redis.setex(REDIS_PREFIX + cve_id, CACHE_TTL_S, str(score))
        except Exception as exc:
            logger.debug("EPSS Redis write failed: %s", exc)

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
            logger.warning("EPSS: Redis unavailable — scores will be fetched per-request")
            return None


# ── Module-level singleton ─────────────────────────────────────────────────────
epss = EPSSIntel()
