"""
sin.scanner.nvd_intel
═════════════════════
Live CVE intelligence from NIST NVD API v2.
Queries by vendor keyword, caches results 24h in SQLite,
returns findings compatible with existing vulnerability schema.

Usage (plugs into VulnerabilityAuditor.audit_device):
    from sin.scanner.nvd_intel import NVDIntel
    intel = NVDIntel()
    findings = intel.enrich(manufacturer="Hikvision", open_ports=[80, 554])
"""

import json
import os
import sqlite3
import time
import urllib.request
import urllib.parse
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import List, Dict, Optional

from sin.utils.logger import get_logger

logger = get_logger("sin.scanner.nvd_intel")

# ── Config ────────────────────────────────────────────────────────────────────
NVD_API      = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY  = os.getenv("NVD_API_KEY", "")        # optional but raises rate limit
CACHE_DB     = Path(os.getenv("SIN_DATA_DIR", "/var/lib/sin")) / "nvd_cache.db"
CACHE_TTL_H  = 24                                    # hours before re-fetching
MAX_RESULTS  = 20                                    # CVEs per vendor query
MIN_CVSS     = 6.0                                   # ignore LOW-scored CVEs

# Vendor → NVD keyword map (NVD search works best with brand names)
VENDOR_KEYWORDS: Dict[str, List[str]] = {
    "hikvision":     ["hikvision"],
    "dahua":         ["dahua"],
    "axis":          ["axis communications"],
    "uniview":       ["uniview", "univideo"],
    "hanwha":        ["hanwha", "samsung techwin"],
    "vivotek":       ["vivotek"],
    "reolink":       ["reolink"],
    "amcrest":       ["amcrest"],
    "pelco":         ["pelco"],
    "bosch security":["bosch security"],
    "mikrotik":      ["mikrotik", "routeros"],
    "ubiquiti":      ["ubiquiti", "unifi"],
    "tp-link":       ["tp-link", "tplink"],
    "d-link":        ["d-link", "dlink"],
    "netgear":       ["netgear"],
    "cisco":         ["cisco"],
    "zyxel":         ["zyxel"],
    "tenda":         ["tenda"],
    "raspberry pi":  ["raspberry pi foundation"],
    "synology":      ["synology"],
    "qnap":          ["qnap"],
}

# CVSS score → SIN severity
def _cvss_to_severity(score: float) -> str:
    if score >= 9.0: return "CRITICAL"
    if score >= 7.0: return "HIGH"
    if score >= 4.0: return "MEDIUM"
    return "LOW"


class NVDIntel:
    """
    Live CVE enrichment engine.
    Thread-safe: each call opens/closes its own DB connection.
    """

    def __init__(self):
        CACHE_DB.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()
        logger.info(f"NVD Intel ready | cache={CACHE_DB} | key={'yes' if NVD_API_KEY else 'no (rate-limited)'}")

    # ── Public API ────────────────────────────────────────────────────────────

    def enrich(self, manufacturer: str, open_ports: List[int]) -> List[Dict]:
        """
        Return a list of CVE-based vulnerability dicts for the given device.
        Compatible with existing vulnerabilities[] schema.
        """
        if not manufacturer or manufacturer.lower() in ("unknown", ""):
            return []

        keywords = self._resolve_keywords(manufacturer)
        if not keywords:
            return []

        findings = []
        for kw in keywords:
            cves = self._get_cves(kw)
            for cve in cves:
                score = cve.get("cvss_score", 0)
                if score < MIN_CVSS:
                    continue
                findings.append({
                    "severity":    _cvss_to_severity(score),
                    "type":        "NVD CVE — " + cve.get("cwe", "Vulnerability"),
                    "description": cve.get("description", ""),
                    "cve":         cve.get("cve_id", ""),
                    "confidence":  min(0.75, score / 10),
                    "engine":      "nvd",
                    "cvss":        score,
                    "published":   cve.get("published", ""),
                })

        # Deduplicate by CVE ID and sort by CVSS descending
        seen = set()
        unique = []
        for f in findings:
            if f["cve"] not in seen:
                seen.add(f["cve"])
                unique.append(f)
        unique.sort(key=lambda x: x.get("cvss", 0), reverse=True)

        logger.info(f"NVD enrichment: {manufacturer} → {len(unique)} CVEs")
        return unique[:10]   # cap at 10 per device

    def prefetch_all_vendors(self) -> None:
        """
        Background task: pre-warm the cache for all known IoT vendors.
        Call this from a Celery beat task.
        """
        delay = 0.6 if NVD_API_KEY else 6.1  # Intelligent delay
	for vendor_key, keywords in VENDOR_KEYWORDS.items():
            for kw in keywords:
                try:
                    self._get_cves(kw)
                    time.sleep(delay)   # NVD rate limit: ~10 req/min without key
                except Exception as e:
                    logger.error(f"Prefetch failed for {kw}: {e}")

    # ── Cache layer ───────────────────────────────────────────────────────────

    def _get_cves(self, keyword: str) -> List[Dict]:
        cached = self._cache_get(keyword)
        if cached is not None:
            return cached
        fetched = self._fetch_nvd(keyword)
        self._cache_set(keyword, fetched)
        return fetched

    def _fetch_nvd(self, keyword: str) -> List[Dict]:
        """Query NVD API and parse results into our schema."""
        params = {
            "keywordSearch":  keyword,
            "resultsPerPage": MAX_RESULTS,
        }
        url = f"{NVD_API}?{urllib.parse.urlencode(params)}"
        headers = {"User-Agent": "SIN-Scanner/3.0"}
        if NVD_API_KEY:
            headers["apiKey"] = NVD_API_KEY

        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode())
        except Exception as e:
            logger.error(f"NVD fetch failed for '{keyword}': {e}")
            return []

        results = []
        for item in data.get("vulnerabilities", []):
            cve_data = item.get("cve", {})
            cve_id   = cve_data.get("id", "")

            # Description (English)
            desc = ""
            for d in cve_data.get("descriptions", []):
                if d.get("lang") == "en":
                    desc = d.get("value", "")[:500]
                    break

            # Best CVSS score available
            score = 0.0
            metrics = cve_data.get("metrics", {})
            for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                metric_list = metrics.get(metric_key, [])
                if metric_list:
                    try:
                        score = float(
                            metric_list[0]["cvssData"]["baseScore"]
                        )
                    except (KeyError, TypeError, ValueError):
                        pass
                    if score > 0:
                        break

            # Primary CWE
            cwe = ""
            for w in cve_data.get("weaknesses", []):
                for wd in w.get("description", []):
                    if wd.get("lang") == "en":
                        cwe = wd.get("value", "")
                        break
                if cwe:
                    break

            published = cve_data.get("published", "")[:10]

            if score >= MIN_CVSS and desc:
                results.append({
                    "cve_id":      cve_id,
                    "description": desc,
                    "cvss_score":  score,
                    "cwe":         cwe,
                    "published":   published,
                })

        logger.debug(f"NVD '{keyword}': {len(results)} CVEs (score≥{MIN_CVSS})")
        return results

    # ── Keyword resolution ────────────────────────────────────────────────────

    @staticmethod
    def _resolve_keywords(manufacturer: str) -> List[str]:
        mfr_lower = manufacturer.lower()
        for key, keywords in VENDOR_KEYWORDS.items():
            if key in mfr_lower or mfr_lower in key:
                return keywords[:1]   # use first keyword only to conserve API calls
        return []

    # ── SQLite cache ──────────────────────────────────────────────────────────

    def _init_db(self) -> None:
        with sqlite3.connect(CACHE_DB) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS nvd_cache (
                    keyword TEXT PRIMARY KEY,
                    data    TEXT NOT NULL,
                    fetched INTEGER NOT NULL
                )
            """)
            conn.commit()

    def _cache_get(self, keyword: str) -> Optional[List[Dict]]:
        cutoff = int(time.time()) - CACHE_TTL_H * 3600
        try:
            with sqlite3.connect(CACHE_DB) as conn:
                row = conn.execute(
                    "SELECT data FROM nvd_cache WHERE keyword=? AND fetched>?",
                    (keyword, cutoff)
                ).fetchone()
            if row:
                return json.loads(row[0])
        except Exception as e:
            logger.error(f"Cache read error: {e}")
        return None

    def _cache_set(self, keyword: str, data: List[Dict]) -> None:
        try:
            with sqlite3.connect(CACHE_DB) as conn:
                conn.execute(
                    "INSERT OR REPLACE INTO nvd_cache VALUES (?,?,?)",
                    (keyword, json.dumps(data), int(time.time()))
                )
                conn.commit()
        except Exception as e:
            logger.error(f"Cache write error: {e}")
