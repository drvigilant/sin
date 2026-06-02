"""
sin.scanner.cpe_correlator
═══════════════════════════
CPE 2.3 string builder + NVD CVE correlation engine.

Replaces the fuzzy vendor-name CVE matching in audit.py with structured
CPE-based lookups:

  vendor + product + version  →  CPE 2.3 string
                              →  NVD API query
                              →  confirmed CVE list with CVSS scores

Why CPE matters
───────────────
Old approach:  "hikvision" in vendor  →  fire CVE-2021-36260 regardless
New approach:  cpe:2.3:o:hikvision:ds-2cd2143g2-i_firmware:v2.840.00
               →  NVD confirms CVE-2021-36260 affects this exact version
               →  CVE-2017-7921 does NOT affect V5.6.x → not fired

Architecture
────────────
1.  CPEBuilder     — maps (vendor, product, firmware) to CPE 2.3 string
                    using a vendor normalisation table + heuristics

2.  NVDClient      — queries NVD API 2.0 with the CPE string,
                    caches results in Redis (TTL 24h),
                    falls back to the embedded IoT CVE seed on failure

3.  CPECorrelator  — public interface:
                    correlate(device_data) → List[finding_dict]
                    each finding is already in the audit.py vulnerability format

NVD API key
───────────
Set SIN_NVD_API_KEY env var for 50 req/30s (vs 5 req/30s unauthenticated).
The module rate-limits itself and works fine without a key.

Offline seed
────────────
The embedded IoT CVE database is always consulted first.  NVD is additive.
This ensures the module works air-gapped and during NVD maintenance windows.
"""
from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

from sin.utils.logger import get_logger

logger = get_logger("sin.scanner.cpe_correlator")

# ── NVD API ────────────────────────────────────────────────────────────────
_NVD_API      = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_NVD_CACHE_TTL = 24 * 3600        # 24 hours
_NVD_RATE_S    = 0.6              # 1 req/0.6s unauthenticated → ~5/30s
_NVD_RATE_KEY  = float(os.getenv("SIN_NVD_API_KEY", "") and 0.06 or _NVD_RATE_S)
_REDIS_PREFIX  = "sin:cpe:"
_TIMEOUT       = 10

# ── Vendor normalisation table ────────────────────────────────────────────
# Maps lowercase brand variants → CPE vendor string (NVD format)
_VENDOR_NORM: Dict[str, str] = {
    # Hikvision
    "hikvision": "hikvision",
    "hkvision":  "hikvision",
    "hik":       "hikvision",
    # Dahua
    "dahua":     "dahua",
    "dahua technology": "dahua",
    # Xiongmai / generic DVR OEM
    "xiongmai":  "xiongmai",
    "xiongmai-oem": "xiongmai",
    "securus":   "xiongmai",   # Securus is rebadged Xiongmai
    "sricam":    "xiongmai",
    # Axis
    "axis":      "axis",
    "axis communications": "axis",
    # Uniview
    "uniview":   "uniview",
    "unv":       "uniview",
    # Hanwha / Samsung Techwin
    "hanwha":    "hanwha",
    "samsung techwin": "hanwha",
    "wisenet":   "hanwha",
    # Reolink
    "reolink":   "reolink",
    # TP-Link / Tapo
    "tp-link":   "tp-link",
    "tplink":    "tp-link",
    "tapo":      "tp-link",
    # Ubiquiti
    "ubiquiti":  "ubiquiti",
    "ubnt":      "ubiquiti",
    # Zyxel
    "zyxel":     "zyxel",
    # Cisco / Meraki
    "cisco":     "cisco",
    "meraki":    "cisco",
    # Fortinet
    "fortinet":  "fortinet",
    "fortigate": "fortinet",
    # Mikrotik
    "mikrotik":  "mikrotik",
    # D-Link
    "d-link":    "d-link",
    "dlink":     "d-link",
    # Netgear
    "netgear":   "netgear",
}

# ── Offline IoT CVE seed database ─────────────────────────────────────────
# Each entry: CPE vendor prefix (or "*" for any) → list of findings
# version_affected: None = all versions; callable = version_check(fw) → bool
#
# This is consulted BEFORE NVD and is always available offline.
# Entries here have been manually verified against NVD and CISA KEV.

def _hik_pre_5_5_0(fw: str) -> bool:
    """Return True if fw is a Hikvision version before 5.5.0 (affected by CVE-2017-7921)."""
    m = re.search(r"[Vv]?(\d+)\.(\d+)", fw or "")
    if not m:
        return True   # unknown version = assume affected (conservative)
    major, minor = int(m.group(1)), int(m.group(2))
    return (major, minor) < (5, 5)

def _hik_pre_5_6_0(fw: str) -> bool:
    """Hikvision before 5.6.0 (affected by CVE-2021-36260)."""
    m = re.search(r"[Vv]?(\d+)\.(\d+)", fw or "")
    if not m:
        return True
    major, minor = int(m.group(1)), int(m.group(2))
    return (major, minor) < (5, 6)

_SEED_DB: List[Dict[str, Any]] = [
    # ── Hikvision ──────────────────────────────────────────────────────────
    {
        "vendor":   "hikvision",
        "product":  "*",
        "cve":      "CVE-2021-36260",
        "cvss":     9.8,
        "severity": "CRITICAL",
        "in_kev":   True,
        "type":     "Remote Code Execution",
        "version_affected": _hik_pre_5_6_0,
        "description": (
            "Hikvision command injection via web server parameter (CVE-2021-36260). "
            "Unauthenticated RCE — attacker sends a crafted message to the web server "
            "and gains full device control. CISA KEV confirmed; actively exploited by "
            "APT41 and opportunistic botnets. Patch: firmware ≥ V5.5.800."
        ),
    },
    {
        "vendor":   "hikvision",
        "product":  "*",
        "cve":      "CVE-2017-7921",
        "cvss":     8.8,
        "severity": "HIGH",
        "in_kev":   True,
        "type":     "Authentication Bypass",
        "version_affected": _hik_pre_5_5_0,
        "description": (
            "Hikvision improper authentication (CVE-2017-7921). "
            "A crafted URL bypasses authentication on ISAPI endpoints, "
            "allowing unauthenticated snapshot capture, config dump, and user enumeration. "
            "Used by Iranian threat actors (CISA AA22-257A). Patch: firmware ≥ V5.4.5."
        ),
    },
    # ── Dahua ──────────────────────────────────────────────────────────────
    {
        "vendor":   "dahua",
        "product":  "*",
        "cve":      "CVE-2021-33044",
        "cvss":     9.8,
        "severity": "CRITICAL",
        "in_kev":   True,
        "type":     "Authentication Bypass",
        "version_affected": None,   # all versions prior to 2021-10 patch
        "description": (
            "Dahua authentication bypass (CVE-2021-33044). "
            "A specially crafted login packet bypasses authentication on the SDK port (37777), "
            "enabling credential extraction and device takeover without knowing the password. "
            "Affects NVR, DVR, and IP camera product lines."
        ),
    },
    {
        "vendor":   "dahua",
        "product":  "*",
        "cve":      "CVE-2021-33045",
        "cvss":     9.8,
        "severity": "CRITICAL",
        "in_kev":   True,
        "type":     "Authentication Bypass",
        "version_affected": None,
        "description": (
            "Dahua authentication bypass variant (CVE-2021-33045). "
            "Similar to CVE-2021-33044 but affects a different code path in the "
            "authentication flow. Both CVEs should be remediated together."
        ),
    },
    # ── Xiongmai / generic DVR OEM ─────────────────────────────────────────
    {
        "vendor":   "xiongmai",
        "product":  "*",
        "cve":      "CVE-2018-10088",
        "cvss":     9.8,
        "severity": "CRITICAL",
        "in_kev":   True,
        "type":     "Remote Code Execution",
        "version_affected": None,
        "description": (
            "Xiongmai DVR/NVR unauthenticated RCE via port 34567 (CVE-2018-10088). "
            "The NetSurveillance protocol on port 34567 allows arbitrary command execution "
            "without authentication. Exploited by Mirai variants to recruit cameras into botnets."
        ),
    },
    # ── Zyxel ──────────────────────────────────────────────────────────────
    {
        "vendor":   "zyxel",
        "product":  "*",
        "cve":      "CVE-2022-30525",
        "cvss":     9.8,
        "severity": "CRITICAL",
        "in_kev":   True,
        "type":     "Remote Code Execution",
        "version_affected": None,
        "description": (
            "Zyxel firewall OS command injection (CVE-2022-30525). "
            "Unauthenticated RCE via the administrative HTTP interface. "
            "Affected: USG FLEX, ATP, VPN series running ZLD 5.00–5.21 Patch 1."
        ),
    },
    {
        "vendor":   "zyxel",
        "product":  "*",
        "cve":      "CVE-2023-28771",
        "cvss":     9.8,
        "severity": "CRITICAL",
        "in_kev":   True,
        "type":     "Remote Code Execution",
        "version_affected": None,
        "description": (
            "Zyxel OS command injection via IKEv2 (CVE-2023-28771). "
            "Pre-authentication RCE on VPN/firewall devices. "
            "Exploited by Mirai botnet within days of disclosure."
        ),
    },
    # ── Cisco ──────────────────────────────────────────────────────────────
    {
        "vendor":   "cisco",
        "product":  "*",
        "cve":      "CVE-2023-20198",
        "cvss":     10.0,
        "severity": "CRITICAL",
        "in_kev":   True,
        "type":     "Privilege Escalation",
        "version_affected": None,
        "description": (
            "Cisco IOS XE web UI privilege escalation (CVE-2023-20198). "
            "Unauthenticated attacker can create a local account with privilege level 15. "
            "Exploited in the wild to implant persistent backdoors."
        ),
    },
    # ── Fortinet ───────────────────────────────────────────────────────────
    {
        "vendor":   "fortinet",
        "product":  "*",
        "cve":      "CVE-2022-40684",
        "cvss":     9.8,
        "severity": "CRITICAL",
        "in_kev":   True,
        "type":     "Authentication Bypass",
        "version_affected": None,
        "description": (
            "Fortinet FortiOS/FortiProxy authentication bypass (CVE-2022-40684). "
            "HTTP request with crafted headers bypasses authentication on the "
            "administrative interface. Exploited within 3 days of public disclosure."
        ),
    },
    # ── D-Link ─────────────────────────────────────────────────────────────
    {
        "vendor":   "d-link",
        "product":  "*",
        "cve":      "CVE-2019-16920",
        "cvss":     9.8,
        "severity": "CRITICAL",
        "in_kev":   False,
        "type":     "Remote Code Execution",
        "version_affected": None,
        "description": (
            "D-Link router unauthenticated RCE via apply_sec.cgi (CVE-2019-16920). "
            "Allows unauthenticated command injection through the web interface. "
            "Affects multiple D-Link router models."
        ),
    },
    # ── Reolink ────────────────────────────────────────────────────────────
    {
        "vendor":   "reolink",
        "product":  "*",
        "cve":      "CVE-2023-45261",
        "cvss":     7.5,
        "severity": "HIGH",
        "in_kev":   False,
        "type":     "Information Disclosure",
        "version_affected": None,
        "description": (
            "Reolink camera information disclosure (CVE-2023-45261). "
            "The RTMP/RTSP stream can be accessed without authentication on "
            "certain firmware versions, exposing live video."
        ),
    },
]


# ── CPE 2.3 builder ───────────────────────────────────────────────────────

class CPEBuilder:
    """Build CPE 2.3 WFN strings from device_data fields."""

    @staticmethod
    def build(
        vendor:   str,
        product:  str = "*",
        version:  str = "*",
        target_hw: str = "*",
    ) -> str:
        """
        Return a CPE 2.3 formatted string.
        cpe:2.3:a|h|o:vendor:product:version:*:*:*:*:*:*:*
        """
        v   = CPEBuilder._norm_component(vendor)
        p   = CPEBuilder._norm_component(product)
        ver = CPEBuilder._norm_version(version)
        return f"cpe:2.3:*:{v}:{p}:{ver}:*:*:*:*:*:*:*"

    @staticmethod
    def _norm_component(s: str) -> str:
        if not s or s in ("*", "-"):
            return "*"
        # CPE 2.3 uses lowercase, spaces → underscores, strip special chars
        s = s.lower().strip()
        s = re.sub(r"[^a-z0-9_\-\.]", "_", s)
        s = re.sub(r"_+", "_", s).strip("_")
        return s or "*"

    @staticmethod
    def _norm_version(v: str) -> str:
        if not v or v in ("*", "-", "unknown", "Unknown"):
            return "*"
        # Strip leading V/v
        v = v.strip().lstrip("Vv")
        return CPEBuilder._norm_component(v) or "*"

    @staticmethod
    def from_device(device_data: Dict[str, Any]) -> Tuple[str, str, str, str]:
        """
        Extract (vendor_cpe, product_cpe, version_cpe, cpe_string) from device_data.
        Uses vendor normalisation table to produce clean CPE vendor strings.
        """
        raw_vendor = (
            device_data.get("vendor")
            or device_data.get("manufacturer")
            or ""
        ).lower().strip()

        # Normalise vendor
        vendor_cpe = "*"
        for key, norm in _VENDOR_NORM.items():
            if key in raw_vendor:
                vendor_cpe = norm
                break

        product_cpe = CPEBuilder._norm_component(
            device_data.get("model") or "*"
        )
        version_cpe = CPEBuilder._norm_version(
            device_data.get("firmware") or "*"
        )

        cpe_str = CPEBuilder.build(vendor_cpe, product_cpe, version_cpe)
        return vendor_cpe, product_cpe, version_cpe, cpe_str


# ── NVD API client ────────────────────────────────────────────────────────

class NVDClient:
    """Query NVD CVE API 2.0 with CPE strings. Redis-cached, rate-limited."""

    def __init__(self) -> None:
        self._redis    = self._connect_redis()
        self._last_req = 0.0
        self._api_key  = os.getenv("SIN_NVD_API_KEY", "")

    def query_cpe(self, cpe_string: str) -> List[Dict[str, Any]]:
        """
        Return list of NVD CVE dicts matching cpe_string.
        Each dict: {cve, cvss, severity, description}
        Returns [] on network failure — offline seed covers the gap.
        """
        if "*:*:*" in cpe_string.split(":")[5:]:
            # CPE with no specific product/version — skip NVD, use seed only
            return []

        cache_key = _REDIS_PREFIX + "nvd:" + urllib.parse.quote(cpe_string, safe="")
        cached = self._redis_get(cache_key)
        if cached is not None:
            return cached

        results = self._fetch(cpe_string)
        self._redis_set(cache_key, results, _NVD_CACHE_TTL)
        return results

    def _fetch(self, cpe_string: str) -> List[Dict[str, Any]]:
        # Rate limiting
        gap = _NVD_RATE_KEY - (time.time() - self._last_req)
        if gap > 0:
            time.sleep(gap)
        self._last_req = time.time()

        params = {"cpeName": cpe_string, "resultsPerPage": "20"}
        if self._api_key:
            params["apiKey"] = self._api_key

        url = f"{_NVD_API}?{urllib.parse.urlencode(params)}"
        headers = {"User-Agent": "SIN-Scanner/4.0", "Accept": "application/json"}
        if self._api_key:
            headers["apiKey"] = self._api_key

        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
                data = json.loads(resp.read().decode())
            return self._parse_nvd_response(data)
        except urllib.error.HTTPError as e:
            if e.code == 403:
                logger.warning("[nvd] 403 — check SIN_NVD_API_KEY")
            elif e.code == 404:
                pass   # no CVEs for this CPE — normal
            else:
                logger.debug(f"[nvd] HTTP {e.code} for {cpe_string}")
        except Exception as e:
            logger.debug(f"[nvd] fetch failed: {e}")
        return []

    @staticmethod
    def _parse_nvd_response(data: Dict) -> List[Dict[str, Any]]:
        results = []
        for item in data.get("vulnerabilities", []):
            cve_obj = item.get("cve", {})
            cve_id  = cve_obj.get("id", "")
            if not cve_id:
                continue

            # Extract CVSS score (prefer v3.1, fall back to v2)
            cvss   = 0.0
            severity = "MEDIUM"
            metrics = cve_obj.get("metrics", {})
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                entries = metrics.get(key, [])
                if entries:
                    try:
                        cvss_data = entries[0].get("cvssData", {})
                        cvss      = float(cvss_data.get("baseScore", 0.0))
                        severity  = cvss_data.get("baseSeverity", "MEDIUM").upper()
                    except (KeyError, TypeError, ValueError):
                        pass
                    break

            # Description (English preferred)
            desc = ""
            for d in cve_obj.get("descriptions", []):
                if d.get("lang") == "en":
                    desc = d.get("value", "")
                    break

            results.append({
                "cve":         cve_id,
                "cvss":        cvss,
                "severity":    severity if severity in {"CRITICAL","HIGH","MEDIUM","LOW"} else "MEDIUM",
                "description": desc[:400],
                "source":      "nvd",
            })
        return results

    def _redis_get(self, key: str) -> Optional[List]:
        if not self._redis:
            return None
        try:
            val = self._redis.get(key)
            return json.loads(val) if val else None
        except Exception:
            return None

    def _redis_set(self, key: str, value: Any, ttl: int) -> None:
        if not self._redis:
            return
        try:
            self._redis.setex(key, ttl, json.dumps(value))
        except Exception:
            pass

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
            return None


# ── Main correlator ───────────────────────────────────────────────────────

class CPECorrelator:
    """
    Public interface. Call correlate(device_data) to get a findings list.

    device_data keys used:
      vendor / manufacturer  — device brand
      model                  — product model
      firmware               — firmware version string
      open_ports             — List[int] (used for port-gated CVEs)

    Returns List[Dict] — each dict is in audit.py vulnerability format:
      {type, cve, severity, cvss, description, port, in_kev, source}
    """

    def __init__(self) -> None:
        self._nvd    = NVDClient()
        self._builder = CPEBuilder()

    def correlate(self, device_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        vendor_cpe, product_cpe, version_cpe, cpe_str = \
            CPEBuilder.from_device(device_data)

        if vendor_cpe == "*":
            # No recognisable vendor — can't do meaningful CPE correlation
            logger.debug(f"[cpe] no vendor match for {device_data.get('ip_address','?')}")
            return []

        logger.debug(f"[cpe] {device_data.get('ip_address','?')} → {cpe_str}")

        firmware    = device_data.get("firmware", "") or ""
        open_ports  = set(device_data.get("open_ports") or [])
        findings: List[Dict[str, Any]] = []
        seen_cves:  set[str] = set()

        # 1. Offline seed — always consulted first
        for entry in _SEED_DB:
            if entry["vendor"] != vendor_cpe and entry["vendor"] != "*":
                continue

            # Version check
            vc = entry.get("version_affected")
            if callable(vc) and not vc(firmware):
                continue   # firmware version not in affected range

            cve = entry["cve"]
            if cve in seen_cves:
                continue
            seen_cves.add(cve)

            findings.append({
                "type":        entry["type"],
                "cve":         cve,
                "severity":    entry["severity"],
                "cvss":        entry["cvss"],
                "description": entry["description"],
                "port":        None,
                "in_kev":      entry.get("in_kev", False),
                "source":      "cpe_seed",
                "cpe":         cpe_str,
            })

        # 2. NVD live query (additive — only fires when product/version known)
        if product_cpe != "*" or version_cpe != "*":
            nvd_results = self._nvd.query_cpe(cpe_str)
            for r in nvd_results:
                cve = r["cve"]
                if cve in seen_cves:
                    continue
                seen_cves.add(cve)
                findings.append({
                    "type":        r.get("severity", "MEDIUM") + " Vulnerability",
                    "cve":         cve,
                    "severity":    r["severity"],
                    "cvss":        r["cvss"],
                    "description": r["description"],
                    "port":        None,
                    "in_kev":      False,   # KEV module annotates this separately
                    "source":      "nvd",
                    "cpe":         cpe_str,
                })

        logger.info(
            f"[cpe] {device_data.get('ip_address','?')} vendor={vendor_cpe} "
            f"product={product_cpe} version={version_cpe} "
            f"findings={len(findings)}"
        )
        return findings


# ── Module-level singleton ─────────────────────────────────────────────────
cpe_correlator = CPECorrelator()
