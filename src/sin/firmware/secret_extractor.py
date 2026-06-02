"""
sin.firmware.secret_extractor
══════════════════════════════
Scans an extracted firmware filesystem for credentials, keys, and secrets.

Design decisions vs. the original:
  - IP addresses removed as a "secret" category — they are not secrets and
    produce hundreds of false positives in every firmware image.
  - Deduplication: identical (type, value, file) tuples are collapsed.
  - Per-finding severity: CRITICAL for private keys/certs, HIGH for hardcoded
    passwords, MEDIUM for API tokens/AWS keys, LOW for generic tokens.
  - Risk level derived from highest-severity finding, not raw count.
  - Entropy filter on generic token matches to cut regex false positives.
  - Binary files skipped cleanly (not silently swallowed).
  - Result schema unchanged — server.py compat preserved.
"""
from __future__ import annotations

import math
import os
import re
from typing import Dict, List, Any

from sin.utils.logger import get_logger

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Pattern catalogue
# Each entry: (type_label, severity, compiled_regex)
# Ordered so higher-severity patterns run first.
# ---------------------------------------------------------------------------
_PATTERNS: List[tuple[str, str, re.Pattern]] = []

def _p(label: str, severity: str, pattern: str, flags: int = re.MULTILINE) -> None:
    _PATTERNS.append((label, severity, re.compile(pattern, flags)))

# CRITICAL — private keys and certificates (exact PEM headers)
_p("PRIVATE_KEY",   "CRITICAL", r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----")
_p("CERTIFICATE",   "CRITICAL", r"-----BEGIN CERTIFICATE-----")

# HIGH — hardcoded credentials
_p("HARDCODED_PASSWORD", "HIGH",
   r"""(?:password|passwd|pwd|pass)\s*[=:]\s*['"]?([^\s'"]{4,64})""",
   re.IGNORECASE | re.MULTILINE)
_p("HARDCODED_PASSWORD", "HIGH",
   r"""(?:root|admin):[^:\n]{1,64}:[0-9]+:[0-9]+:""")          # /etc/passwd style
_p("SHADOW_HASH",   "HIGH",
   r"""root:\$[156y]\$[^\s:]{8,}""")                            # /etc/shadow hash

# MEDIUM — cloud / API credentials
_p("AWS_ACCESS_KEY",  "MEDIUM", r"AKIA[0-9A-Z]{16}")
_p("AWS_SECRET_KEY",  "MEDIUM", r"(?:aws_secret|AWS_SECRET_ACCESS_KEY)\s*[=:]\s*[A-Za-z0-9/+]{40}")
_p("GENERIC_API_KEY", "MEDIUM",
   r"""(?:api_key|apikey|api_secret|secret_key|access_token|auth_token)\s*[=:]\s*['"]?([A-Za-z0-9_\-]{16,128})['"]?""",
   re.IGNORECASE | re.MULTILINE)
_p("GITHUB_TOKEN",    "MEDIUM", r"gh[pousr]_[A-Za-z0-9]{20,}")
_p("SLACK_TOKEN",     "MEDIUM", r"xox[baprs]-[0-9A-Za-z\-]{10,}")

# LOW — seeds/salts/nonces that are interesting but lower urgency
_p("HARDCODED_SECRET", "LOW",
   r"""(?:secret|seed|salt|nonce|encryption_key)\s*[=:]\s*['"]?([A-Za-z0-9_+/=]{8,64})['"]?""",
   re.IGNORECASE | re.MULTILINE)

# ---------------------------------------------------------------------------
# Risk roll-up
# ---------------------------------------------------------------------------
_SEVERITY_RANK = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "LOW": 0}
_RANK_LEVEL    = {3: "CRITICAL", 2: "HIGH", 1: "MEDIUM", 0: "LOW"}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
_SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico",
    ".mp4", ".avi", ".mkv", ".mov",
    ".gz", ".xz", ".bz2", ".zip", ".tar", ".elf", ".so", ".ko",
    ".o", ".a", ".bin", ".img", ".squashfs", ".jffs2",
    ".ttf", ".otf", ".woff", ".woff2",
}
_MAX_FILE_BYTES = 5 * 1024 * 1024   # skip files > 5 MB


def _shannon_entropy(s: str) -> float:
    """Shannon entropy of a string — used to filter low-entropy regex matches."""
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((v / n) * math.log2(v / n) for v in freq.values())


def _extract_capture(match: re.Match) -> str:
    """Return first capture group if present, else full match."""
    try:
        g = match.group(1)
        return g if g else match.group(0)
    except IndexError:
        return match.group(0)


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------
class SecretExtractor:
    """Walk an extracted firmware directory and surface credential findings."""

    def scan(self, extracted_path: str) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "secrets_found":      [],
            "risk_level":         "LOW",
            "file_count_scanned": 0,
            "error":              None,
        }

        if not os.path.isdir(extracted_path):
            result["error"] = f"Directory not found: {extracted_path}"
            logger.error(result["error"])
            return result

        seen:        set[tuple[str, str, str]] = set()   # dedup key
        findings:    List[Dict[str, str]]      = []
        file_count:  int                       = 0
        top_rank:    int                       = -1

        for root, _dirs, files in os.walk(extracted_path):
            for fname in files:
                fpath = os.path.join(root, fname)
                ext   = os.path.splitext(fname)[1].lower()

                if ext in _SKIP_EXTENSIONS:
                    continue
                try:
                    if os.path.getsize(fpath) > _MAX_FILE_BYTES:
                        continue
                except OSError:
                    continue

                try:
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as fh:
                        content = fh.read()
                except OSError:
                    continue

                file_count += 1
                rel_path = os.path.relpath(fpath, extracted_path)

                for label, severity, pattern in _PATTERNS:
                    for match in pattern.finditer(content):
                        value = _extract_capture(match).strip()

                        # Entropy guard for generic/API key patterns
                        if label in {"GENERIC_API_KEY", "HARDCODED_SECRET"}:
                            if _shannon_entropy(value) < 3.0:
                                continue

                        # Dedup
                        key = (label, value, rel_path)
                        if key in seen:
                            continue
                        seen.add(key)

                        rank = _SEVERITY_RANK[severity]
                        if rank > top_rank:
                            top_rank = rank

                        findings.append({
                            "type":     label,
                            "severity": severity,
                            "value":    value[:120],    # truncate long keys
                            "file":     rel_path,
                        })

        result["secrets_found"]      = findings
        result["file_count_scanned"] = file_count
        result["risk_level"] = (
            _RANK_LEVEL[top_rank] if top_rank >= 0 else "LOW"
        )

        logger.info(
            f"secret_extractor | path={extracted_path} "
            f"files={file_count} findings={len(findings)} "
            f"risk={result['risk_level']}"
        )
        return result
