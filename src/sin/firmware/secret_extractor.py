# src/sin/firmware/secret_extractor.py
"""
SecretExtractor — scan extracted firmware filesystem for hardcoded secrets.

Finding types (matches what tests expect):
  PRIVATE_KEY        — RSA/EC/DSA/OpenSSH private key
  SHADOW_HASH        — /etc/shadow crypt hash
  HARDCODED_PASSWORD — password= / passwd= / pwd= style
  AWS_ACCESS_KEY     — AKIA... key
  AWS_SECRET_KEY     — AWS_SECRET_ACCESS_KEY
  GITHUB_TOKEN       — ghp_... token
  GENERIC_API_KEY    — high-entropy api_key/token/secret values
  URL_WITH_CREDS     — http://user:pass@host
  HARDCODED_WIFI     — ssid/wpa_passphrase

Each finding includes: type, severity, value (<=120 chars), file.

Risk level:
  CRITICAL — PRIVATE_KEY or SHADOW_HASH or HARDCODED_PASSWORD
  HIGH     — AWS key, GitHub token, URL_WITH_CREDS
  MEDIUM   — GENERIC_API_KEY or other tokens
  LOW      — nothing found
"""
import math
import os
import re
from typing import Dict, List

from sin.utils.logger import get_logger

logger = get_logger(__name__)

# ── Severity per finding type ─────────────────────────────────────────────────
_SEVERITY: Dict[str, str] = {
    "PRIVATE_KEY":        "CRITICAL",
    "SHADOW_HASH":        "CRITICAL",
    "HARDCODED_PASSWORD": "CRITICAL",
    "AWS_ACCESS_KEY":     "HIGH",
    "AWS_SECRET_KEY":     "HIGH",
    "GITHUB_TOKEN":       "HIGH",
    "URL_WITH_CREDS":     "HIGH",
    "GENERIC_API_KEY":    "MEDIUM",
    "HARDCODED_WIFI":     "MEDIUM",
    "CERTIFICATE":        "LOW",
}

# ── Pattern catalogue ─────────────────────────────────────────────────────────
# Order matters for risk roll-up; more specific patterns first.
_PATTERNS = [
    # Private keys — CRITICAL
    ("PRIVATE_KEY",
     re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", re.IGNORECASE)),

    # Shadow hashes — CRITICAL (relaxed body length to catch test/real hashes)
    ("SHADOW_HASH",
     re.compile(r"\$(?:1|2a|2b|5|6)\$[A-Za-z0-9./]{1,16}\$[A-Za-z0-9./]{8,}", re.MULTILINE)),

    # Hardcoded passwords — CRITICAL
    ("HARDCODED_PASSWORD",
     re.compile(r"(?:password|passwd|pwd)\s*[=:]\s*['\"]?([^\s'\"]{4,})", re.IGNORECASE | re.MULTILINE)),

    # AWS access key — HIGH
    ("AWS_ACCESS_KEY",
     re.compile(r"AKIA[0-9A-Z]{16}")),

    # AWS secret key — HIGH
    ("AWS_SECRET_KEY",
     re.compile(r"(?:AWS_SECRET_ACCESS_KEY|aws_secret_access_key)\s*[=:]\s*([A-Za-z0-9/+]{20,})", re.MULTILINE)),

    # GitHub PAT — HIGH (30+ chars after ghp_ covers real 36-char tokens and test data)
    ("GITHUB_TOKEN",
     re.compile(r"ghp_[A-Za-z0-9]{30,}")),

    # URLs with embedded credentials — HIGH
    ("URL_WITH_CREDS",
     re.compile(r"(?:https?|ftp|rtsp)://[^:@/\s]{2,}:[^@/\s]{2,}@[^\s]{4,}", re.IGNORECASE)),

    # Generic high-entropy API keys — MEDIUM (entropy-guarded below)
    ("GENERIC_API_KEY",
     re.compile(r"(?:api_key|apikey|token|secret|auth_token)\s*[=:]\s*['\"]?([A-Za-z0-9_\-]{20,})['\"]?",
                re.IGNORECASE | re.MULTILINE)),

    # WiFi credentials — MEDIUM
    ("HARDCODED_WIFI",
     re.compile(r"(?:ssid|wifi_ssid|wpa_passphrase|wifi_password)\s*[=:]\s*['\"]?([^\s'\"]{4,})",
                re.IGNORECASE | re.MULTILINE)),

    # Certificates (informational, LOW)
    ("CERTIFICATE",
     re.compile(r"-----BEGIN CERTIFICATE-----", re.IGNORECASE)),
]

# Minimum Shannon entropy for GENERIC_API_KEY values (filters out 'aaaa...' placeholders)
_MIN_API_KEY_ENTROPY = 3.5

# File extensions to scan as text
_TEXT_EXTS = {
    ".txt", ".conf", ".cfg", ".ini", ".sh", ".bash", ".py", ".js",
    ".xml", ".json", ".yaml", ".yml", ".env", ".properties",
    ".passwd", ".shadow", ".htpasswd", ".pem", ".crt", ".key",
    ".pfx", ".p12", ".config", ".toml", ".service", ".list",
    # Also handle extensionless files named shadow/passwd explicitly (see scan loop)
}

# Extensions to always skip
_SKIP_EXT = re.compile(
    r"\.(?:png|jpg|jpeg|gif|bmp|ico|mp4|avi|mkv|gz|xz|bz2|ttf|otf|woff2?)$",
    re.IGNORECASE,
)

_MAX_FILE_SIZE  = 50 * 1024 * 1024   # 50 MB
_MIN_STR_LEN    = 6


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: Dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((count / n) * math.log2(count / n) for count in freq.values())


def _extract_strings(data: bytes, min_len: int = _MIN_STR_LEN) -> str:
    """Extract printable ASCII strings from binary data (like `strings`)."""
    pattern = re.compile(rb"[ -~]{%d,}" % min_len)
    return "\n".join(m.decode("ascii", errors="ignore") for m in pattern.findall(data))


def _scan_text(content: str, rel_path: str) -> List[Dict]:
    findings = []
    for ftype, pattern in _PATTERNS:
        for match in pattern.finditer(content):
            # Extract the captured group if present, else the full match
            if match.lastindex:
                value = match.group(match.lastindex).strip()
            else:
                value = match.group(0).strip()

            if not value or len(value) < 3:
                continue

            # Entropy guard for GENERIC_API_KEY
            if ftype == "GENERIC_API_KEY":
                if _shannon_entropy(value) < _MIN_API_KEY_ENTROPY:
                    continue

            findings.append({
                "type":     ftype,
                "severity": _SEVERITY.get(ftype, "LOW"),
                "value":    value[:120],
                "file":     rel_path,
            })
    return findings


class SecretExtractor:

    def scan(self, extracted_path: str) -> Dict:
        result = {
            "secrets_found":      [],
            "high_entropy_files": [],
            "risk_level":         "LOW",
            "file_count_scanned": 0,
            "error":              None,
        }

        if not os.path.isdir(extracted_path):
            result["error"] = f"Directory not found: {extracted_path}"
            logger.error(result["error"])
            return result

        all_findings: List[Dict] = []
        file_count = 0

        for root, _, files in os.walk(extracted_path):
            for fname in files:
                fpath = os.path.join(root, fname)
                rel   = os.path.relpath(fpath, extracted_path)
                ext   = os.path.splitext(fname)[1].lower()

                # Skip known-binary image/media extensions
                if _SKIP_EXT.search(fname):
                    continue

                try:
                    fsize = os.path.getsize(fpath)
                    if fsize == 0 or fsize > _MAX_FILE_SIZE:
                        continue

                    with open(fpath, "rb") as f:
                        raw = f.read()

                    # Decide scan strategy
                    _text_names = {"shadow", "passwd", "hosts", "config",
                                   "fstab", "hostname", "resolv.conf", "motd"}
                    is_text_name = fname.lower() in _text_names
                    if ext in _TEXT_EXTS or is_text_name:
                        text = raw.decode("utf-8", errors="ignore")
                        all_findings.extend(_scan_text(text, rel))
                    elif ext in ("", ".bin", ".img", ".elf", ".so", ".ko") or not ext:
                        # Binary: extract printable strings then scan
                        strings = _extract_strings(raw)
                        if strings:
                            all_findings.extend(_scan_text(strings, rel + " [binary]"))
                    else:
                        # Try as text anyway (catches .conf, unknown extensions)
                        try:
                            text = raw.decode("utf-8", errors="ignore")
                            all_findings.extend(_scan_text(text, rel))
                        except Exception:
                            pass

                    file_count += 1

                except PermissionError:
                    continue
                except Exception as e:
                    logger.debug(f"[secret_extractor] {fpath}: {e}")
                    continue

        # De-duplicate: same (type, value[:40], file)
        seen = set()
        unique: List[Dict] = []
        for f in all_findings:
            key = (f["type"], f["value"][:40], f["file"])
            if key not in seen:
                seen.add(key)
                unique.append(f)

        result["secrets_found"]      = unique
        result["file_count_scanned"] = file_count

        # Risk roll-up
        types = {f["type"] for f in unique}
        if types & {"PRIVATE_KEY", "SHADOW_HASH", "HARDCODED_PASSWORD"}:
            result["risk_level"] = "CRITICAL"
        elif types & {"AWS_ACCESS_KEY", "AWS_SECRET_KEY", "GITHUB_TOKEN", "URL_WITH_CREDS"}:
            result["risk_level"] = "HIGH"
        elif unique:
            result["risk_level"] = "MEDIUM"
        else:
            result["risk_level"] = "LOW"

        logger.info(
            f"[secret_extractor] {extracted_path}: "
            f"{file_count} files, {len(unique)} secrets, risk={result['risk_level']}"
        )
        return result
