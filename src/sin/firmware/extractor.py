# src/sin/firmware/extractor.py
import os
import re
import shutil
import subprocess
import hashlib
from datetime import datetime
from typing import Dict, List, Optional

from sin.utils.logger import get_logger

logger = get_logger(__name__)


# ── Filesystem type signatures ────────────────────────────────────────────────
_FS_SIGNATURES = {
    "ubifs":    ["UBI erase count header", "UBIFS", "ubifs"],
    "squashfs": ["Squashfs filesystem", "squashfs"],
    "jffs2":    ["JFFS2 filesystem", "jffs2"],
    "cramfs":   ["CramFS filesystem", "cramfs"],
    "ext2":     ["ext2 filesystem", "ext3 filesystem", "ext4 filesystem"],
    "yaffs":    ["YAFFS", "yaffs"],
    "romfs":    ["ROMFS filesystem"],
}


def _detect_filesystem_type(binwalk_output: str) -> List[str]:
    """Detect filesystem types from binwalk output."""
    found = []
    output_lower = binwalk_output.lower()
    for fs_type, signatures in _FS_SIGNATURES.items():
        if any(sig.lower() in output_lower for sig in signatures):
            found.append(fs_type)
    return found or ["unknown"]


def _extract_warnings(binwalk_output: str) -> List[str]:
    """Extract WARNING lines from binwalk output."""
    warnings = []
    for line in binwalk_output.splitlines():
        if line.strip().startswith("WARNING"):
            warnings.append(line.strip())
    return warnings


def _try_ubireader(firmware_path: str, extract_path: str) -> Optional[str]:
    """
    Attempt UBI/UBIFS extraction using ubireader directly.
    Returns extraction sub-path on success, None on failure.
    Called when binwalk warns that ubireader_extract_files is missing.
    """
    try:
        ubi_out = os.path.join(extract_path, "ubifs-root")
        os.makedirs(ubi_out, exist_ok=True)
        result = subprocess.run(
            ["ubireader_extract_files", "-o", ubi_out, firmware_path],
            capture_output=True, text=True, timeout=120
        )
        if result.returncode == 0 or os.listdir(ubi_out):
            logger.info(f"[extractor] ubireader succeeded: {ubi_out}")
            return ubi_out
        # Also try ubireader_extract_images as fallback
        img_out = os.path.join(extract_path, "ubi-images")
        os.makedirs(img_out, exist_ok=True)
        result2 = subprocess.run(
            ["ubireader_extract_images", "-o", img_out, firmware_path],
            capture_output=True, text=True, timeout=120
        )
        if result2.returncode == 0 or os.listdir(img_out):
            logger.info(f"[extractor] ubireader_extract_images succeeded: {img_out}")
            return img_out
    except FileNotFoundError:
        logger.warning("[extractor] ubireader not installed — UBI extraction unavailable")
    except Exception as e:
        logger.debug(f"[extractor] ubireader error: {e}")
    return None


def _try_jefferson(firmware_path: str, extract_path: str) -> Optional[str]:
    """Attempt JFFS2 extraction using jefferson."""
    try:
        jffs2_out = os.path.join(extract_path, "jffs2-root")
        os.makedirs(jffs2_out, exist_ok=True)
        result = subprocess.run(
            ["jefferson", "-d", jffs2_out, firmware_path],
            capture_output=True, text=True, timeout=120
        )
        if result.returncode == 0 or os.listdir(jffs2_out):
            logger.info(f"[extractor] jefferson succeeded: {jffs2_out}")
            return jffs2_out
    except FileNotFoundError:
        logger.debug("[extractor] jefferson not installed")
    except Exception as e:
        logger.debug(f"[extractor] jefferson error: {e}")
    return None


class FirmwareExtractor:
    BINWALK_PATH = "/usr/bin/binwalk"
    EXTRACT_DIR  = "/var/lib/sin/firmware"

    def __init__(self, timeout: int = 120):
        self.timeout = timeout

    def extract(self, firmware_path: str) -> Dict:
        result = {
            "success":              False,
            "extracted_path":       None,
            "file_count":           0,
            "file_types":           {},
            "filesystem_types":     [],
            "extraction_warnings":  [],
            "fallback_used":        None,   # e.g. "ubireader", "jefferson"
            "raw_output":           "",
            "md5":                  None,
            "firmware_size_bytes":  None,
            "error":                None,
        }

        extract_path = None

        try:
            # ── Pre-flight ────────────────────────────────────────────────────
            if not os.path.isfile(firmware_path):
                raise FileNotFoundError(f"Firmware file not found: {firmware_path}")

            result["firmware_size_bytes"] = os.path.getsize(firmware_path)
            result["md5"] = self._md5(firmware_path)

            filename    = os.path.basename(firmware_path)
            extract_path = os.path.join(self.EXTRACT_DIR, filename)
            os.makedirs(extract_path, exist_ok=True)

            logger.info(f"[extractor] Extracting: {firmware_path} ({result['firmware_size_bytes']} bytes)")

            # ── Run binwalk ───────────────────────────────────────────────────
            cmd = [
                self.BINWALK_PATH,
                "-e", "--run-as=root",
                "-C", extract_path,
                "-v", firmware_path,
            ]
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )
            combined_output = proc.stdout + "\n" + proc.stderr
            result["raw_output"] = combined_output

            # ── Detect filesystem types from binwalk output ───────────────────
            result["filesystem_types"] = _detect_filesystem_type(combined_output)
            result["extraction_warnings"] = _extract_warnings(combined_output)

            logger.info(f"[extractor] Filesystem types detected: {result['filesystem_types']}")
            if result["extraction_warnings"]:
                logger.warning(f"[extractor] Binwalk warnings: {result['extraction_warnings']}")

            # ── Fallback extractors for filesystem types binwalk can't handle──
            # UBI/UBIFS — ubireader
            needs_ubi = any(fs in result["filesystem_types"] for fs in ("ubifs",))
            ubi_warning = any("ubireader" in w for w in result["extraction_warnings"])

            if needs_ubi or ubi_warning:
                logger.info("[extractor] UBI image detected — attempting ubireader fallback")
                ubi_path = _try_ubireader(firmware_path, extract_path)
                if ubi_path:
                    result["fallback_used"] = "ubireader"

            # JFFS2 — jefferson
            if "jffs2" in result["filesystem_types"]:
                logger.info("[extractor] JFFS2 detected — attempting jefferson fallback")
                jffs2_path = _try_jefferson(firmware_path, extract_path)
                if jffs2_path:
                    result["fallback_used"] = (result["fallback_used"] or "") + "+jefferson"

            # ── Walk extracted files ──────────────────────────────────────────
            files_found = []
            for root, _, files in os.walk(extract_path):
                for f in files:
                    fp = os.path.join(root, f)
                    if fp == firmware_path:
                        continue
                    files_found.append(fp)
                    ext = os.path.splitext(f)[1].lower() or "no_extension"
                    result["file_types"][ext] = result["file_types"].get(ext, 0) + 1

            result["file_count"]    = len(files_found)
            result["success"]       = len(files_found) > 0 or proc.returncode == 0
            result["extracted_path"] = extract_path

            logger.info(
                f"[extractor] Done — {result['file_count']} files extracted"
                f"{' via ' + result['fallback_used'] if result['fallback_used'] else ''}"
            )

        except FileNotFoundError as e:
            result["error"] = str(e)
            logger.error(f"[extractor] {e}")
        except subprocess.TimeoutExpired:
            result["error"] = f"Extraction timed out after {self.timeout}s"
            if extract_path:
                shutil.rmtree(extract_path, ignore_errors=True)
            logger.error(result["error"])
        except Exception as e:
            result["error"] = str(e)
            if extract_path:
                shutil.rmtree(extract_path, ignore_errors=True)
            logger.error(f"[extractor] Unexpected error: {e}", exc_info=True)

        return result

    @staticmethod
    def _md5(path: str) -> str:
        h = hashlib.md5()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
