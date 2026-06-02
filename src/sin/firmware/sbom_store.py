"""
sin.firmware.sbom_store
════════════════════════
Persist and retrieve CycloneDX SBOM documents generated during firmware upload.

Storage layout:
  /var/lib/sin/firmware/sbom/
    {slug}.sbom.json          — full CycloneDX 1.4 document
    {slug}.meta.json          — lightweight index record (no BOM body)

slug = sanitised filename without extension, e.g. "ipc-hfw2831t_bin"

Why filesystem, not DB:
  SBOMs are large JSON documents (can be 100KB+).  Storing them as
  files keeps the PostgreSQL schema clean and makes them trivially
  exportable / importable by external tools (Dependency-Track, Grype).
  The meta index is small and stays queryable without a DB.
"""
from __future__ import annotations

import json
import os
import re
import time
from typing import Any, Dict, List, Optional

from sin.utils.logger import get_logger

logger = get_logger("sin.firmware.sbom_store")

_SBOM_DIR = os.getenv("SIN_SBOM_DIR", "/var/lib/sin/firmware/sbom")


def _ensure_dir() -> None:
    os.makedirs(_SBOM_DIR, exist_ok=True)


def _slugify(filename: str) -> str:
    """Convert a firmware filename to a safe filesystem slug."""
    name = os.path.splitext(os.path.basename(filename))[0]
    name = re.sub(r"[^\w\-]", "_", name).strip("_").lower()
    return name or "firmware"


def _sbom_path(slug: str) -> str:
    return os.path.join(_SBOM_DIR, f"{slug}.sbom.json")


def _meta_path(slug: str) -> str:
    return os.path.join(_SBOM_DIR, f"{slug}.meta.json")


class SBOMStore:
    """
    Persist and retrieve SBOM documents.
    All methods are synchronous — called from FastAPI endpoints via
    run_in_executor or directly (FastAPI handles the thread pool).
    """

    # ── Write ──────────────────────────────────────────────────────────────

    def save(
        self,
        firmware_filename: str,
        sbom_result:       Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Persist the SBOM document and return a lightweight index record.

        Returns:
            {slug, sbom_path, meta_path, component_count,
             risk_level, sources, saved_at, firmware_filename}
        """
        _ensure_dir()
        slug = _slugify(firmware_filename)

        # Resolve slug collisions by appending a counter
        base_slug = slug
        counter   = 1
        while (
            os.path.exists(_sbom_path(slug))
            and not self._same_firmware(_meta_path(slug), firmware_filename)
        ):
            slug    = f"{base_slug}_{counter}"
            counter += 1

        saved_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        # Full CycloneDX document
        sbom_doc = sbom_result.get("sbom_document", {})
        with open(_sbom_path(slug), "w") as fh:
            json.dump(sbom_doc, fh, indent=2)

        # Lightweight meta record (no BOM body — fast to list)
        meta: Dict[str, Any] = {
            "slug":              slug,
            "firmware_filename": firmware_filename,
            "component_count":   sbom_result.get("sbom_component_count", 0),
            "risk_level":        sbom_result.get("sbom_risk_level", "UNKNOWN"),
            "sources":           sbom_result.get("sbom_sources", []),
            "sbom_success":      sbom_result.get("sbom_success", False),
            "saved_at":          saved_at,
            "sbom_path":         _sbom_path(slug),
        }
        with open(_meta_path(slug), "w") as fh:
            json.dump(meta, fh, indent=2)

        logger.info(
            f"[sbom_store] saved slug={slug} "
            f"components={meta['component_count']} "
            f"risk={meta['risk_level']}"
        )
        return meta

    # ── Read ───────────────────────────────────────────────────────────────

    def get(self, slug: str) -> Optional[Dict[str, Any]]:
        """
        Return the full CycloneDX document for *slug*, or None if not found.
        """
        path = _sbom_path(slug)
        if not os.path.isfile(path):
            return None
        try:
            with open(path) as fh:
                return json.load(fh)
        except (OSError, json.JSONDecodeError) as e:
            logger.error(f"[sbom_store] get failed slug={slug}: {e}")
            return None

    def get_meta(self, slug: str) -> Optional[Dict[str, Any]]:
        """Return the meta record for *slug*, or None if not found."""
        path = _meta_path(slug)
        if not os.path.isfile(path):
            return None
        try:
            with open(path) as fh:
                return json.load(fh)
        except (OSError, json.JSONDecodeError):
            return None

    def list_all(self) -> List[Dict[str, Any]]:
        """
        Return all meta records, sorted newest-first.
        Does NOT include the full BOM document (use get() for that).
        """
        _ensure_dir()
        records = []
        try:
            for fname in os.listdir(_SBOM_DIR):
                if not fname.endswith(".meta.json"):
                    continue
                fpath = os.path.join(_SBOM_DIR, fname)
                try:
                    with open(fpath) as fh:
                        records.append(json.load(fh))
                except (OSError, json.JSONDecodeError):
                    pass
        except OSError:
            pass

        records.sort(key=lambda r: r.get("saved_at", ""), reverse=True)
        return records

    def delete(self, slug: str) -> bool:
        """Delete the SBOM document and meta record. Returns True if deleted."""
        deleted = False
        for path in (_sbom_path(slug), _meta_path(slug)):
            if os.path.isfile(path):
                try:
                    os.remove(path)
                    deleted = True
                except OSError as e:
                    logger.error(f"[sbom_store] delete failed {path}: {e}")
        return deleted

    # ── Helpers ────────────────────────────────────────────────────────────

    @staticmethod
    def _same_firmware(meta_path: str, firmware_filename: str) -> bool:
        """Return True if the existing meta file is for the same firmware."""
        try:
            with open(meta_path) as fh:
                meta = json.load(fh)
            return meta.get("firmware_filename") == firmware_filename
        except Exception:
            return False


# ── Module-level singleton ─────────────────────────────────────────────────
sbom_store = SBOMStore()
