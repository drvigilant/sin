"""
sin.firmware.sbom_generator
════════════════════════════
Generate a CycloneDX 1.4 SBOM from an extracted firmware filesystem.

Component sources (in priority order):
  1. opkg/dpkg/ipkg package databases  — most reliable, version-exact
  2. Python dist-info / egg-info        — pip-installed packages
  3. Node.js package.json files         — npm packages
  4. requirements.txt / setup.py        — Python source deps
  5. ELF SONAME strings                 — shared libs with no metadata
  6. Version strings in text configs    — last resort heuristic

Output format: CycloneDX 1.4 JSON
  Compatible with: Dependency-Track, Grype, Trivy, OWASP tooling.

The result dict is designed to drop straight into the /firmware/upload
response alongside secret_extractor output.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import struct
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from sin.utils.logger import get_logger

logger = get_logger(__name__)

# ── CycloneDX constants ────────────────────────────────────────────────────
_CDX_SPEC     = "1.4"
_CDX_FORMAT   = "CycloneDX"
_CDX_BOMFMT   = "application/vnd.cyclonedx+json"

# ── File skip lists ────────────────────────────────────────────────────────
_SKIP_DIRS = {
    "proc", "sys", "dev", "run", "tmp",
    ".git", "__pycache__", "node_modules",
}
_SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico",
    ".mp4", ".avi", ".mkv", ".gz", ".xz", ".bz2",
    ".ttf", ".otf", ".woff", ".woff2",
}

# ── Regexes ────────────────────────────────────────────────────────────────
_RE_OPKG_PKG   = re.compile(r"^Package:\s*(.+)$",  re.MULTILINE)
_RE_OPKG_VER   = re.compile(r"^Version:\s*(.+)$",  re.MULTILINE)
_RE_OPKG_DESC  = re.compile(r"^Description:\s*(.+)$", re.MULTILINE)
_RE_OPKG_ARCH  = re.compile(r"^Architecture:\s*(.+)$", re.MULTILINE)

_RE_DPKG_NAME  = re.compile(r"^Package: (.+)$", re.MULTILINE)
_RE_DPKG_VER   = re.compile(r"^Version: (.+)$",  re.MULTILINE)

_RE_DISTINFO   = re.compile(r"^Name:\s*(.+)$.*?^Version:\s*(.+)$",
                             re.MULTILINE | re.DOTALL)
_RE_REQ        = re.compile(
    r"^\s*([A-Za-z0-9_\-\.]+)\s*(?:[><=!~^]+\s*([\w\.\-\+\*]+))?",
    re.MULTILINE)

_RE_SONAME     = re.compile(rb"lib[a-zA-Z0-9_\-\.]+\.so(?:\.\d+)*")

# ── Component dataclass (plain dict for JSON compat) ──────────────────────

def _make_component(
    name:    str,
    version: str       = "unknown",
    purl:    str       = "",
    comp_type: str     = "library",
    source:  str       = "",
    arch:    str       = "",
    description: str   = "",
    licenses: List[str] = None,
) -> Dict[str, Any]:
    c: Dict[str, Any] = {
        "type":    comp_type,
        "name":    name.strip(),
        "version": version.strip() or "unknown",
    }
    if purl:
        c["purl"] = purl
    if description:
        c["description"] = description[:200]
    if arch:
        c["properties"] = [{"name": "sin:arch", "value": arch}]
    if source:
        c.setdefault("properties", []).append(
            {"name": "sin:source", "value": source}
        )
    if licenses:
        c["licenses"] = [{"license": {"name": lc}} for lc in licenses]
    return c


def _purl(ecosystem: str, name: str, version: str) -> str:
    """Build a Package URL per https://github.com/package-url/purl-spec"""
    ver = version.strip().lstrip("v=~^")
    n   = name.strip().lower().replace(" ", "-")
    return f"pkg:{ecosystem}/{n}@{ver}"


# ── Source parsers ─────────────────────────────────────────────────────────

def _parse_opkg_status(path: str) -> List[Dict]:
    """Parse OpenWrt/Buildroot /usr/lib/opkg/status (or /var/lib/opkg/status)."""
    try:
        with open(path, "r", errors="ignore") as fh:
            content = fh.read()
    except OSError:
        return []

    components = []
    # Blocks are separated by blank lines
    for block in re.split(r"\n\n+", content):
        m_pkg = _RE_OPKG_PKG.search(block)
        if not m_pkg:
            continue
        m_ver  = _RE_OPKG_VER.search(block)
        m_arch = _RE_OPKG_ARCH.search(block)
        m_desc = _RE_OPKG_DESC.search(block)

        name    = m_pkg.group(1).strip()
        version = m_ver.group(1).strip()  if m_ver  else "unknown"
        arch    = m_arch.group(1).strip() if m_arch else ""
        desc    = m_desc.group(1).strip() if m_desc else ""

        components.append(_make_component(
            name=name, version=version,
            purl=_purl("opkg", name, version),
            source="opkg", arch=arch, description=desc,
        ))
    return components


def _parse_dpkg_status(path: str) -> List[Dict]:
    """Parse Debian/Ubuntu /var/lib/dpkg/status."""
    try:
        with open(path, "r", errors="ignore") as fh:
            content = fh.read()
    except OSError:
        return []

    components = []
    for block in re.split(r"\n\n+", content):
        m_name = _RE_DPKG_NAME.search(block)
        m_ver  = _RE_DPKG_VER.search(block)
        if not m_name:
            continue
        name    = m_name.group(1).strip()
        version = m_ver.group(1).strip() if m_ver else "unknown"
        components.append(_make_component(
            name=name, version=version,
            purl=_purl("deb", name, version),
            source="dpkg",
        ))
    return components


def _parse_python_distinfo(root: str) -> List[Dict]:
    """Find all dist-info and egg-info METADATA/PKG-INFO files."""
    components = []
    for dirpath, dirnames, filenames in os.walk(root):
        # prune heavy dirs
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        dirname = os.path.basename(dirpath)
        if dirname.endswith((".dist-info", ".egg-info")):
            for meta_name in ("METADATA", "PKG-INFO"):
                meta_path = os.path.join(dirpath, meta_name)
                if os.path.isfile(meta_path):
                    try:
                        with open(meta_path, "r", errors="ignore") as fh:
                            text = fh.read(16384)
                        m = _RE_DISTINFO.search(text)
                        if m:
                            name, version = m.group(1).strip(), m.group(2).strip()
                            components.append(_make_component(
                                name=name, version=version,
                                purl=_purl("pypi", name, version),
                                source="distinfo",
                            ))
                    except OSError:
                        pass
                    break
    return components


def _parse_nodejs_packages(root: str) -> List[Dict]:
    """Find package.json files and extract name + version."""
    components = []
    seen_dirs: Set[str] = set()
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        if "package.json" in filenames:
            pkg_path = os.path.join(dirpath, "package.json")
            if pkg_path in seen_dirs:
                continue
            seen_dirs.add(pkg_path)
            try:
                with open(pkg_path, "r", errors="ignore") as fh:
                    data = json.load(fh)
                name    = data.get("name", "").strip()
                version = data.get("version", "unknown").strip()
                if name:
                    components.append(_make_component(
                        name=name, version=version,
                        purl=_purl("npm", name, version),
                        source="package.json",
                        description=data.get("description", "")[:200],
                    ))
                # Also pull in production dependencies
                for dep_name, dep_ver in data.get("dependencies", {}).items():
                    ver = dep_ver.lstrip("^~>=<").strip() if dep_ver else "unknown"
                    components.append(_make_component(
                        name=dep_name, version=ver,
                        purl=_purl("npm", dep_name, ver),
                        source="package.json#dependencies",
                    ))
            except (OSError, json.JSONDecodeError):
                pass
    return components


def _parse_requirements_txt(path: str) -> List[Dict]:
    """Parse a requirements.txt file into components."""
    components = []
    try:
        with open(path, "r", errors="ignore") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith(("#", "-", "http")):
                    continue
                m = _RE_REQ.match(line)
                if m:
                    name    = m.group(1).strip()
                    version = (m.group(2) or "unknown").strip()
                    if name:
                        components.append(_make_component(
                            name=name, version=version,
                            purl=_purl("pypi", name, version),
                            source="requirements.txt",
                        ))
    except OSError:
        pass
    return components


def _parse_elf_sonames(path: str) -> List[str]:
    """Extract SONAME strings from an ELF binary (DT_SONAME tag)."""
    sonames = []
    try:
        with open(path, "rb") as fh:
            magic = fh.read(4)
            if magic != b"\x7fELF":
                return []
            # Just grep for libXXX.so patterns — fast and good enough
            fh.seek(0)
            data = fh.read(1024 * 512)   # first 512 KB
            for m in _RE_SONAME.findall(data):
                try:
                    sonames.append(m.decode("ascii", errors="ignore"))
                except Exception:
                    pass
    except OSError:
        pass
    return sonames


def _collect_elf_libraries(root: str) -> List[Dict]:
    """Walk for ELF .so files and extract SONAME-derived component names."""
    seen: Set[str] = set()
    components = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for fname in filenames:
            if ".so" not in fname:
                continue
            fpath = os.path.join(dirpath, fname)
            try:
                size = os.path.getsize(fpath)
            except OSError:
                continue
            if size > 50 * 1024 * 1024:
                continue
            for soname in _parse_elf_sonames(fpath):
                if soname in seen:
                    continue
                seen.add(soname)
                # Parse name + version from e.g. libssl.so.1.1
                parts = soname.split(".so")
                lib_name = parts[0].lstrip("lib")
                lib_ver  = parts[1].lstrip(".") if len(parts) > 1 else "unknown"
                if lib_name:
                    components.append(_make_component(
                        name=lib_name, version=lib_ver or "unknown",
                        source="elf-soname",
                    ))
    return components


# ── Deduplication ──────────────────────────────────────────────────────────

def _dedup(components: List[Dict]) -> List[Dict]:
    """Collapse exact (name, version) duplicates; prefer richer source."""
    _SOURCE_PRIORITY = {
        "opkg": 6, "dpkg": 6,
        "distinfo": 5, "package.json": 5,
        "requirements.txt": 4,
        "package.json#dependencies": 3,
        "elf-soname": 2,
        "": 1,
    }
    best: Dict[Tuple[str, str], Dict] = {}
    for c in components:
        key = (c["name"].lower(), c["version"].lower())
        src = ""
        for prop in c.get("properties", []):
            if prop.get("name") == "sin:source":
                src = prop.get("value", "")
                break
        priority = _SOURCE_PRIORITY.get(src, 1)
        if key not in best or priority > _SOURCE_PRIORITY.get(
            next((p["value"] for p in best[key].get("properties", [])
                  if p["name"] == "sin:source"), ""), 1
        ):
            best[key] = c
    return list(best.values())


# ── BOM assembly ───────────────────────────────────────────────────────────

def _sha256_dir(path: str) -> str:
    """Stable hash of extracted path for BOM serial reproducibility."""
    return hashlib.sha256(path.encode()).hexdigest()[:16]


def _build_bom(
    components: List[Dict],
    source_path: str,
    metadata: Dict[str, Any],
) -> Dict[str, Any]:
    """Assemble a CycloneDX 1.4 BOM dict."""
    now = datetime.now(timezone.utc).isoformat()
    bom_serial = f"urn:uuid:{uuid.uuid4()}"

    # Assign stable BOM-ref to each component
    for idx, c in enumerate(components):
        c["bom-ref"] = f"{c['name']}-{c['version']}-{idx}"

    return {
        "bomFormat":    _CDX_FORMAT,
        "specVersion":  _CDX_SPEC,
        "serialNumber": bom_serial,
        "version":      1,
        "metadata": {
            "timestamp": now,
            "tools": [{"vendor": "SIN", "name": "sin-sbom-generator", "version": "1.0"}],
            "component": {
                "type":    "firmware",
                "name":    metadata.get("firmware_name", os.path.basename(source_path)),
                "version": metadata.get("firmware_version", "unknown"),
            },
        },
        "components": components,
    }


# ── Public interface ───────────────────────────────────────────────────────

class SBOMGenerator:
    """
    Walk an extracted firmware directory and produce a CycloneDX 1.4 SBOM.

    Return schema (backward-compat with firmware/upload endpoint):
    {
        "sbom_success":        bool,
        "sbom_component_count": int,
        "sbom_risk_level":     str,   # LOW | MEDIUM | HIGH
        "sbom_document":       dict,  # full CycloneDX BOM
        "sbom_error":          str | None,
    }
    """

    def generate(
        self,
        extracted_path:   str,
        firmware_name:    str = "",
        firmware_version: str = "unknown",
    ) -> Dict[str, Any]:

        result: Dict[str, Any] = {
            "sbom_success":         False,
            "sbom_component_count": 0,
            "sbom_risk_level":      "LOW",
            "sbom_document":        {},
            "sbom_error":           None,
        }

        if not os.path.isdir(extracted_path):
            result["sbom_error"] = f"Directory not found: {extracted_path}"
            logger.error(result["sbom_error"])
            return result

        components: List[Dict] = []
        sources_used: List[str] = []

        # 1. opkg (OpenWrt, many IP cameras)
        for candidate in (
            "usr/lib/opkg/status",
            "var/lib/opkg/status",
            "usr/lib/opkg/info",
        ):
            p = os.path.join(extracted_path, candidate)
            if os.path.isfile(p):
                found = _parse_opkg_status(p)
                if found:
                    components.extend(found)
                    sources_used.append("opkg")
                    logger.info(f"sbom opkg: {len(found)} packages from {candidate}")

        # 2. dpkg (Debian-based embedded)
        for candidate in ("var/lib/dpkg/status", "usr/lib/dpkg/status"):
            p = os.path.join(extracted_path, candidate)
            if os.path.isfile(p):
                found = _parse_dpkg_status(p)
                if found:
                    components.extend(found)
                    sources_used.append("dpkg")
                    logger.info(f"sbom dpkg: {len(found)} packages from {candidate}")

        # 3. Python dist-info / egg-info
        py_comps = _parse_python_distinfo(extracted_path)
        if py_comps:
            components.extend(py_comps)
            sources_used.append("distinfo")
            logger.info(f"sbom python distinfo: {len(py_comps)} packages")

        # 4. Node.js package.json
        node_comps = _parse_nodejs_packages(extracted_path)
        if node_comps:
            components.extend(node_comps)
            sources_used.append("package.json")
            logger.info(f"sbom npm: {len(node_comps)} packages")

        # 5. requirements.txt files
        for dirpath, dirnames, filenames in os.walk(extracted_path):
            dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
            for fname in filenames:
                if fname in ("requirements.txt", "requirements-prod.txt"):
                    found = _parse_requirements_txt(os.path.join(dirpath, fname))
                    if found:
                        components.extend(found)
                        sources_used.append("requirements.txt")

        # 6. ELF SONAME heuristic (fallback — low confidence)
        elf_comps = _collect_elf_libraries(extracted_path)
        if elf_comps:
            components.extend(elf_comps)
            sources_used.append("elf-soname")
            logger.info(f"sbom elf: {len(elf_comps)} shared libs")

        # Dedup and build BOM
        components = _dedup(components)
        bom = _build_bom(
            components=components,
            source_path=extracted_path,
            metadata={
                "firmware_name":    firmware_name or os.path.basename(extracted_path),
                "firmware_version": firmware_version,
            },
        )

        # Risk heuristic:
        # HIGH  — no package DB found (blind spot), or >0 elf-only components
        #         meaning we couldn't verify provenance
        # MEDIUM — some components found but only from heuristic sources
        # LOW   — opkg/dpkg fully enumerated the firmware
        authoritative = {"opkg", "dpkg", "distinfo", "package.json"}
        has_authoritative = bool(authoritative & set(sources_used))
        has_elf_only      = "elf-soname" in sources_used and not has_authoritative
        n = len(components)

        if n == 0:
            sbom_risk = "HIGH"   # couldn't identify anything
        elif has_elf_only:
            sbom_risk = "HIGH"   # only binary heuristics
        elif not has_authoritative:
            sbom_risk = "MEDIUM"
        else:
            sbom_risk = "LOW"

        result.update({
            "sbom_success":         True,
            "sbom_component_count": n,
            "sbom_risk_level":      sbom_risk,
            "sbom_document":        bom,
            "sbom_error":           None,
            "sbom_sources":         list(set(sources_used)),
        })

        logger.info(
            f"sbom_generator | path={extracted_path} "
            f"components={n} sources={sources_used} risk={sbom_risk}"
        )
        return result
