"""
sin.firmware.binary_analyzer
═════════════════════════════
Static analysis of ELF binaries extracted from IoT firmware.

Uses readelf(1) and strings(1) from binutils — zero additional dependencies.
Ghidra/EMBA are not required and not used.

What this detects
─────────────────
  Security properties (from readelf):
    - Stack canary      — __stack_chk_fail in dynamic symbols
    - NX bit            — GNU_STACK segment flags (RW vs RWE)
    - PIE               — ELF type DYN (position-independent) vs EXEC
    - Stripped binary   — absence of .symtab section

  Dangerous functions (from readelf dynamic symbols):
    gets                → CRITICAL  (unbounded stdin — always exploitable)
    strcpy / strcat     → HIGH      (classic buffer overflow source)
    sprintf / vsprintf  → HIGH      (format string / buffer overflow)
    system / popen      → HIGH      (command injection surface)
    execve / execl      → MEDIUM    (arbitrary execution)

  Hardcoded strings (from strings -n 8):
    Private key headers → CRITICAL
    Password patterns   → HIGH
    Hardcoded IPs       → MEDIUM

Limits
──────
  Max 50 ELF binaries per firmware image (prevents DoS on huge images)
  Max 50MB per binary for strings analysis
  10s timeout per readelf / strings subprocess call
"""
from __future__ import annotations

import os
import re
import subprocess
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from sin.utils.logger import get_logger

logger = get_logger("sin.firmware.binary_analyzer")

# ── Constants ─────────────────────────────────────────────────────────────────
MAX_BINARIES       = 50
MAX_BINARY_SIZE    = 50 * 1024 * 1024   # 50 MB
SUBPROCESS_TIMEOUT = 10                 # seconds
STRINGS_MIN_LEN    = 8

# ── Architecture map (readelf "Machine:" → friendly name) ─────────────────────
_ARCH_MAP: Dict[str, str] = {
    "advanced micro devices x86-64": "x86_64",
    "intel 80386":                   "x86",
    "arm":                           "ARM",
    "aarch64":                       "ARM64",
    "mips r3000":                    "MIPS",
    "mips":                          "MIPS",
    "powerpc":                       "PowerPC",
    "ucb risc-v":                    "RISC-V",
}

# ── Dangerous function risk levels ────────────────────────────────────────────
_DANGEROUS_FUNCS: Dict[str, str] = {
    "gets":     "CRITICAL",   # unbounded stdin — always exploitable
    "strcpy":   "HIGH",
    "strcat":   "HIGH",
    "sprintf":  "HIGH",
    "vsprintf": "HIGH",
    "system":   "HIGH",
    "popen":    "HIGH",
    "execve":   "MEDIUM",
    "execl":    "MEDIUM",
    "execlp":   "MEDIUM",
    "scanf":    "MEDIUM",
    "memcpy":   "LOW",
    "strncpy":  "LOW",
}

# ── Hardcoded string patterns ─────────────────────────────────────────────────
_STRING_PATTERNS: List[Tuple[str, str, str]] = [
    # (severity, type, regex)
    ("CRITICAL", "Private Key Material",    r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"),
    ("CRITICAL", "Hardcoded Password",      r"(?i)password\s*[=:]\s*\S{4,}"),
    ("HIGH",     "Hardcoded Credential",    r"(?i)(?:passwd|pwd|secret|token)\s*[=:]\s*\S{4,}"),
    ("HIGH",     "Default Admin String",    r"(?i)admin\s*[=:]\s*(?:admin|1234|12345|password|888888)"),
    ("MEDIUM",   "Hardcoded Private IP",    r"(?:192\.168\.|10\.\d+\.|172\.(?:1[6-9]|2\d|3[01])\.)"),
    ("MEDIUM",   "Debug/Backdoor Path",     r"(?:/debug/|/backdoor|/shell|/telnetd|/dropbear)"),
]


# ── Data classes ──────────────────────────────────────────────────────────────

@dataclass
class BinaryFinding:
    severity:    str
    type:        str
    description: str
    binary:      str
    detail:      Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "severity":    self.severity,
            "type":        self.type,
            "description": self.description,
            "binary":      self.binary,
            "detail":      self.detail,
        }


@dataclass
class BinaryAnalysis:
    path:                str
    filename:            str
    arch:                str
    binary_type:         str       # EXEC | DYN | REL | unknown
    stripped:            bool
    has_stack_canary:    bool
    has_nx:              bool
    has_pie:             bool
    dangerous_functions: List[str]
    string_hits:         List[Tuple[str, str, str]]   # (severity, type, value)
    findings:            List[BinaryFinding]
    error:               Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "filename":            self.filename,
            "arch":                self.arch,
            "binary_type":         self.binary_type,
            "stripped":            self.stripped,
            "has_stack_canary":    self.has_stack_canary,
            "has_nx":              self.has_nx,
            "has_pie":             self.has_pie,
            "dangerous_functions": self.dangerous_functions,
            "string_hits":         [
                {"severity": s, "type": t, "value": v[:80]}
                for s, t, v in self.string_hits
            ],
            "findings":            [f.to_dict() for f in self.findings],
            "error":               self.error,
        }


# ── ELF detection ─────────────────────────────────────────────────────────────

def _is_elf(path: str) -> bool:
    """Check ELF magic bytes — fast, no subprocess."""
    try:
        with open(path, "rb") as f:
            return f.read(4) == b"\x7fELF"
    except OSError:
        return False


# ── readelf parsing ───────────────────────────────────────────────────────────

def _run_readelf(path: str) -> Optional[str]:
    """Run readelf -a. Returns stdout or None on failure."""
    try:
        result = subprocess.run(
            ["readelf", "-a", path],
            capture_output=True,
            text=True,
            timeout=SUBPROCESS_TIMEOUT,
        )
        return result.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
        logger.debug("[binary_analyzer] readelf failed for %s: %s", path, exc)
        return None


def _parse_arch(readelf_out: str) -> str:
    for line in readelf_out.splitlines():
        if "Machine:" in line:
            machine = line.split("Machine:", 1)[1].strip().lower()
            for key, arch in _ARCH_MAP.items():
                if key in machine:
                    return arch
            return machine[:32]  # Return raw truncated value if unknown
    return "unknown"


def _parse_binary_type(readelf_out: str) -> str:
    for line in readelf_out.splitlines():
        if "Type:" in line and ("EXEC" in line or "DYN" in line or "REL" in line):
            if "EXEC" in line:
                return "EXEC"
            if "DYN" in line:
                return "DYN"
            if "REL" in line:
                return "REL"
    return "unknown"


def _parse_stripped(readelf_out: str) -> bool:
    """Binary is stripped if .symtab section is absent."""
    return ".symtab" not in readelf_out


def _parse_stack_canary(readelf_out: str) -> bool:
    """Stack canary present if __stack_chk_fail appears in dynamic symbols."""
    return "__stack_chk_fail" in readelf_out


def _parse_nx(readelf_out: str) -> bool:
    """
    NX (non-executable stack) is ON when GNU_STACK segment has flags RW (no E).
    GNU_STACK with flags RWE means executable stack = NO NX protection.
    Returns True if NX is enabled (stack is not executable).
    """
    for line in readelf_out.splitlines():
        if "GNU_STACK" in line:
            # flags appear after the addresses — look for E in the flags field
            # Format: GNU_STACK  0x... 0x... 0x... 0x... 0x... RWE  0x...
            #     or: GNU_STACK  0x... 0x... 0x... 0x... 0x... RW   0x...
            parts = line.split()
            for part in parts:
                if re.fullmatch(r"R?W?E?", part) and len(part) >= 2:
                    return "E" not in part
    return True  # Assume NX if GNU_STACK not found (conservative)


def _parse_pie(readelf_out: str, binary_type: str) -> bool:
    """PIE executables have ELF type DYN. Non-PIE executables are EXEC."""
    return binary_type == "DYN"


def _parse_dangerous_functions(readelf_out: str) -> List[str]:
    """Find dangerous function names in imported dynamic symbols."""
    found = []
    for line in readelf_out.splitlines():
        # Dynamic symbol entries — look for UND (undefined = imported) symbols
        if "UND" in line or "FUNC" in line:
            for func in _DANGEROUS_FUNCS:
                pattern = rf"\b{re.escape(func)}(?:@|\s|$)"
                if re.search(pattern, line):
                    if func not in found:
                        found.append(func)
    return found


# ── strings parsing ───────────────────────────────────────────────────────────

def _run_strings(path: str) -> List[str]:
    """Run strings -n STRINGS_MIN_LEN. Returns list of lines, empty on failure."""
    if os.path.getsize(path) > MAX_BINARY_SIZE:
        logger.debug("[binary_analyzer] %s too large for strings analysis", path)
        return []
    try:
        result = subprocess.run(
            ["strings", f"-n{STRINGS_MIN_LEN}", path],
            capture_output=True,
            text=True,
            timeout=SUBPROCESS_TIMEOUT,
        )
        return result.stdout.splitlines()
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
        logger.debug("[binary_analyzer] strings failed for %s: %s", path, exc)
        return []


def _parse_string_hits(lines: List[str]) -> List[Tuple[str, str, str]]:
    """Match strings output against credential/secret patterns."""
    hits: List[Tuple[str, str, str]] = []
    seen: set = set()
    for line in lines:
        for severity, finding_type, pattern in _STRING_PATTERNS:
            m = re.search(pattern, line)
            if m:
                key = (finding_type, line[:60])
                if key not in seen:
                    seen.add(key)
                    hits.append((severity, finding_type, line[:120]))
    return hits


# ── Finding generation ────────────────────────────────────────────────────────

def _build_findings(analysis: BinaryAnalysis) -> List[BinaryFinding]:
    findings: List[BinaryFinding] = []
    fname = analysis.filename

    if not analysis.has_stack_canary:
        findings.append(BinaryFinding(
            severity="HIGH",
            type="No Stack Canary",
            description=f"{fname} was compiled without stack canary protection (-fno-stack-protector). "
                        "Buffer overflows in this binary will not be detected at runtime.",
            binary=fname,
        ))

    if not analysis.has_nx:
        findings.append(BinaryFinding(
            severity="HIGH",
            type="Executable Stack (No NX)",
            description=f"{fname} has an executable stack (GNU_STACK RWE). "
                        "Shellcode can be placed on the stack and executed directly.",
            binary=fname,
        ))

    if not analysis.has_pie:
        findings.append(BinaryFinding(
            severity="MEDIUM",
            type="No PIE",
            description=f"{fname} is not a position-independent executable. "
                        "Hardcoded load addresses make ASLR ineffective against return-to-libc attacks.",
            binary=fname,
        ))

    for func in analysis.dangerous_functions:
        sev = _DANGEROUS_FUNCS.get(func, "MEDIUM")
        findings.append(BinaryFinding(
            severity=sev,
            type="Dangerous Function Import",
            description=f"{fname} imports {func}() — a known memory-unsafe function.",
            binary=fname,
            detail=func,
        ))

    for sev, hit_type, value in analysis.string_hits:
        findings.append(BinaryFinding(
            severity=sev,
            type=f"Hardcoded String: {hit_type}",
            description=f"{fname} contains a hardcoded {hit_type.lower()}.",
            binary=fname,
            detail=value[:80],
        ))

    return findings


# ── FirmwareBinaryAnalyzer ────────────────────────────────────────────────────

class FirmwareBinaryAnalyzer:
    """
    Analyzes ELF binaries extracted from IoT firmware.
    Uses readelf and strings — no additional dependencies.
    """

    def analyze_file(self, path: str) -> Optional[BinaryAnalysis]:
        """
        Analyze a single ELF binary. Returns BinaryAnalysis or None if not ELF.
        Never raises.
        """
        if not _is_elf(path):
            return None

        filename = os.path.basename(path)
        logger.debug("[binary_analyzer] Analyzing %s", filename)

        readelf_out = _run_readelf(path)
        if readelf_out is None:
            return BinaryAnalysis(
                path=path, filename=filename,
                arch="unknown", binary_type="unknown",
                stripped=True, has_stack_canary=False,
                has_nx=False, has_pie=False,
                dangerous_functions=[], string_hits=[],
                findings=[], error="readelf failed",
            )

        arch         = _parse_arch(readelf_out)
        binary_type  = _parse_binary_type(readelf_out)
        stripped     = _parse_stripped(readelf_out)
        has_canary   = _parse_stack_canary(readelf_out)
        has_nx       = _parse_nx(readelf_out)
        has_pie      = _parse_pie(readelf_out, binary_type)
        danger_funcs = _parse_dangerous_functions(readelf_out)

        strings_lines = _run_strings(path)
        string_hits   = _parse_string_hits(strings_lines)

        result = BinaryAnalysis(
            path=path,
            filename=filename,
            arch=arch,
            binary_type=binary_type,
            stripped=stripped,
            has_stack_canary=has_canary,
            has_nx=has_nx,
            has_pie=has_pie,
            dangerous_functions=danger_funcs,
            string_hits=string_hits,
            findings=[],
        )
        result.findings = _build_findings(result)

        logger.info(
            "[binary_analyzer] %s arch=%s type=%s canary=%s nx=%s pie=%s "
            "danger_funcs=%d string_hits=%d findings=%d",
            filename, arch, binary_type,
            has_canary, has_nx, has_pie,
            len(danger_funcs), len(string_hits), len(result.findings),
        )
        return result

    def analyze_directory(self, extract_path: str) -> List[BinaryAnalysis]:
        """
        Walk an extracted firmware directory and analyze all ELF binaries.
        Capped at MAX_BINARIES to prevent DoS on huge firmware images.
        Returns list of BinaryAnalysis (one per ELF found).
        """
        if not os.path.isdir(extract_path):
            logger.warning("[binary_analyzer] Not a directory: %s", extract_path)
            return []

        results: List[BinaryAnalysis] = []
        count = 0

        for root, _, files in os.walk(extract_path):
            for fname in files:
                if count >= MAX_BINARIES:
                    logger.info("[binary_analyzer] MAX_BINARIES limit reached — stopping walk")
                    return results
                fpath = os.path.join(root, fname)
                try:
                    if os.path.isfile(fpath) and not os.path.islink(fpath):
                        analysis = self.analyze_file(fpath)
                        if analysis is not None:
                            results.append(analysis)
                            count += 1
                except OSError:
                    continue

        logger.info("[binary_analyzer] Directory scan complete: %d ELF binaries analyzed", len(results))
        return results

    def summarize(self, analyses: List[BinaryAnalysis]) -> dict:
        """
        Aggregate findings across all analyzed binaries into a summary report.
        """
        all_findings = [f for a in analyses for f in a.findings]
        by_severity: Dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in all_findings:
            by_severity[f.severity] = by_severity.get(f.severity, 0) + 1

        archs = list({a.arch for a in analyses if a.arch != "unknown"})
        no_canary = [a.filename for a in analyses if not a.has_stack_canary]
        no_nx     = [a.filename for a in analyses if not a.has_nx]
        no_pie    = [a.filename for a in analyses if not a.has_pie]

        return {
            "binaries_analyzed": len(analyses),
            "total_findings":    len(all_findings),
            "findings_by_severity": by_severity,
            "architectures":     archs,
            "binaries_without_stack_canary": no_canary,
            "binaries_without_nx":           no_nx,
            "binaries_without_pie":          no_pie,
            "findings": [f.to_dict() for f in all_findings],
        }


# Module-level singleton
binary_analyzer = FirmwareBinaryAnalyzer()
