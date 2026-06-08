"""
tests/unit/test_binary_analyzer.py
════════════════════════════════════
Unit tests for sin.firmware.binary_analyzer.

All subprocess calls and filesystem access are mocked.
No real ELF binaries or readelf/strings needed.
"""
import os
import tempfile
from unittest.mock import MagicMock, mock_open, patch

import pytest

from sin.firmware.binary_analyzer import (
    MAX_BINARIES,
    BinaryAnalysis,
    BinaryFinding,
    FirmwareBinaryAnalyzer,
    _build_findings,
    _is_elf,
    _parse_arch,
    _parse_binary_type,
    _parse_dangerous_functions,
    _parse_nx,
    _parse_pie,
    _parse_stack_canary,
    _parse_string_hits,
    _parse_stripped,
    _run_readelf,
    _run_strings,
)

# ── Fixtures — realistic readelf output ───────────────────────────────────────

READELF_ARM_EXEC = """ELF Header:
  Class:                             ELF32
  Type:                              EXEC (Executable file)
  Machine:                           ARM
  Flags:                             0x5000200
Symbol table '.symtab':
  Num: Value  Size Type  Bind   Vis  Ndx Name
   10: 00000000 0 FUNC  GLOBAL DEFAULT UND strcpy@GLIBC_2.4
   11: 00000000 0 FUNC  GLOBAL DEFAULT UND gets@GLIBC_2.4
   12: 00000000 0 FUNC  GLOBAL DEFAULT UND __stack_chk_fail@GLIBC_2.4
Program Headers:
  Type           Offset VirtAddr PhysAddr FileSiz MemSiz Flg Align
  GNU_STACK      0x000000 0x00000000 0x00000000 0x00000 0x00000 RW  0x10
"""

READELF_MIPS_STRIPPED = """ELF Header:
  Class:                             ELF32
  Type:                              EXEC (Executable file)
  Machine:                           MIPS R3000
Symbol table '.dynsym' contains 5 entries:
  Num: Value  Size Type  Bind   Vis  Ndx Name
    1: 00000000 0 FUNC  GLOBAL DEFAULT UND system@GLIBC
    2: 00000000 0 FUNC  GLOBAL DEFAULT UND sprintf@GLIBC
Program Headers:
  Type           Offset VirtAddr PhysAddr FileSiz MemSiz Flg Align
  GNU_STACK      0x000000 0x00000000 0x00000000 0x00000 0x00000 RWE 0x10
"""

READELF_DYN_PIE = """ELF Header:
  Class:                             ELF64
  Type:                              DYN (Shared object file)
  Machine:                           Advanced Micro Devices X86-64
Symbol table '.symtab':
  1: 000 OBJECT LOCAL DEFAULT 1 name
Program Headers:
  Type           Offset VirtAddr PhysAddr FileSiz MemSiz Flg Align
  GNU_STACK      0x000000 0x00000000 0x00000000 0x00000 0x00000 RW  0x10
"""

STRINGS_WITH_CREDS = [
    "password=admin123",
    "-----BEGIN RSA PRIVATE KEY-----",
    "/usr/bin/telnetd",
    "normal string here",
    "admin=admin",
]

STRINGS_CLEAN = [
    "/lib/libc.so.6",
    "GLIBC_2.4",
    "normal string",
]


# ── _is_elf ───────────────────────────────────────────────────────────────────

class TestIsElf:
    def test_returns_true_for_elf_magic(self):
        with patch("builtins.open", mock_open(read_data=b"\x7fELF\x01\x01\x01")):
            assert _is_elf("/fake/binary") is True

    def test_returns_false_for_non_elf(self):
        with patch("builtins.open", mock_open(read_data=b"#!/bin/sh\n")):
            assert _is_elf("/fake/script.sh") is False

    def test_returns_false_on_oserror(self):
        with patch("builtins.open", side_effect=OSError):
            assert _is_elf("/nonexistent") is False


# ── readelf parsing ───────────────────────────────────────────────────────────

class TestParseArch:
    def test_arm(self):
        assert _parse_arch(READELF_ARM_EXEC) == "ARM"

    def test_mips(self):
        assert _parse_arch(READELF_MIPS_STRIPPED) == "MIPS"

    def test_x86_64(self):
        assert _parse_arch(READELF_DYN_PIE) == "x86_64"

    def test_unknown_on_empty(self):
        assert _parse_arch("") == "unknown"


class TestParseBinaryType:
    def test_exec(self):
        assert _parse_binary_type(READELF_ARM_EXEC) == "EXEC"

    def test_dyn(self):
        assert _parse_binary_type(READELF_DYN_PIE) == "DYN"

    def test_unknown_on_empty(self):
        assert _parse_binary_type("") == "unknown"


class TestParseStripped:
    def test_not_stripped_when_symtab_present(self):
        assert _parse_stripped(READELF_ARM_EXEC) is False

    def test_stripped_when_no_symtab(self):
        assert _parse_stripped(READELF_MIPS_STRIPPED) is True


class TestParseStackCanary:
    def test_canary_present(self):
        assert _parse_stack_canary(READELF_ARM_EXEC) is True

    def test_canary_absent(self):
        assert _parse_stack_canary(READELF_MIPS_STRIPPED) is False


class TestParseNx:
    def test_nx_enabled_rw_stack(self):
        assert _parse_nx(READELF_ARM_EXEC) is True

    def test_nx_disabled_rwe_stack(self):
        assert _parse_nx(READELF_MIPS_STRIPPED) is False

    def test_nx_assumed_true_when_no_gnu_stack(self):
        assert _parse_nx("no GNU_STACK here") is True


class TestParsePie:
    def test_pie_on_dyn(self):
        assert _parse_pie("", "DYN") is True

    def test_no_pie_on_exec(self):
        assert _parse_pie("", "EXEC") is False


class TestParseDangerousFunctions:
    def test_detects_strcpy_and_gets(self):
        funcs = _parse_dangerous_functions(READELF_ARM_EXEC)
        assert "strcpy" in funcs
        assert "gets" in funcs

    def test_detects_system_and_sprintf(self):
        funcs = _parse_dangerous_functions(READELF_MIPS_STRIPPED)
        assert "system" in funcs
        assert "sprintf" in funcs

    def test_no_false_positives_on_clean(self):
        funcs = _parse_dangerous_functions(READELF_DYN_PIE)
        assert funcs == []


# ── strings parsing ───────────────────────────────────────────────────────────

class TestParseStringHits:
    def test_detects_password_pattern(self):
        hits = _parse_string_hits(STRINGS_WITH_CREDS)
        types = [h[1] for h in hits]
        assert any("Password" in t or "Credential" in t for t in types)

    def test_detects_private_key(self):
        hits = _parse_string_hits(STRINGS_WITH_CREDS)
        types = [h[1] for h in hits]
        assert any("Private Key" in t for t in types)

    def test_no_hits_on_clean_strings(self):
        hits = _parse_string_hits(STRINGS_CLEAN)
        assert hits == []

    def test_deduplicates_same_hit(self):
        repeated = STRINGS_WITH_CREDS + STRINGS_WITH_CREDS
        hits = _parse_string_hits(repeated)
        # Should not have duplicates
        seen = set()
        for hit in hits:
            key = (hit[1], hit[2])
            assert key not in seen, f"Duplicate hit: {key}"
            seen.add(key)


# ── _build_findings ───────────────────────────────────────────────────────────

class TestBuildFindings:
    def _make_analysis(self, **kwargs) -> BinaryAnalysis:
        defaults = dict(
            path="/tmp/test", filename="test_binary",
            arch="ARM", binary_type="EXEC",
            stripped=False, has_stack_canary=True,
            has_nx=True, has_pie=False,
            dangerous_functions=[], string_hits=[], findings=[],
        )
        defaults.update(kwargs)
        a = BinaryAnalysis(**defaults)
        a.findings = _build_findings(a)
        return a

    def test_no_canary_produces_high_finding(self):
        a = self._make_analysis(has_stack_canary=False)
        types = [f.type for f in a.findings]
        assert any("Stack Canary" in t for t in types)
        assert a.findings[0].severity == "HIGH"

    def test_no_nx_produces_high_finding(self):
        a = self._make_analysis(has_nx=False)
        types = [f.type for f in a.findings]
        assert any("NX" in t for t in types)

    def test_no_pie_produces_medium_finding(self):
        a = self._make_analysis(has_pie=False)
        types = [f.type for f in a.findings]
        assert any("PIE" in t for t in types)

    def test_dangerous_func_produces_finding(self):
        a = self._make_analysis(dangerous_functions=["gets", "strcpy"])
        types = [f.type for f in a.findings]
        assert any("Dangerous Function" in t for t in types)
        severities = {f.severity for f in a.findings if "Dangerous" in f.type}
        assert "CRITICAL" in severities  # gets is CRITICAL

    def test_clean_binary_has_only_pie_finding(self):
        a = self._make_analysis(
            has_stack_canary=True, has_nx=True, has_pie=False,
            dangerous_functions=[], string_hits=[],
        )
        # Only no-PIE finding
        assert len(a.findings) == 1
        assert "PIE" in a.findings[0].type


# ── FirmwareBinaryAnalyzer ────────────────────────────────────────────────────

class TestFirmwareBinaryAnalyzer:
    def setup_method(self):
        self.analyzer = FirmwareBinaryAnalyzer()

    def test_analyze_file_returns_none_for_non_elf(self):
        with patch("sin.firmware.binary_analyzer._is_elf", return_value=False):
            result = self.analyzer.analyze_file("/fake/script.sh")
        assert result is None

    def test_analyze_file_returns_analysis_for_elf(self):
        with patch("sin.firmware.binary_analyzer._is_elf", return_value=True), \
             patch("sin.firmware.binary_analyzer._run_readelf", return_value=READELF_ARM_EXEC), \
             patch("sin.firmware.binary_analyzer._run_strings", return_value=STRINGS_CLEAN), \
             patch("os.path.getsize", return_value=1024):
            result = self.analyzer.analyze_file("/fake/busybox")
        assert result is not None
        assert result.arch == "ARM"
        assert result.has_stack_canary is True

    def test_analyze_file_handles_readelf_failure(self):
        with patch("sin.firmware.binary_analyzer._is_elf", return_value=True), \
             patch("sin.firmware.binary_analyzer._run_readelf", return_value=None):
            result = self.analyzer.analyze_file("/fake/binary")
        assert result is not None
        assert result.error == "readelf failed"

    def test_analyze_directory_returns_empty_for_nonexistent(self):
        result = self.analyzer.analyze_directory("/nonexistent/path")
        assert result == []

    def test_summarize_aggregates_correctly(self):
        analyses = []
        for i in range(3):
            a = BinaryAnalysis(
                path=f"/fake/{i}", filename=f"bin{i}",
                arch="ARM", binary_type="EXEC",
                stripped=True, has_stack_canary=False,
                has_nx=True, has_pie=False,
                dangerous_functions=[], string_hits=[],
                findings=[],
            )
            a.findings = _build_findings(a)
            analyses.append(a)

        summary = self.analyzer.summarize(analyses)
        assert summary["binaries_analyzed"] == 3
        assert summary["total_findings"] > 0
        assert "ARM" in summary["architectures"]
        assert all(f"bin{i}" in summary["binaries_without_stack_canary"] for i in range(3))
